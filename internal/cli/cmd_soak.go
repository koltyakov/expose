package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/koltyakov/expose/internal/client"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/debughttp"
	ilog "github.com/koltyakov/expose/internal/log"
)

const (
	defaultSoakDuration       = 2 * time.Minute
	defaultSoakReportInterval = 5 * time.Second
	defaultSoakRestartDelay   = time.Second
	defaultSoakChurnDelay     = 500 * time.Millisecond
)

type soakClient interface {
	SetVersion(string)
	SetLogger(*slog.Logger)
	SetLifecycleHooks(client.LifecycleHooks)
	Run(context.Context) error
}

var newSoakClient = func(cfg config.ClientConfig) soakClient {
	return client.New(cfg, nil)
}

type soakStats struct {
	started                     atomic.Int64
	readyEvents                 atomic.Int64
	currentActive               atomic.Int64
	peakActive                  atomic.Int64
	registerFailures            atomic.Int64
	retryableRegisterFailures   atomic.Int64
	nonRetryableRegisterFailure atomic.Int64
	sessionDrops                atomic.Int64
	churnRestarts               atomic.Int64
	workerReturns               atomic.Int64
}

type soakSnapshot struct {
	Elapsed                    time.Duration
	Started                    int64
	ReadyEvents                int64
	CurrentActive              int64
	PeakActive                 int64
	RegisterFailures           int64
	RetryableRegisterFailures  int64
	NonRetryableRegisterErrors int64
	SessionDrops               int64
	ChurnRestarts              int64
	WorkerReturns              int64
}

type soakWorkerState struct {
	name       string
	mu         sync.Mutex
	active     bool
	cancel     context.CancelFunc
	generation int
}

type soakRunner struct {
	ctx            context.Context
	version        string
	logger         *slog.Logger
	clientLog      *slog.Logger
	out            io.Writer
	baseCfg        config.ClientConfig
	workers        []*soakWorkerState
	reportInterval time.Duration
	churnInterval  time.Duration
	churnBatch     int
	newClient      func(config.ClientConfig) soakClient

	stats      soakStats
	churnIndex atomic.Int64
	wg         sync.WaitGroup
}

func runSoak(ctx context.Context, args []string) int {
	loadClientEnvFromDotEnv(".env")

	fs := flag.NewFlagSet("soak", flag.ContinueOnError)
	serverURL := envOr("EXPOSE_DOMAIN", "")
	apiKey := envOr("EXPOSE_API_KEY", "")
	port := parseIntEnv("EXPOSE_PORT", 0)
	pprofListen := strings.TrimSpace(envOr("EXPOSE_PPROF_LISTEN", ""))
	count := 25
	duration := defaultSoakDuration
	ramp := time.Duration(0)
	reportInterval := defaultSoakReportInterval
	churnInterval := time.Duration(0)
	churnBatch := 1
	prefix := fmt.Sprintf("soak-%s", time.Now().UTC().Format("060102150405"))

	fs.StringVar(&serverURL, "server", serverURL, "Server URL (e.g. https://example.com)")
	fs.StringVar(&apiKey, "api-key", apiKey, "API key")
	fs.IntVar(&port, "port", port, "Local HTTP port on 127.0.0.1")
	fs.IntVar(&count, "count", count, "Number of concurrent tunnel clients to run")
	fs.DurationVar(&duration, "duration", duration, "Total soak run duration")
	fs.DurationVar(&ramp, "ramp", ramp, "Delay between worker launches")
	fs.DurationVar(&reportInterval, "report-interval", reportInterval, "Interval for rolling status output")
	fs.DurationVar(&churnInterval, "churn-interval", churnInterval, "How often to restart a batch of workers (0 disables churn)")
	fs.IntVar(&churnBatch, "churn-batch", churnBatch, "How many workers to restart per churn tick")
	fs.StringVar(&prefix, "prefix", prefix, "Subdomain prefix for temporary soak tunnels")
	fs.StringVar(&pprofListen, "pprof-listen", pprofListen, "Optional pprof listen address (e.g. 127.0.0.1:6060)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, "soak command error:", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: expose soak --port 3000 [--count 100 --duration 10m]")
		return 2
	}
	if port <= 0 || port > 65535 {
		fmt.Fprintln(os.Stderr, "soak command error: missing or invalid port (1..65535)")
		return 2
	}
	if count <= 0 {
		fmt.Fprintln(os.Stderr, "soak command error: count must be > 0")
		return 2
	}
	if duration <= 0 {
		fmt.Fprintln(os.Stderr, "soak command error: duration must be > 0")
		return 2
	}
	if ramp < 0 {
		fmt.Fprintln(os.Stderr, "soak command error: ramp must be >= 0")
		return 2
	}
	if reportInterval <= 0 {
		fmt.Fprintln(os.Stderr, "soak command error: report interval must be > 0")
		return 2
	}
	if churnInterval < 0 {
		fmt.Fprintln(os.Stderr, "soak command error: churn interval must be >= 0")
		return 2
	}
	if churnBatch <= 0 || churnBatch > count {
		fmt.Fprintln(os.Stderr, "soak command error: churn batch must be between 1 and count")
		return 2
	}

	baseCfg := config.ClientConfig{
		ServerURL:             serverURL,
		APIKey:                apiKey,
		LocalPort:             port,
		Timeout:               30 * time.Second,
		PingInterval:          30 * time.Second,
		MaxConcurrentForwards: parseIntEnv("EXPOSE_MAX_CONCURRENT_FORWARDS", 32),
		PprofListen:           strings.TrimSpace(pprofListen),
		RegistrationMode:      "temporary",
	}
	if err := mergeClientSettings(&baseCfg); err != nil {
		fmt.Fprintln(os.Stderr, "soak config error:", err)
		return 2
	}
	if strings.TrimSpace(baseCfg.ServerURL) == "" || strings.TrimSpace(baseCfg.APIKey) == "" {
		fmt.Fprintln(os.Stderr, "soak config error: missing --server/--api-key (or saved login / env vars)")
		return 2
	}

	logger := ilog.NewStderr("info")
	clientLog := ilog.NewStderr("error")
	if err := debughttp.StartPprofServer(ctx, baseCfg.PprofListen, logger, "soak"); err != nil {
		fmt.Fprintln(os.Stderr, "soak config error: pprof:", err)
		return 2
	}

	runCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	runner := soakRunner{
		ctx:            runCtx,
		version:        Version,
		logger:         logger,
		clientLog:      clientLog,
		out:            os.Stdout,
		baseCfg:        baseCfg,
		workers:        make([]*soakWorkerState, count),
		reportInterval: reportInterval,
		churnInterval:  churnInterval,
		churnBatch:     churnBatch,
		newClient:      newSoakClient,
	}
	prefix = normalizeSoakPrefix(prefix)
	for i := 0; i < count; i++ {
		runner.workers[i] = &soakWorkerState{
			name: fmt.Sprintf("%s-%04d", prefix, i+1),
		}
	}

	fmt.Printf("soak start count=%d duration=%s port=%d server=%s prefix=%s churn_interval=%s churn_batch=%d\n",
		count,
		duration.Round(time.Second),
		port,
		baseCfg.ServerURL,
		prefix,
		churnInterval.Round(time.Second),
		churnBatch,
	)

	snap := runner.run(ramp)
	if snap.PeakActive == 0 {
		fmt.Fprintln(os.Stderr, "soak error: no tunnels became ready")
		return 1
	}
	return 0
}

func (r *soakRunner) run(ramp time.Duration) soakSnapshot {
	startedAt := time.Now()

	go r.runReporter(startedAt)
	if r.churnInterval > 0 {
		go r.runChurnLoop()
	}

	for i := range r.workers {
		if r.ctx.Err() != nil {
			break
		}
		r.startWorker(i)
		if ramp > 0 && i < len(r.workers)-1 {
			timer := time.NewTimer(ramp)
			select {
			case <-r.ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}

	<-r.ctx.Done()
	r.stopAllWorkers()
	r.wg.Wait()

	snap := r.snapshot(time.Since(startedAt))
	r.printSnapshot("final", snap)
	return snap
}

func (r *soakRunner) startWorker(idx int) {
	if idx < 0 || idx >= len(r.workers) || r.ctx.Err() != nil {
		return
	}
	worker := r.workers[idx]
	workerCtx, generation, started := worker.start(r.ctx)
	if !started {
		return
	}
	r.stats.started.Add(1)

	r.wg.Add(1)
	go func(worker *soakWorkerState, generation int, workerCtx context.Context) {
		defer r.wg.Done()
		defer worker.clearCancel(generation)
		defer worker.markInactive(&r.stats)

		clientCfg := r.baseCfg
		clientCfg.Name = worker.name
		factory := r.clientFactory()

		for {
			c := factory(clientCfg)
			c.SetVersion(r.version)
			c.SetLogger(r.clientLog)
			c.SetLifecycleHooks(client.LifecycleHooks{
				OnTunnelReady: func(client.TunnelReadyEvent) {
					worker.markReady(&r.stats)
				},
				OnRegisterFailure: func(evt client.RegisterFailureEvent) {
					r.stats.registerFailures.Add(1)
					if evt.WillRetry {
						r.stats.retryableRegisterFailures.Add(1)
					} else {
						r.stats.nonRetryableRegisterFailure.Add(1)
					}
				},
				OnSessionDrop: func(client.SessionDisconnectEvent) {
					if worker.markInactive(&r.stats) {
						r.stats.sessionDrops.Add(1)
					}
				},
			})

			err := c.Run(workerCtx)
			if workerCtx.Err() != nil || r.ctx.Err() != nil {
				return
			}

			r.stats.workerReturns.Add(1)
			if r.logger != nil {
				r.logger.Warn("soak worker returned; restarting", "worker", worker.name, "err", err)
			}

			timer := time.NewTimer(defaultSoakRestartDelay)
			select {
			case <-workerCtx.Done():
				timer.Stop()
				return
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}(worker, generation, workerCtx)
}

func (r *soakRunner) clientFactory() func(config.ClientConfig) soakClient {
	if r.newClient != nil {
		return r.newClient
	}
	return newSoakClient
}

func (r *soakRunner) restartWorker(idx int, churn bool) {
	if idx < 0 || idx >= len(r.workers) {
		return
	}
	worker := r.workers[idx]
	worker.markInactive(&r.stats)
	cancel := worker.stop()
	if cancel != nil {
		cancel()
	}
	if churn {
		r.stats.churnRestarts.Add(1)
	}

	delay := time.Duration(0)
	if churn {
		delay = defaultSoakChurnDelay
	}
	go func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		r.startWorker(idx)
	}()
}

func (r *soakRunner) stopAllWorkers() {
	for _, worker := range r.workers {
		if worker == nil {
			continue
		}
		worker.markInactive(&r.stats)
		if cancel := worker.stop(); cancel != nil {
			cancel()
		}
	}
}

func (r *soakRunner) runReporter(startedAt time.Time) {
	ticker := time.NewTicker(r.reportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.printSnapshot("tick", r.snapshot(time.Since(startedAt)))
		}
	}
}

func (r *soakRunner) runChurnLoop() {
	ticker := time.NewTicker(r.churnInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < r.churnBatch; i++ {
				idx := int(r.churnIndex.Add(1)-1) % len(r.workers)
				r.restartWorker(idx, true)
			}
		}
	}
}

func (r *soakRunner) snapshot(elapsed time.Duration) soakSnapshot {
	return soakSnapshot{
		Elapsed:                    elapsed,
		Started:                    r.stats.started.Load(),
		ReadyEvents:                r.stats.readyEvents.Load(),
		CurrentActive:              r.stats.currentActive.Load(),
		PeakActive:                 r.stats.peakActive.Load(),
		RegisterFailures:           r.stats.registerFailures.Load(),
		RetryableRegisterFailures:  r.stats.retryableRegisterFailures.Load(),
		NonRetryableRegisterErrors: r.stats.nonRetryableRegisterFailure.Load(),
		SessionDrops:               r.stats.sessionDrops.Load(),
		ChurnRestarts:              r.stats.churnRestarts.Load(),
		WorkerReturns:              r.stats.workerReturns.Load(),
	}
}

func (r *soakRunner) printSnapshot(label string, snap soakSnapshot) {
	out := r.out
	if out == nil {
		out = os.Stdout
	}
	_, _ = fmt.Fprintf(
		out,
		"soak %s elapsed=%s started=%d active=%d peak=%d ready_events=%d register_failures=%d retryable=%d nonretryable=%d disconnects=%d churns=%d worker_returns=%d\n",
		label,
		snap.Elapsed.Round(time.Second),
		snap.Started,
		snap.CurrentActive,
		snap.PeakActive,
		snap.ReadyEvents,
		snap.RegisterFailures,
		snap.RetryableRegisterFailures,
		snap.NonRetryableRegisterErrors,
		snap.SessionDrops,
		snap.ChurnRestarts,
		snap.WorkerReturns,
	)
}

func (w *soakWorkerState) start(parent context.Context) (context.Context, int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return nil, 0, false
	}
	w.generation++
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	return ctx, w.generation, true
}

func (w *soakWorkerState) clearCancel(generation int) {
	w.mu.Lock()
	if w.generation == generation {
		w.cancel = nil
	}
	w.mu.Unlock()
}

func (w *soakWorkerState) stop() context.CancelFunc {
	w.mu.Lock()
	cancel := w.cancel
	w.cancel = nil
	w.mu.Unlock()
	return cancel
}

func (w *soakWorkerState) markReady(stats *soakStats) {
	stats.readyEvents.Add(1)

	w.mu.Lock()
	alreadyActive := w.active
	w.active = true
	w.mu.Unlock()

	if alreadyActive {
		return
	}
	current := stats.currentActive.Add(1)
	updatePeak(&stats.peakActive, current)
}

func (w *soakWorkerState) markInactive(stats *soakStats) bool {
	w.mu.Lock()
	wasActive := w.active
	w.active = false
	w.mu.Unlock()
	if !wasActive {
		return false
	}
	stats.currentActive.Add(-1)
	return true
}

func updatePeak(peak *atomic.Int64, current int64) {
	for {
		prev := peak.Load()
		if current <= prev {
			return
		}
		if peak.CompareAndSwap(prev, current) {
			return
		}
	}
}

func normalizeSoakPrefix(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		raw = "soak"
	}
	var out strings.Builder
	lastDash := false
	for _, r := range raw {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			out.WriteRune(r)
			lastDash = false
		case r == '-':
			if out.Len() == 0 || lastDash {
				continue
			}
			out.WriteRune('-')
			lastDash = true
		default:
			if out.Len() == 0 || lastDash {
				continue
			}
			out.WriteRune('-')
			lastDash = true
		}
		if out.Len() >= 48 {
			break
		}
	}
	normalized := strings.Trim(out.String(), "-")
	if normalized == "" {
		return "soak"
	}
	return normalized
}

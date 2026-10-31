package server

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"golang.org/x/net/http/httpguts"
)

type bypassLimits struct {
	total, http, upgrades int
}

func bypassLimitsFor(route config.ServerBypass, cfg config.ServerConfig) bypassLimits {
	total := route.MaxInFlight
	if total == 0 {
		total = int(maxPendingPerSessionFor(cfg))
	}
	httpLimit, upgradeLimit := route.MaxHTTPRequests, route.MaxUpgrades
	if httpLimit == 0 {
		httpLimit = total
	}
	if upgradeLimit == 0 {
		// Preserve ordinary HTTP capacity while reserving a quarter of the
		// aggregate budget against persistent upgrades. Tiny test/deployment
		// limits still permit one upgrade; a total of one cannot reserve HTTP.
		upgradeLimit = max(1, total-max(1, total/4))
	}
	return bypassLimits{total, httpLimit, upgradeLimit}
}

func isBypassUpgrade(r *http.Request) bool {
	// Account for all HTTP upgrades, not just well-formed WebSocket requests.
	return r.Header.Get("Upgrade") != "" && httpguts.HeaderValuesContainsToken(r.Header["Connection"], "upgrade")
}

func (b *serverBypass) acquire(upgrade bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	reason := -1
	switch {
	case b.closing:
		reason = 3
	case b.pending.Load() >= int64(b.limits.total):
		reason = 0
	case upgrade && b.upgradePending >= b.limits.upgrades:
		reason = 2
	case !upgrade && b.httpPending >= b.limits.http:
		reason = 1
	}
	if reason >= 0 {
		b.rejects[reason].Add(1)
		return false
	}
	b.pending.Add(1)
	if upgrade {
		b.upgradePending++
	} else {
		b.httpPending++
	}
	b.owner.bypassWG.Add(1)
	return true
}

func (b *serverBypass) release(upgrade bool) {
	b.mu.Lock()
	b.pending.Add(-1)
	if upgrade {
		b.upgradePending--
	} else {
		b.httpPending--
	}
	b.mu.Unlock()
	b.owner.bypassWG.Done()
}

type trackingBypassTransport struct {
	base  http.RoundTripper
	route *serverBypass
}

func (t trackingBypassTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	started := time.Now()
	resp, err := t.base.RoundTrip(r)
	t.route.headerCount.Add(1)
	t.route.headerNanos.Add(time.Since(started).Nanoseconds())
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return resp, err
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		return resp, nil // ReverseProxy rejects the unsupported upgrade body.
	}
	body := &trackedBypassUpgrade{ReadWriteCloser: rw, route: t.route, started: time.Now()}
	t.route.mu.Lock()
	closing := t.route.closing
	if !closing {
		t.route.upgrades[body] = struct{}{}
		t.route.upgradeCount.Add(1)
	}
	t.route.mu.Unlock()
	if closing {
		_ = rw.Close()
		return nil, errors.New("local service proxy stopping")
	}
	resp.Body = body
	return resp, nil
}

type trackedBypassUpgrade struct {
	io.ReadWriteCloser
	route   *serverBypass
	started time.Time
	once    sync.Once
	err     error
}

func (b *trackedBypassUpgrade) Close() error {
	b.once.Do(func() {
		b.err = b.ReadWriteCloser.Close()
		b.route.mu.Lock()
		delete(b.route.upgrades, b)
		b.route.mu.Unlock()
		b.route.upgradeNanos.Add(time.Since(b.started).Nanoseconds())
		b.route.upgradeCompleted.Add(1)
	})
	return b.err
}

func (s *Server) closeBypasses() {
	for _, b := range s.bypasses {
		b.mu.Lock()
		b.closing = true // Excludes both new admission and late upstream upgrades.
		bodies := make([]*trackedBypassUpgrade, 0, len(b.upgrades))
		for body := range b.upgrades {
			bodies = append(bodies, body)
		}
		b.mu.Unlock()
		for _, body := range bodies {
			_ = body.Close()
		}
		b.transport.CloseIdleConnections()
	}
}

package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"

	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/waf"
)

// Run starts the HTTPS server, ACME challenge server, and background janitor.
// It blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	s.runtimeCtx.Store(ctx)

	resetCount, err := s.store.ResetConnectedTunnels(ctx)
	if err != nil {
		return fmt.Errorf("reset connected tunnels: %w", err)
	}
	if resetCount > 0 {
		s.log.Info("reconciled stale connected tunnels", "count", resetCount)
	}

	disconnectCtx, disconnectCancel := context.WithCancel(ctx)
	defer func() {
		disconnectCancel()
		s.disconnectWg.Wait()
	}()

	go s.runDisconnectWorker(disconnectCtx)
	go s.runJanitor(ctx)
	go s.runDomainTouchWorker(ctx)
	s.routes.startClock(ctx.Done())
	if s.cfg.WAFEnabled {
		go s.runWAFAuditWorker(ctx)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tunnels/register", s.handleRegister)
	mux.HandleFunc("/v1/tunnels/connect", s.handleConnect)
	mux.HandleFunc("/v1/tunnels/connect-h3", s.handleConnectH3)
	mux.HandleFunc("/v1/tunnels/connect-h3/stream", s.handleConnectH3Stream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handlePublic)

	var handler http.Handler = mux
	if s.cfg.WAFEnabled {
		handler = waf.NewMiddleware(waf.Config{
			Enabled:          true,
			AuditOnly:        s.cfg.WAFAuditOnly,
			BodyInspectLimit: s.cfg.WAFBodyInspectLimit,
			MaxURILength:     s.cfg.WAFMaxURILength,
			MaxHeaderCount:   s.cfg.WAFMaxHeaderCount,
			ShouldInspectBody: func(r *http.Request) bool {
				return shouldInspectWAFBody(r)
			},
			OnBlock: s.recordWAFBlock,
		}, s.log)(handler)
		s.log.Info("WAF enabled")
	}

	var manager *autocert.Manager
	useDynamicACME := s.cfg.TLSMode != tlsModeWildcard
	if useDynamicACME {
		manager = &autocert.Manager{
			Cache:  autocert.DirCache(s.cfg.CertCacheDir),
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				host = normalizeHost(host)
				base := normalizeHost(s.cfg.BaseDomain)
				if host == base {
					return nil
				}
				ok, err := s.store.IsHostnameActive(ctx, host)
				if err != nil {
					return errors.New("failed to authorize host")
				}
				if ok {
					return nil
				}
				return errors.New("host not allowed")
			},
		}
	}

	staticCert, err := s.loadStaticCertificate(s.cfg.TLSMode)
	if err != nil {
		return err
	}
	s.wildcardTLSOn = false
	if staticCert != nil {
		base := normalizeHost(s.cfg.BaseDomain)
		s.wildcardTLSOn = staticCert.supportsHost("probe." + base)
	}

	var tlsConfig *tls.Config
	if manager != nil {
		tlsConfig = manager.TLSConfig()
	} else {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.GetCertificate = s.selectCertificate(manager, staticCert, s.cfg.TLSMode)

	httpsServer := &http.Server{
		Addr:              s.cfg.ListenHTTPS,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       durationOr(s.cfg.HTTPSReadTimeout, httpsReadTimeout),
		WriteTimeout:      durationOr(s.cfg.HTTPSWriteTimeout, httpsWriteTimeout),
		IdleTimeout:       durationOr(s.cfg.HTTPSIdleTimeout, httpsIdleTimeout),
		MaxHeaderBytes:    httpsMaxHeaderBytes,
		TLSConfig:         tlsConfig,
		ErrorLog:          log.New(newHTTPSErrorLogWriter(s.log, useDynamicACME), "", 0),
	}

	h3TLSConfig := http3.ConfigureTLSConfig(tlsConfig.Clone())
	h3TLSConfig.MinVersion = tls.VersionTLS13
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	h3Server := &http3.Server{
		Addr:        s.cfg.ListenHTTPS,
		Handler:     handler,
		TLSConfig:   h3TLSConfig,
		QUICConfig:  netutil.TunnelQUICConfig(0),
		IdleTimeout: durationOr(s.cfg.HTTPSIdleTimeout, httpsIdleTimeout),
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			return context.WithValue(ctx, http3ConnContextKey{}, c)
		},
	}

	errChSize := 1
	if useDynamicACME {
		errChSize = 2
	}
	errChSize++
	errCh := make(chan error, errChSize)

	var challengeServer *http.Server
	if useDynamicACME {
		challengeServer = &http.Server{
			Addr:              s.cfg.ListenHTTP,
			Handler:           manager.HTTPHandler(http.NotFoundHandler()),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       httpIdleTimeout,
			MaxHeaderBytes:    httpsMaxHeaderBytes,
		}
		go func() {
			s.log.Info("starting ACME challenge server", "addr", s.cfg.ListenHTTP)
			if err := challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("challenge server: %w", err)
			}
		}()
	} else {
		s.log.Info("TLS mode wildcard: dynamic ACME disabled", "hint", "set EXPOSE_TLS_MODE=auto to allow dynamic per-host fallback")
	}

	go func() {
		s.log.Info("starting HTTPS server", "addr", s.cfg.ListenHTTPS)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https server: %w", err)
		}
	}()
	go func() {
		s.log.Info("starting HTTP/3 server", "addr", s.cfg.ListenHTTPS)
		if err := h3Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http3 server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		return s.gracefulShutdown(httpsServer, challengeServer, h3Server)
	case err := <-errCh:
		s.forceCloseAllSessions("fatal error")
		_ = shutdownServer(httpsServer, durationOr(s.cfg.ShutdownDrainTime, 5*time.Second))
		_ = h3Server.Close()
		if challengeServer != nil {
			_ = shutdownServer(challengeServer, durationOr(s.cfg.ShutdownDrainTime, 5*time.Second))
		}
		waitGroupWait(&s.hub.wg, durationOr(s.cfg.ShutdownWaitTime, 15*time.Second))
		return err
	}
}

func shouldInspectWAFBody(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/v1/") {
		return false
	}
	return true
}

// gracefulShutdown performs an orderly multi-phase shutdown:
//  1. Drain - stop accepting new connections (http.Server.Shutdown).
//  2. Signal - ask active tunnel sessions to reconnect elsewhere.
//  3. Close - terminate any sessions that didn't exit on their own.
//  4. Wait  - allow read loops to finish within a timeout.
func (s *Server) gracefulShutdown(httpsServer *http.Server, challengeServer *http.Server, h3Server *http3.Server) error {
	drainTimeout := durationOr(s.cfg.ShutdownDrainTime, 5*time.Second)
	waitTimeout := durationOr(s.cfg.ShutdownWaitTime, 15*time.Second)

	s.log.Info("shutdown: draining connections", "timeout", drainTimeout)
	drainErrCh := make(chan error, 1)
	go func() {
		drainErrCh <- s.drainServers(httpsServer, challengeServer, h3Server, drainTimeout)
	}()
	s.signalAllSessions("shutdown")

	s.log.Info("shutdown: waiting for tunnel sessions to finish", "timeout", waitTimeout)
	if !waitGroupWait(&s.hub.wg, waitTimeout) {
		s.log.Warn("shutdown: timed out waiting for tunnel sessions; forcing close", "timeout", waitTimeout)
		s.forceCloseAllSessions("shutdown timeout")
		if !waitGroupWait(&s.hub.wg, 2*time.Second) {
			s.log.Warn("shutdown: timed out waiting for forced tunnel session close")
		}
	}
	firstErr := <-drainErrCh
	s.log.Info("shutdown: complete")
	return firstErr
}

func (s *Server) drainServers(httpsServer *http.Server, challengeServer *http.Server, h3Server *http3.Server, timeout time.Duration) error {
	type shutdownTask struct {
		name string
		run  func() error
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tasks := make([]shutdownTask, 0, 3)
	if httpsServer != nil {
		tasks = append(tasks, shutdownTask{
			name: "https",
			run:  func() error { return shutdownServer(httpsServer, timeout) },
		})
	}
	if h3Server != nil {
		tasks = append(tasks, shutdownTask{
			name: "http3",
			run: func() error {
				err := h3Server.Shutdown(ctx)
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			},
		})
	}
	if challengeServer != nil {
		tasks = append(tasks, shutdownTask{
			name: "challenge",
			run:  func() error { return shutdownServer(challengeServer, timeout) },
		})
	}

	errCh := make(chan error, len(tasks))
	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(task shutdownTask) {
			defer wg.Done()
			if err := task.run(); err != nil {
				errCh <- fmt.Errorf("%s server shutdown: %w", task.name, err)
			}
		}(task)
	}
	wg.Wait()
	close(errCh)

	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) signalAllSessions(reason string) {
	s.hub.mu.RLock()
	sessions := make([]*session, 0, len(s.hub.sessions))
	for _, sess := range s.hub.sessions {
		sessions = append(sessions, sess)
	}
	s.hub.mu.RUnlock()

	if len(sessions) > 0 && s.log != nil {
		s.log.Info("signaling active tunnel sessions", "count", len(sessions), "reason", reason)
	}

	var wg sync.WaitGroup
	for _, sess := range sessions {
		if sess == nil || sess.writer == nil {
			continue
		}
		wg.Add(1)
		go func(sess *session) {
			defer wg.Done()
			_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindClose})
		}(sess)
	}
	wg.Wait()
}

func (s *Server) forceCloseAllSessions(reason string) {
	s.hub.mu.RLock()
	sessions := make([]*session, 0, len(s.hub.sessions))
	for _, sess := range s.hub.sessions {
		sessions = append(sessions, sess)
	}
	s.hub.mu.RUnlock()

	if len(sessions) > 0 && s.log != nil {
		s.log.Info("closing active tunnel sessions", "count", len(sessions), "reason", reason)
	}
	for _, sess := range sessions {
		if sess != nil && sess.transport != nil {
			_ = sess.transport.Close()
		}
	}
}

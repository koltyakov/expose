package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/koltyakov/expose/internal/waf"
)

// Run starts the HTTPS server, ACME challenge server, and background janitor.
// It blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	resetCount, err := s.store.ResetConnectedTunnels(ctx)
	if err != nil {
		return fmt.Errorf("reset connected tunnels: %w", err)
	}
	if resetCount > 0 {
		s.log.Info("reconciled stale connected tunnels", "count", resetCount)
	}

	go s.runJanitor(ctx)
	go s.runDomainTouchWorker(ctx)
	if s.cfg.WAFEnabled {
		go s.runWAFAuditWorker(ctx)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tunnels/register", s.handleRegister)
	mux.HandleFunc("/v1/tunnels/connect", s.handleConnect)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handlePublic)

	var handler http.Handler = mux
	if s.cfg.WAFEnabled {
		handler = waf.NewMiddleware(waf.Config{
			Enabled: true,
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
		ReadTimeout:       httpsReadTimeout,
		WriteTimeout:      httpsWriteTimeout,
		IdleTimeout:       httpsIdleTimeout,
		MaxHeaderBytes:    httpsMaxHeaderBytes,
		TLSConfig:         tlsConfig,
		ErrorLog:          log.New(newHTTPSErrorLogWriter(s.log, useDynamicACME), "", 0),
	}

	errChSize := 1
	if useDynamicACME {
		errChSize = 2
	}
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

	select {
	case <-ctx.Done():
		s.closeAllSessions()
		var firstErr error
		if err := shutdownServer(httpsServer, 5*time.Second); err != nil {
			firstErr = err
		}
		if challengeServer != nil {
			if err := shutdownServer(challengeServer, 5*time.Second); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		waitGroupWait(&s.hub.wg, 15*time.Second)
		return firstErr
	case err := <-errCh:
		s.closeAllSessions()
		_ = shutdownServer(httpsServer, 5*time.Second)
		if challengeServer != nil {
			_ = shutdownServer(challengeServer, 5*time.Second)
		}
		waitGroupWait(&s.hub.wg, 15*time.Second)
		return err
	}
}

func (s *Server) closeAllSessions() {
	s.hub.mu.RLock()
	sessions := make([]*session, 0, len(s.hub.sessions))
	for _, sess := range s.hub.sessions {
		sessions = append(sessions, sess)
	}
	s.hub.mu.RUnlock()

	for _, sess := range sessions {
		_ = sess.conn.Close()
	}
}

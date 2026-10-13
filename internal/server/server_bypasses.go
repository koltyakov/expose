package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

type serverBypass struct {
	config.ServerBypass
	proxy   *httputil.ReverseProxy
	pending atomic.Int64
}

func (s *Server) initBypasses(store *sqlite.Store) {
	s.bypasses = make(map[string]*serverBypass, len(s.cfg.Bypasses))
	hosts := make([]string, 0, len(s.cfg.Bypasses))
	for _, cfg := range s.cfg.Bypasses {
		host := config.NormalizeTunnelSubdomain(cfg.Subdomain) + "." + normalizeHost(s.cfg.BaseDomain)
		target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(cfg.Port)}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil // Local services must never go through HTTP_PROXY.
		transport.ResponseHeaderTimeout = durationOr(s.cfg.RequestTimeout, 30*time.Second)
		proxy := &httputil.ReverseProxy{
			Transport: bypassTransport{transport, transport.ResponseHeaderTimeout},
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host
				stripPublicAccessCookie(pr.Out.Header)
				injectForwardedProxyHeaders(pr.Out.Header, pr.In)
				pr.Out.Header.Del("Host")
				injectForwardedFor(pr.Out.Header, s.clientIP(pr.In))
			},
			ModifyResponse: func(resp *http.Response) error {
				stripUpstreamAltSvc(resp.Header)
				return nil
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				if s.log != nil {
					s.log.Warn("local service proxy failed", "host", normalizeHost(r.Host), "err", err)
				}
				http.Error(w, "upstream unavailable", http.StatusBadGateway)
			},
		}
		s.bypasses[host] = &serverBypass{ServerBypass: cfg, proxy: proxy}
		hosts = append(hosts, host)
	}
	if store != nil {
		store.SetReservedHostnames(hosts)
	}
}

// The standard transport only times out response headers. Bound each blocked
// body read as well, including over HTTP/3 where a public read deadline cannot
// interrupt a stalled upstream response. Active streams may run indefinitely.
type bypassTransport struct {
	base    http.RoundTripper
	timeout time.Duration
}

type bypassBodyFailureKey struct{}

func (t bypassTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithCancel(r.Context())
	resp, err := t.base.RoundTrip(r.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		// Preserve the bidirectional body required by ReverseProxy's upgrade
		// handling; ordinary HTTP body timeouts must not break idle WebSockets.
		if rw, ok := resp.Body.(io.ReadWriteCloser); ok {
			resp.Body = &bypassUpgradeBody{rw, cancel}
			return resp, nil
		}
	}
	failed, _ := r.Context().Value(bypassBodyFailureKey{}).(*bool)
	resp.Body = &bypassResponseBody{ReadCloser: resp.Body, cancel: cancel, timeout: t.timeout, failed: failed}
	return resp, nil
}

type bypassResponseBody struct {
	io.ReadCloser
	cancel  context.CancelFunc
	timeout time.Duration
	failed  *bool // read and inspected by the proxy handler's goroutine
}

func (b *bypassResponseBody) Read(p []byte) (int, error) {
	timer := time.AfterFunc(b.timeout, b.cancel)
	defer timer.Stop()
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF && b.failed != nil {
		*b.failed = true
	}
	return n, err
}

func (b *bypassResponseBody) Close() error {
	defer b.cancel()
	return b.ReadCloser.Close()
}

type bypassUpgradeBody struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
}

func (b *bypassUpgradeBody) Close() error {
	defer b.cancel()
	return b.ReadWriteCloser.Close()
}

func (s *Server) serveBypass(w http.ResponseWriter, r *http.Request, host string) bool {
	route, ok := s.bypasses[host]
	if !ok {
		return false
	}
	if !route.DisableRateLimit && !s.publicLimiter.allow(publicRateLimitKey(host, s.clientIP(r))) {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return true
	}
	if route.pending.Add(1) > maxPendingPerSessionFor(s.cfg) {
		route.pending.Add(-1)
		http.Error(w, "local service overloaded", http.StatusServiceUnavailable)
		return true
	}
	defer route.pending.Add(-1)
	var bodyFailed bool
	ctx := context.WithValue(r.Context(), bypassBodyFailureKey{}, &bodyFailed)
	route.proxy.ServeHTTP(w, r.WithContext(ctx))
	if bodyFailed {
		// ReverseProxy only aborts automatically when net/http's server
		// context key is present. HTTP/3 must also signal a truncated body
		// as a failed transfer after the upstream timeout releases the slot.
		panic(http.ErrAbortHandler)
	}
	return true
}

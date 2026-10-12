package server

import (
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
			Transport: transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host
				stripPublicAccessCookie(pr.Out.Header)
				injectForwardedProxyHeaders(pr.Out.Header, pr.In)
				pr.Out.Header.Del("Host")
				injectForwardedFor(pr.Out.Header, s.clientIP(pr.In))
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
	route.proxy.ServeHTTP(w, r)
	return true
}

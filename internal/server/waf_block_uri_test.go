package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/waf"
)

func TestWAFBlockBuildsURIOnlyForServedHosts(t *testing.T) {
	srv := &Server{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)), // info level
		liveRoutes:    newLiveRouteIndex(),
		routes:        routeCache{entries: make(map[string]routeCacheEntry), hostsByTunnel: make(map[string]map[string]struct{})},
		wafAuditQueue: make(chan wafAuditEvent, 4),
	}
	srv.routes.set("app.example.com", domain.TunnelRoute{Domain: domain.Domain{ID: "d1", Hostname: "app.example.com"}, Tunnel: domain.Tunnel{ID: "t1"}})
	handler := waf.NewMiddleware(waf.Config{Enabled: true, OnBlock: srv.recordWAFBlock}, srv.log)(http.NotFoundHandler())
	block := func(host string) wafAuditEvent {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/.env?token=secret", nil)
		handler.ServeHTTP(httptest.NewRecorder(), r)
		return <-srv.wafAuditQueue
	}
	if got := block("probe.invalid").event.RequestURI; got != "" {
		t.Fatalf("unknown-host block built URI %q", got)
	}
	if got := block("app.example.com").event.RequestURI; got != "/.env?token=REDACTED" {
		t.Fatalf("served-host block URI = %q", got)
	}
}

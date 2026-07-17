package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsHandlerReportsRuntimeState(t *testing.T) {
	t.Parallel()

	sess := &session{}
	sess.pendingCount.Store(2)
	sess.webSocketCount.Store(1)
	srv := &Server{
		store:         &stubServerStore{},
		hub:           &hub{sessions: map[string]*session{"t-1": sess}},
		liveRoutes:    newLiveRouteIndex(),
		disconnects:   make(chan string, 2),
		domainTouches: make(chan string, 2),
		wafAuditQueue: make(chan wafAuditEvent, 2),
	}
	srv.connectionsTotal.Store(3)

	rr := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	for _, expected := range []string{
		"expose_active_tunnel_sessions 1",
		"expose_pending_http_requests 2",
		"expose_open_websockets 1",
		"expose_tunnel_connections_total 3",
		"expose_sqlite_write_operations_total 0",
	} {
		if !strings.Contains(rr.Body.String(), expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, rr.Body.String())
		}
	}
}

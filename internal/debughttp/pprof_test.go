package debughttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofMuxServesIndex(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	rr := httptest.NewRecorder()

	newPprofMux().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "profile?debug=1") {
		t.Fatalf("expected pprof index body, got %q", rr.Body.String())
	}
}

func TestPprofMuxServesExtraHandler(t *testing.T) {
	t.Parallel()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/metrics", nil)
	newPprofMux(map[string]http.HandlerFunc{
		"/debug/metrics": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("metric 1\n")) },
	}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "metric 1\n" {
		t.Fatalf("extra handler response = %d %q", rr.Code, rr.Body.String())
	}
}

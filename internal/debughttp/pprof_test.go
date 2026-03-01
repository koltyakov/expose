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

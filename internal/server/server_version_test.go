package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koltyakov/expose/internal/serviceapi"
)

func TestServerVersionEndpoint(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	srv.version = "v2.3.4"
	srv.cfg.WAFEnabled = true
	handler := srv.httpHandler()

	for _, tc := range []struct {
		name   string
		method string
		key    string
		status int
	}{
		{name: "authenticated", method: http.MethodGet, key: "owner", status: http.StatusOK},
		{name: "missing key", method: http.MethodGet, status: http.StatusUnauthorized},
		{name: "invalid key", method: http.MethodGet, key: "invalid", status: http.StatusUnauthorized},
		{name: "wrong method", method: http.MethodPost, key: "owner", status: http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "https://example.com"+serviceapi.Version, nil)
			if tc.key != "" {
				req.Header.Set("Authorization", "Bearer "+tc.key)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status = %d, headers = %v, body = %q", w.Code, w.Header(), w.Body.String())
			}
			if tc.status == http.StatusOK {
				if w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"version\":\"v2.3.4\"}\n" {
					t.Fatalf("unexpected version response: %v %q", w.Header(), w.Body.String())
				}
			}
			if tc.status == http.StatusMethodNotAllowed && w.Header().Get("Allow") != http.MethodGet {
				t.Errorf("Allow = %q, want GET", w.Header().Get("Allow"))
			}
		})
	}
}

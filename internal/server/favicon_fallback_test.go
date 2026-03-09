package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	embedassets "github.com/koltyakov/expose/internal/assets"
)

func TestShouldServeFallbackFavicon(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
		status int
		want   bool
	}{
		{name: "get favicon 404", method: http.MethodGet, path: "/favicon.ico", status: http.StatusNotFound, want: true},
		{name: "head favicon 404", method: http.MethodHead, path: "/favicon.ico", status: http.StatusNotFound, want: true},
		{name: "other path", method: http.MethodGet, path: "/icon-192.png", status: http.StatusNotFound, want: false},
		{name: "other status", method: http.MethodGet, path: "/favicon.ico", status: http.StatusOK, want: false},
		{name: "other method", method: http.MethodPost, path: "/favicon.ico", status: http.StatusNotFound, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if got := shouldServeFallbackFavicon(req, tc.status); got != tc.want {
				t.Fatalf("shouldServeFallbackFavicon() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestWriteFallbackFavicon(t *testing.T) {
	t.Parallel()

	t.Run("GET", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
		rr := httptest.NewRecorder()
		writeFallbackFavicon(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if got := rr.Header().Get("Content-Type"); got != "image/x-icon" {
			t.Fatalf("content-type = %q, want %q", got, "image/x-icon")
		}
		if rr.Body.Len() == 0 {
			t.Fatal("expected favicon body")
		}
		if !bytes.Equal(rr.Body.Bytes(), embedassets.FaviconICO) {
			t.Fatal("favicon body does not match embedded internal/assets/favicon.ico")
		}
	})

	t.Run("HEAD", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodHead, "/favicon.ico", nil)
		rr := httptest.NewRecorder()
		writeFallbackFavicon(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("head response body len = %d, want 0", rr.Body.Len())
		}
	})
}

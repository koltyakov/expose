package publish

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeCacheRevalidation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "index")
	writeFile(t, dir, "app.js", "script")
	for _, path := range []string{"/", "/index.html", "/client/route", "/app.js"} {
		t.Run(path, func(t *testing.T) {
			initial := httptest.NewRecorder()
			Serve(initial, httptest.NewRequest(http.MethodGet, path, nil), dir)
			etag := initial.Header().Get("ETag")
			if initial.Code != http.StatusOK || len(etag) < 2 || etag[0] != '"' || etag[len(etag)-1] != '"' {
				t.Fatalf("initial response: status=%d ETag=%q", initial.Code, etag)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, validator := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
					r := httptest.NewRequest(method, path, nil)
					r.Header.Set("If-None-Match", validator)
					rr := httptest.NewRecorder()
					Serve(rr, r, dir)
					if rr.Code != http.StatusNotModified || rr.Body.Len() != 0 {
						t.Fatalf("%s %s: status=%d body=%q", method, validator, rr.Code, rr.Body.String())
					}
					if rr.Header().Get("Cache-Control") != "no-cache" || rr.Header().Get("ETag") != etag {
						t.Fatalf("missing cache metadata: %v", rr.Header())
					}
				}
			}
			if initial.Header().Get("Cache-Control") != "no-cache" {
				t.Fatalf("unexpected cache policy: %v", initial.Header())
			}
		})
	}
}

func TestServeRepublishInvalidatesETag(t *testing.T) {
	oldDir, newDir := t.TempDir(), t.TempDir()
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	for dir, body := range map[string]string{oldDir: "old", newDir: "new"} {
		writeFile(t, dir, "index.html", body)
		if err := os.Chtimes(filepath.Join(dir, "index.html"), stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	initial := httptest.NewRecorder()
	Serve(initial, httptest.NewRequest(http.MethodGet, "/", nil), oldDir)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("If-None-Match", initial.Header().Get("ETag"))
	r.Header.Set("If-Modified-Since", initial.Header().Get("Last-Modified"))
	rr := httptest.NewRecorder()
	Serve(rr, r, newDir)
	if rr.Code != http.StatusOK || rr.Body.String() != "new" || rr.Header().Get("ETag") == initial.Header().Get("ETag") {
		t.Fatalf("republished response: status=%d body=%q headers=%v", rr.Code, rr.Body.String(), rr.Header())
	}
}

func TestServeErrorsAreNotCached(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/missing", http.StatusNotFound},
		{http.MethodGet, "/.env", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
	} {
		rr := httptest.NewRecorder()
		Serve(rr, httptest.NewRequest(tc.method, tc.path, nil), dir)
		if rr.Code != tc.status || rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("ETag") != "" {
			t.Fatalf("%s %s: status=%d headers=%v", tc.method, tc.path, rr.Code, rr.Header())
		}
	}
}

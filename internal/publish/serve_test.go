package publish

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeMissingAssetsDoNotUseSPAFallback(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "root app")
	// Even HTML alternatives must not mask a missing asset.
	writeFile(t, dir, "assets/missing.png.html", "not an image")
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, url := range []string{
			"/assets/missing.png", "/assets/missing%2ePNG?v=1", "/app.js", "/style.css",
			"/font.woff2", "/sound.mp3", "/manifest.webmanifest", "/app.js.map",
			"/data.json", "/module.wasm", "/missing.custom", "/missing.png/",
			"/.env", "/.git/config", "/assets/.git/config",
		} {
			t.Run(method+url, func(t *testing.T) {
				r := httptest.NewRequest(method, url, nil)
				r.Header.Set("Accept", "text/html,*/*")
				r.Header.Set("If-None-Match", "*")
				w := httptest.NewRecorder()
				Serve(w, r, dir)
				if w.Code != http.StatusNotFound || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("ETag") != "" {
					t.Fatalf("missing asset: status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
				}
			})
		}
	}
}

func TestServeSPAFallbackUsesRequestHeaders(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "root app")
	writeFile(t, dir, "app.js", "script")
	writeFile(t, dir, "docs.v1/index.html", "root app")
	for _, tc := range []struct {
		path, accept, dest string
		status             int
	}{
		{"/dashboard", "", "", 200},
		{"/dashboard", "text/html", "document", 200},
		{"/dashboard.html", "text/html", "iframe", 200},
		{"/dashboard", "text/html;q=0,*/*", "", 404},
		{"/api", "application/json", "", 404},
		{"/image", "*/*", "image", 404},
		{"/script", "*/*", "script", 404},
		{"/app.js", "application/json", "script", 200},
		{"/docs.v1/", "*/*", "empty", 200},
	} {
		t.Run(tc.path+tc.accept+tc.dest, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("Sec-Fetch-Dest", tc.dest)
			w := httptest.NewRecorder()
			readyCalls := 0
			ServeWithOptions(w, r, dir, ServeOptions{BeforeServe: func() { readyCalls++ }})
			if w.Code != tc.status || readyCalls != 1 {
				t.Fatalf("response: status=%d ready calls=%d", w.Code, readyCalls)
			}
			if tc.status == 200 && tc.path != "/app.js" {
				if w.Body.String() != "root app" || !strings.Contains(w.Header().Get("Vary"), "Accept, Sec-Fetch-Dest") {
					t.Fatalf("fallback: body=%q headers=%v", w.Body.String(), w.Header())
				}
			}
		})
	}
}

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

package publish

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresenceHTMLServing(t *testing.T) {
	dir := t.TempDir()
	html := "<!doctype html><html><head><title>Site</title></head><body>hello</body></html>"
	writeFile(t, dir, "index.html", html)
	writeFile(t, dir, "docs/index.html", html)
	writeFile(t, dir, "about.html", html)
	writeFile(t, dir, "app.js", "const value = 1;")
	writeFile(t, dir, "data.txt", "plain text")
	for _, path := range []string{"/", "/index.html", "/docs/", "/about", "/spa/route", "/app.js", "/data.txt"} {
		t.Run(path, func(t *testing.T) {
			plain := httptest.NewRecorder()
			Serve(plain, httptest.NewRequest("GET", path, nil), dir)
			enabled := httptest.NewRecorder()
			ServeWithOptions(enabled, httptest.NewRequest("GET", path, nil), dir, ServeOptions{WS: true})
			want := plain.Body.String()
			isHTML := strings.HasPrefix(plain.Header().Get("Content-Type"), "text/html")
			if isHTML {
				want += presenceHTMLScript
				if enabled.Header().Get("ETag") == plain.Header().Get("ETag") {
					t.Fatal("HTML variants share a cache validator")
				}
			}
			if enabled.Code != http.StatusOK || enabled.Body.String() != want {
				t.Fatalf("unexpected injected response: %d %q", enabled.Code, enabled.Body.String())
			}
			for _, method := range []string{"GET", "HEAD"} {
				r := httptest.NewRequest(method, path, nil)
				r.Header.Set("If-None-Match", enabled.Header().Get("ETag"))
				w := httptest.NewRecorder()
				ServeWithOptions(w, r, dir, ServeOptions{WS: true})
				if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
					t.Fatalf("cached %s: %d %q", method, w.Code, w.Body.String())
				}
			}
			head := httptest.NewRecorder()
			ServeWithOptions(head, httptest.NewRequest("HEAD", path, nil), dir, ServeOptions{WS: true})
			if head.Body.Len() != 0 || head.Header().Get("Content-Length") != fmt.Sprint(len(want)) {
				t.Fatalf("HEAD did not describe transformed response: %v", head.Header())
			}
			// Ranges before, across and after the original EOF must describe the
			// same representation as the complete HTML response.
			for _, start := range []int{0, len(plain.Body.Bytes()) - 3, len(want) - 3} {
				r := httptest.NewRequest("GET", path, nil)
				r.Header.Set("Range", fmt.Sprintf("bytes=%d-", start))
				w := httptest.NewRecorder()
				ServeWithOptions(w, r, dir, ServeOptions{WS: true})
				if w.Code != http.StatusPartialContent || w.Body.String() != want[start:] {
					t.Fatalf("range from %d: %d %q", start, w.Code, w.Body.String())
				}
			}
		})
	}
	stored, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil || string(stored) != html {
		t.Fatalf("injection changed uploaded content: %q %v", stored, err)
	}
}

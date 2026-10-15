package publish

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestRootCacheReusesUntilClosed(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "hello")
	cache := NewRootCache(4)

	first, cached, err := cache.open(dir)
	if err != nil || !cached {
		t.Fatalf("open = %v, cached %v; want cached root", err, cached)
	}
	again, cached, err := cache.open(dir)
	if err != nil || !cached || again != first {
		t.Fatalf("second open = %p (cached %v, %v), want reused %p", again, cached, err, first)
	}
	if cache.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", cache.Len())
	}

	cache.Close(dir)
	if cache.Len() != 0 {
		t.Fatalf("Len() after Close = %d, want 0", cache.Len())
	}
	if _, err := first.Open("index.html"); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed root Open error = %v, want os.ErrClosed", err)
	}
	reopened, cached, err := cache.open(dir)
	if err != nil || !cached || reopened == first {
		t.Fatalf("open after Close = %p (cached %v, %v), want a new cached root", reopened, cached, err)
	}
	cache.Close(dir)
	cache.Close(dir) // closing an absent entry is a no-op
}

func TestRootCacheBoundAndNil(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	cache := NewRootCache(1)
	if _, cached, err := cache.open(a); err != nil || !cached {
		t.Fatalf("open(a) cached = %v, %v", cached, err)
	}
	root, cached, err := cache.open(b)
	if err != nil || cached {
		t.Fatalf("open(b) past the bound cached = %v, %v; want caller-owned root", cached, err)
	}
	_ = root.Close()
	if cache.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", cache.Len())
	}
	cache.Close(a)

	var none *RootCache
	root, cached, err = none.open(a)
	if err != nil || cached {
		t.Fatalf("nil cache open cached = %v, %v; want caller-owned root", cached, err)
	}
	_ = root.Close()
	none.Close(a)
	if none.Len() != 0 {
		t.Fatal("nil cache reports open roots")
	}
}

func TestRootCacheDoesNotCacheMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "later")
	cache := NewRootCache(4)
	if _, _, err := cache.open(dir); err == nil {
		t.Fatal("open of a missing directory succeeded")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len() after failed open = %d, want 0", cache.Len())
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, cached, err := cache.open(dir); err != nil || !cached {
		t.Fatalf("open after creation cached = %v, %v", cached, err)
	}
	cache.Close(dir)
}

func TestRootCacheConcurrentOpen(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "hello")
	cache := NewRootCache(4)
	var wg sync.WaitGroup
	roots := make([]any, 32)
	for i := range roots {
		wg.Go(func() {
			root, cached, err := cache.open(dir)
			if err != nil || !cached {
				t.Errorf("open cached = %v, %v", cached, err)
				return
			}
			f, err := root.Open("index.html")
			if err != nil {
				t.Errorf("open file: %v", err)
				return
			}
			_ = f.Close()
			roots[i] = root
		})
	}
	wg.Wait()
	for _, root := range roots[1:] {
		if root != roots[0] {
			t.Fatal("concurrent opens returned different cached roots")
		}
	}
	if cache.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", cache.Len())
	}
	cache.Close(dir)
}

// TestServeWithRootCacheMatchesUncached compares complete responses, including
// validators, with and without a cache across the resolution and conditional
// request paths.
func TestServeWithRootCacheMatchesUncached(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html>root</html>")
	writeFile(t, dir, "app.js", "console.log(1)")
	writeFile(t, dir, "page.html", "<html>page</html>")
	if err := os.Mkdir(filepath.Join(dir, "docs"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "docs/index.html", "<html>docs</html>")
	cache := NewRootCache(4)
	defer cache.Close(dir)

	uncachedETag := httptest.NewRecorder()
	ServeWithOptions(uncachedETag, httptest.NewRequest(http.MethodGet, "/app.js", nil), dir, ServeOptions{})
	etag := uncachedETag.Header().Get("ETag")

	type request struct {
		method, path string
		headers      http.Header
	}
	requests := []request{
		{http.MethodGet, "/", nil},
		{http.MethodGet, "/app.js", nil},
		{http.MethodHead, "/app.js", nil},
		{http.MethodGet, "/page", nil},
		{http.MethodGet, "/docs/", nil},
		{http.MethodGet, "/missing/route", nil},
		{http.MethodGet, "/app.js", http.Header{"If-None-Match": {etag}}},
		{http.MethodGet, "/app.js", http.Header{"Range": {"bytes=2-5"}}},
		{http.MethodGet, "/app.js", http.Header{"Range": {"bytes=99-"}}},
		{http.MethodPost, "/app.js", nil},
		{http.MethodGet, "/%2e%2e/secret", nil},
	}
	for _, ws := range []bool{false, true} {
		for _, req := range requests {
			t.Run(fmt.Sprintf("ws=%t/%s %s %v", ws, req.method, req.path, req.headers), func(t *testing.T) {
				serve := func(roots *RootCache) *httptest.ResponseRecorder {
					r := httptest.NewRequest(req.method, req.path, nil)
					if req.headers != nil {
						r.Header = req.headers.Clone()
					}
					w := httptest.NewRecorder()
					ServeWithOptions(w, r, dir, ServeOptions{WS: ws, Roots: roots})
					return w
				}
				want := serve(nil)
				for range 2 { // first request opens the root, second reuses it
					got := serve(cache)
					if got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
						t.Fatalf("cached response = %d %v %q, uncached = %d %v %q",
							got.Code, got.Header(), got.Body.String(), want.Code, want.Header(), want.Body.String())
					}
				}
			})
		}
	}
	if cache.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", cache.Len())
	}
}

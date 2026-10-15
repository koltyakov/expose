package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestSiteLookupCacheExpiryAndInvalidation(t *testing.T) {
	t.Parallel()
	var c siteLookupCache
	now := time.Now()
	expires := now.Add(time.Minute)
	site := domain.PublishedSite{ID: "site_a", Hostname: "a.example.com", ExpiresAt: &expires}

	if _, ok := c.get(site.Hostname, now); ok {
		t.Fatal("empty cache returned a site")
	}
	c.put(site.Hostname, site, c.generation())
	if got, ok := c.get(site.Hostname, now); !ok || got.ID != site.ID {
		t.Fatalf("get = %+v, %v; want cached site", got, ok)
	}
	if _, ok := c.get(site.Hostname, expires); ok {
		t.Fatal("site served at its expiry instant")
	}
	if _, ok := c.get(site.Hostname, expires.Add(time.Second)); ok {
		t.Fatal("expired site served from cache")
	}

	c.invalidate(site.Hostname)
	if _, ok := c.get(site.Hostname, now); ok {
		t.Fatal("invalidated site still cached")
	}
	c.put(site.Hostname, site, c.generation())
	c.clear()
	if _, ok := c.get(site.Hostname, now); ok {
		t.Fatal("cleared site still cached")
	}

	permanent := domain.PublishedSite{ID: "site_b", Hostname: "b.example.com"}
	c.put(permanent.Hostname, permanent, c.generation())
	if _, ok := c.get(permanent.Hostname, now.Add(100*365*24*time.Hour)); !ok {
		t.Fatal("site without expiry was not cached")
	}
}

// TestSiteLookupCacheDiscardsStaleStoreReads covers a store read that started
// before an invalidation: its result predates the change and must not be
// cached after it.
func TestSiteLookupCacheDiscardsStaleStoreReads(t *testing.T) {
	t.Parallel()
	site := domain.PublishedSite{ID: "site_a", Hostname: "a.example.com"}
	for name, change := range map[string]func(*siteLookupCache){
		"clear":            func(c *siteLookupCache) { c.clear() },
		"invalidate host":  func(c *siteLookupCache) { c.invalidate(site.Hostname) },
		"invalidate other": func(c *siteLookupCache) { c.invalidate("other.example.com") },
	} {
		t.Run(name, func(t *testing.T) {
			var c siteLookupCache
			gen := c.generation()
			change(&c)
			c.put(site.Hostname, site, gen)
			if _, ok := c.get(site.Hostname, time.Now()); ok {
				t.Fatal("store result read before the change was cached")
			}
		})
	}
}

type siteLookupFixture struct {
	t     *testing.T
	ctx   context.Context
	st    *sqlite.Store
	srv   *Server
	owner domain.APIKey
}

func newSiteLookupFixture(t *testing.T, cfg config.ServerConfig) *siteLookupFixture {
	t.Helper()
	ctx := context.Background()
	cfg.BaseDomain = "example.com"
	cfg.DBPath = filepath.Join(t.TempDir(), "sites.db")
	st, err := sqlite.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	owner, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.authLimiter, srv.regLimiter = nil, nil
	return &siteLookupFixture{t: t, ctx: ctx, st: st, srv: srv, owner: owner}
}

func (f *siteLookupFixture) upload(query, index string) domain.PublishedSite {
	f.t.Helper()
	root := f.t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(index), 0o600); err != nil {
		f.t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/_expose/v1/sites?"+query, &archive)
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	f.srv.handleSites(w, r)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		f.t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var site domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		f.t.Fatal(err)
	}
	return site
}

func (f *siteLookupFixture) get(host string) (int, string) {
	w := httptest.NewRecorder()
	f.srv.handlePublic(w, httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil))
	return w.Code, w.Body.String()
}

func (f *siteLookupFixture) wantBody(step, host, body string) {
	f.t.Helper()
	if code, got := f.get(host); code != http.StatusOK || got != body {
		f.t.Fatalf("%s: %d %q, want 200 %q", step, code, got, body)
	}
}

func (f *siteLookupFixture) wantUnknown(step, host string) {
	f.t.Helper()
	if code, got := f.get(host); code != http.StatusNotFound {
		f.t.Fatalf("%s: %d %q, want the unknown-host 404", step, code, got)
	}
}

func (f *siteLookupFixture) cached(host string) bool {
	_, ok := f.srv.siteLookups.get(host, time.Now())
	return ok
}

func TestPublishedSiteLookupCacheFollowsPublications(t *testing.T) {
	t.Parallel()
	f := newSiteLookupFixture(t, config.ServerConfig{})
	site := f.upload("domain=lookup", "v0")
	if f.cached(site.Hostname) {
		t.Fatal("upload cached the site before any request")
	}
	f.wantBody("first request", site.Hostname, "v0")
	if !f.cached(site.Hostname) {
		t.Fatal("served site was not cached")
	}

	// Replacement takes effect on the next request, with no sweep.
	f.upload("domain=lookup", "v1")
	f.wantBody("after replace", site.Hostname, "v1")

	r := httptest.NewRequest(http.MethodDelete, "/_expose/v1/sites/lookup", nil)
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	f.srv.handleSites(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if f.cached(site.Hostname) {
		t.Fatal("deleted site still cached")
	}
	f.wantUnknown("after delete", site.Hostname)

	// A new publication on the same hostname is not shadowed by old state.
	f.upload("domain=lookup", "v2")
	f.wantBody("after republish", site.Hostname, "v2")
}

func TestPublishedSiteLookupCacheHonorsExpiry(t *testing.T) {
	t.Parallel()
	f := newSiteLookupFixture(t, config.ServerConfig{})
	site := f.upload("domain=brief&ttl=300ms", "brief")
	f.wantBody("before expiry", site.Hostname, "brief")
	if !f.cached(site.Hostname) {
		t.Fatal("served site was not cached")
	}
	// No sweep runs here: the cached expiry alone must stop serving.
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := f.get(site.Hostname)
		if code == http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expired site still served: %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if site.ExpiresAt == nil || time.Now().Before(*site.ExpiresAt) {
		t.Fatal("site stopped serving before its expiry")
	}
}

func TestPublishedSiteLookupCacheRechecksRevocationOnHeartbeat(t *testing.T) {
	t.Parallel()
	f := newSiteLookupFixture(t, config.ServerConfig{
		HeartbeatCheckInterval: 25 * time.Millisecond,
		CleanupInterval:        time.Hour,
	})
	site := f.upload("domain=revoked", "live")
	f.wantBody("before revocation", site.Hostname, "live")

	// The CLI revokes keys in another process, so the server is not told.
	if err := f.st.RevokeAPIKey(f.ctx, f.owner.ID); err != nil {
		t.Fatal(err)
	}
	f.wantBody("between sweeps", site.Hostname, "live")

	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.srv.runJanitor(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := f.get(site.Hostname)
		if code == http.StatusNotFound {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revoked key's site still served after heartbeat sweeps: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if f.cached(site.Hostname) {
		t.Fatal("revoked key's site was cached again")
	}
}

// TestPublishedSiteLookupCacheConcurrentChanges races readers against
// republishing and heartbeat clears; every response must be one complete
// publication.
func TestPublishedSiteLookupCacheConcurrentChanges(t *testing.T) {
	t.Parallel()
	f := newSiteLookupFixture(t, config.ServerConfig{})
	site := f.upload("domain=busy", "v0")
	var stop atomic.Bool
	var failures atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for !stop.Load() {
				code, body := f.get(site.Hostname)
				if code != http.StatusOK || len(body) < 2 || body[0] != 'v' {
					failures.Add(1)
				}
			}
		})
	}
	wg.Go(func() {
		for !stop.Load() {
			f.srv.siteLookups.clear()
			time.Sleep(time.Millisecond)
		}
	})
	for i := 1; i <= 20; i++ {
		f.upload("domain=busy", fmt.Sprintf("v%d", i))
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests failed during concurrent changes", failures.Load())
	}
	f.wantBody("final", site.Hostname, "v20")
}

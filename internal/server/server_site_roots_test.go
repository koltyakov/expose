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

// TestPublishedSiteRootsClosedBeforeRemoval checks that every path deleting a
// publication directory first closes its cached root, and that serving stays
// correct while publications are replaced.
func TestPublishedSiteRootsClosedBeforeRemoval(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sites.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	owner, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.authLimiter, srv.regLimiter = nil, nil

	archive := func(index string) []byte {
		t.Helper()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(index), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := publish.Archive(root, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	upload := func(query, index string) domain.PublishedSite {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/_expose/v1/sites?"+query, bytes.NewReader(archive(index)))
		r.Header.Set("Authorization", "Bearer owner")
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			t.Fatalf("upload: %d %s", w.Code, w.Body.String())
		}
		var site domain.PublishedSite
		if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
			t.Fatal(err)
		}
		stored, err := st.FindPublishedSite(ctx, site.Hostname)
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	get := func(host string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.handlePublic(w, httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil))
		return w
	}
	wantOpen := func(step string, n int) {
		t.Helper()
		if got := srv.siteRoots.Len(); got != n {
			t.Fatalf("%s: %d cached roots, want %d", step, got, n)
		}
	}
	dirOf := func(site domain.PublishedSite) string {
		return filepath.Join(srv.publishDir(), site.StorageID())
	}
	assertRemoved := func(step string, site domain.PublishedSite) {
		t.Helper()
		if _, err := os.Stat(dirOf(site)); !os.IsNotExist(err) {
			t.Fatalf("%s: publication directory remains: %v", step, err)
		}
	}

	first := upload("domain=roots", "v0")
	if w := get(first.Hostname); w.Code != http.StatusOK || w.Body.String() != "v0" {
		t.Fatalf("first serve: %d %q", w.Code, w.Body.String())
	}
	wantOpen("after first serve", 1)

	// Replacement closes the previous root before removing its directory.
	second := upload("domain=roots", "v1")
	wantOpen("after replace", 0)
	assertRemoved("replace", first)
	if w := get(second.Hostname); w.Code != http.StatusOK || w.Body.String() != "v1" {
		t.Fatalf("serve after replace: %d %q", w.Code, w.Body.String())
	}
	wantOpen("after serving the replacement", 1)

	// Readers racing replacements always see one complete publication.
	var stop atomic.Bool
	var failures atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for !stop.Load() {
				w := get(second.Hostname)
				if w.Code != http.StatusOK || len(w.Body.String()) < 2 || w.Body.String()[0] != 'v' {
					failures.Add(1)
				}
			}
		})
	}
	latest := second
	for i := 2; i < 22; i++ {
		previous := latest
		latest = upload("domain=roots", fmt.Sprintf("v%d", i))
		assertRemoved(fmt.Sprintf("replace %d", i), previous)
	}
	stop.Store(true)
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests failed while publications were replaced", failures.Load())
	}
	if w := get(latest.Hostname); w.Body.String() != "v21" {
		t.Fatalf("final content = %q, want v21", w.Body.String())
	}
	wantOpen("after concurrent replacements", 1)

	// Deletion closes the root first.
	r := httptest.NewRequest(http.MethodDelete, "/_expose/v1/sites/roots", nil)
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	srv.handleSites(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	wantOpen("after delete", 0)
	assertRemoved("delete", latest)

	// Expiry cleanup deletes through the same path.
	expiring := upload("domain=expiring", "soon")
	get(expiring.Hostname)
	wantOpen("after serving expiring site", 1)
	expired := time.Now().Add(-time.Second)
	expiring.ExpiresAt = &expired
	if err := st.ReplacePublishedSite(ctx, expiring); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	wantOpen("after expiry cleanup", 0)
	assertRemoved("expiry", expiring)

	// A served directory whose record disappeared is closed before the
	// stale-directory sweep removes it.
	orphan := upload("domain=orphan", "orphan")
	get(orphan.Hostname)
	wantOpen("after serving orphan", 1)
	if err := st.DeletePublishedSite(ctx, owner.ID, orphan.ID); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dirOf(orphan), old, old); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	wantOpen("after orphan cleanup", 0)
	assertRemoved("orphan cleanup", orphan)
}

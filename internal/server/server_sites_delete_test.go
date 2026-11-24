package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestSiteDeletionRemovesFilesOutsideSitesLock(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sites.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", "")); err != nil {
		t.Fatal(err)
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.authLimiter, srv.regLimiter = nil, nil

	upload := func(label, content string) domain.PublishedSite {
		t.Helper()
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := publish.Archive(root, &buf); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/_expose/v1/sites?domain="+label, &buf)
		r.Header.Set("Authorization", "Bearer owner")
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("upload %s: %d %s", label, w.Code, w.Body.String())
		}
		var site domain.PublishedSite
		if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
			t.Fatal(err)
		}
		return site
	}
	big := upload("big", "big")
	other := upload("other", "other")

	// Hold the file removal open, as a 20,000-file RemoveAll would.
	removing := make(chan string, 1)
	finish := make(chan struct{})
	original := removeSiteDir
	removeSiteDir = func(dir string) error {
		removing <- dir
		<-finish
		return original(dir)
	}
	t.Cleanup(func() { removeSiteDir = original })

	deleted := make(chan int, 1)
	go func() {
		r := httptest.NewRequest(http.MethodDelete, "/_expose/v1/sites/big", nil)
		r.Header.Set("Authorization", "Bearer owner")
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		deleted <- w.Code
	}()
	var tomb string
	select {
	case tomb = <-removing:
	case <-time.After(5 * time.Second):
		t.Fatal("deletion never reached file removal")
	}
	if !strings.HasPrefix(filepath.Base(tomb), siteTombstonePrefix) {
		t.Fatalf("removed %q, want a tombstone", tomb)
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), big.StorageID())); !os.IsNotExist(err) {
		t.Fatalf("published directory still present during removal: %v", err)
	}

	served := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		srv.handlePublic(w, httptest.NewRequest(http.MethodGet, "https://"+other.Hostname+"/", nil))
		served <- w.Code
	}()
	select {
	case code := <-served:
		if code != http.StatusOK {
			t.Fatalf("other site: %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("other site blocked while a deleted site's files were removed")
	}
	close(finish)
	if code := <-deleted; code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, err := os.Stat(tomb); !os.IsNotExist(err) {
		t.Fatalf("tombstone left behind: %v", err)
	}
}

func TestCleanupReapsLeftoverSiteTombstones(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sites.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	tomb := filepath.Join(srv.publishDir(), siteTombstonePrefix+"site_x-1")
	if err := os.MkdirAll(filepath.Join(tomb, "assets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tomb, "assets", "a.js"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tomb); !os.IsNotExist(err) {
		t.Fatalf("startup cleanup kept a tombstone: %v", err)
	}
}

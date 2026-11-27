package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

// publishRecoveryTestSite publishes index.html with content at label and
// returns the stored publication.
func publishRecoveryTestSite(t *testing.T, srv *Server, label, content string) domain.PublishedSite {
	t.Helper()
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", content)
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	w := incrementalSiteRequest(srv, http.MethodPost, serviceapi.Sites+"?domain="+label, "owner", "", archive.Bytes())
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("publish %s: %d %s", label, w.Code, w.Body.String())
	}
	var site domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	// The response omits the revision; read it back.
	stored, err := srv.store.(siteStore).FindPublishedSite(context.Background(), site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func recoveryServe(srv *Server, host string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	srv.handlePublic(w, httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil))
	return w
}

func recoveryTombstones(t *testing.T, srv *Server) []string {
	t.Helper()
	entries, err := os.ReadDir(srv.publishDir())
	if err != nil {
		t.Fatal(err)
	}
	var tombs []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), siteTombstonePrefix) {
			tombs = append(tombs, entry.Name())
		}
	}
	return tombs
}

func recoveryStorageDir(srv *Server, site domain.PublishedSite) string {
	return filepath.Join(srv.publishDir(), site.StorageID())
}

// deleteHookStore runs hook in place of the database deletion; hook may call
// the real deletion through next.
type deleteHookStore struct {
	*sqlite.Store
	hook func(ctx context.Context, key, id string, next func() error) error
}

func (s *deleteHookStore) DeletePublishedSite(ctx context.Context, key, id string) error {
	return s.hook(ctx, key, id, func() error { return s.Store.DeletePublishedSite(ctx, key, id) })
}

// An earlier release moved the files aside before the deletion committed.
// A crash or failed commit in that window left the site published with its
// content in a tombstone; startup cleanup must restore it, not reap it.
func TestCleanupRecoversLegacyPreCommitTombstone(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	other := publishRecoveryTestSite(t, srv, "other", "other")
	dir := recoveryStorageDir(srv, site)

	older := filepath.Join(srv.publishDir(), siteTombstonePrefix+site.StorageID()+"-"+strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 36))
	newer := filepath.Join(srv.publishDir(), siteTombstonePrefix+site.StorageID()+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err := os.Rename(dir, newer); err != nil {
		t.Fatal(err)
	}
	writeIncrementalTestFile(t, older, "index.html", "older attempt")
	// A tombstone of an unpublished revision is still reaped.
	unrelated := filepath.Join(srv.publishDir(), siteTombstonePrefix+"site_gone-1")
	writeIncrementalTestFile(t, unrelated, "index.html", "gone")

	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || string(b) != "live" {
		t.Fatalf("live content not recovered from the newest tombstone: %q, %v", b, err)
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("tombstones left after recovery: %v", tombs)
	}
	if w := recoveryServe(srv, site.Hostname); w.Code != http.StatusOK || w.Body.String() != "live" {
		t.Fatalf("recovered site: %d %q", w.Code, w.Body.String())
	}
	if w := recoveryServe(srv, other.Hostname); w.Code != http.StatusOK || w.Body.String() != "other" {
		t.Fatalf("unrelated site: %d %q", w.Code, w.Body.String())
	}

	// A missing revision with no tombstone is left for the operator; cleanup
	// still succeeds and does not touch other publications.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := recoveryServe(srv, other.Hostname); w.Code != http.StatusOK {
		t.Fatalf("unrelated site after cleanup: %d", w.Code)
	}
}

func recoveryTombstoneName(site domain.PublishedSite, at time.Time) string {
	return siteTombstonePrefix + site.StorageID() + "-" + strconv.FormatInt(at.UnixNano(), 36)
}

// Only a real directory is promoted back to a revision, even when a file or
// symlink with a tombstone name looks like a more recent attempt.
func TestCleanupRecoversOnlyDirectoryTombstones(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	dir := recoveryStorageDir(srv, site)
	now := time.Now()
	if err := os.Rename(dir, filepath.Join(srv.publishDir(), recoveryTombstoneName(site, now.Add(-time.Hour)))); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(srv.publishDir(), recoveryTombstoneName(site, now))
	if err := os.WriteFile(file, []byte("not a revision"), 0600); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	writeIncrementalTestFile(t, elsewhere, "index.html", "elsewhere")
	link := filepath.Join(srv.publishDir(), recoveryTombstoneName(site, now.Add(time.Hour)))
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}

	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		t.Fatalf("revision not recovered as a directory: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || string(b) != "live" {
		t.Fatalf("recovered content: %q, %v", b, err)
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("non-directory tombstones not reaped: %v", tombs)
	}
	if b, err := os.ReadFile(filepath.Join(elsewhere, "index.html")); err != nil || string(b) != "elsewhere" {
		t.Fatalf("symlink target changed: %q, %v", b, err)
	}
	if w := recoveryServe(srv, site.Hostname); w.Code != http.StatusOK || w.Body.String() != "live" {
		t.Fatalf("recovered site: %d %q", w.Code, w.Body.String())
	}
}

// A non-directory at the revision path is not taken as the revision: the
// directory copy is kept rather than reaped, and nothing is overwritten.
func TestCleanupKeepsTombstoneWhenRevisionPathBlocked(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	dir := recoveryStorageDir(srv, site)
	tomb := filepath.Join(srv.publishDir(), recoveryTombstoneName(site, time.Now()))
	if err := os.Rename(dir, tomb); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 { // startup, then a periodic pass
		if err := srv.cleanupPublishedSites(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(tomb, "index.html")); err != nil || string(b) != "live" {
		t.Fatalf("directory copy not preserved: %q, %v", b, err)
	}
	if b, err := os.ReadFile(dir); err != nil || string(b) != "placeholder" {
		t.Fatalf("blocking entry changed: %q, %v", b, err)
	}
	// Once the path is clear, the next pass recovers the revision.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || string(b) != "live" {
		t.Fatalf("revision not recovered after clearing the path: %q, %v", b, err)
	}
}

func TestSiteDeletionFailedCommitKeepsPublication(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	dir := recoveryStorageDir(srv, site)
	if w := recoveryServe(srv, site.Hostname); w.Code != http.StatusOK {
		t.Fatalf("serve: %d", w.Code)
	}
	commitErr := errors.New("disk I/O error")
	srv.store = &deleteHookStore{Store: st, hook: func(context.Context, string, string, func() error) error {
		if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
			t.Errorf("files moved before the deletion committed: %v", err)
		}
		return commitErr
	}}
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("failed delete: %d %s", w.Code, w.Body.String())
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("failed delete left tombstones: %v", tombs)
	}
	if w := recoveryServe(srv, site.Hostname); w.Code != http.StatusOK || w.Body.String() != "live" {
		t.Fatalf("site after failed delete: %d %q", w.Code, w.Body.String())
	}
	if _, ok := srv.siteStats.Load(site.ID); !ok {
		t.Fatal("failed delete dropped live stats")
	}
	w := incrementalSiteRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs", "owner", "", nil)
	if w.Code != http.StatusOK || w.Header().Get("ETag") != publishedSiteRevision(&site) {
		t.Fatalf("files after failed delete: %d %s", w.Code, w.Header().Get("ETag"))
	}
	// Restart-equivalent cleanup keeps the still-published content.
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatalf("cleanup removed a published revision: %v", err)
	}
}

func TestSiteDeletionCommitsBeforeRetiringFiles(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	dir := recoveryStorageDir(srv, site)
	committed := false
	srv.store = &deleteHookStore{Store: st, hook: func(_ context.Context, _, _ string, next func() error) error {
		if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
			t.Errorf("files moved before the deletion committed: %v", err)
		}
		err := next()
		committed = err == nil
		return err
	}}
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if !committed {
		t.Fatal("deletion did not commit")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("deleted revision remains: %v", err)
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("tombstones left: %v", tombs)
	}
	if w := recoveryServe(srv, site.Hostname); w.Code == http.StatusOK {
		t.Fatal("deleted site still served")
	}
	// Deleting again is a clean not-found, and the hostname is free again.
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("repeat delete: %d", w.Code)
	}
	again := publishRecoveryTestSite(t, srv, "docs", "again")
	if w := recoveryServe(srv, again.Hostname); w.Code != http.StatusOK || w.Body.String() != "again" {
		t.Fatalf("republished site: %d %q", w.Code, w.Body.String())
	}
}

// A crash after the deletion committed but before its files moved leaves an
// unreferenced revision directory. Cleanup reaps it as an orphan once aged,
// and never touches published revisions.
func TestCleanupReapsRevisionLeftByPostCommitCrash(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "deleted")
	other := publishRecoveryTestSite(t, srv, "other", "other")
	stored, err := st.FindPublishedSite(t.Context(), site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePublishedSite(t.Context(), stored.APIKeyID, stored.ID); err != nil {
		t.Fatal(err)
	}
	dir := recoveryStorageDir(srv, site)
	// A recent orphan may be an upload about to commit; it waits.
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("recent orphan reaped early: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour)
	for _, d := range []string{dir, recoveryStorageDir(srv, other)} {
		if err := os.Chtimes(d, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("orphaned revision remains: %v", err)
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("tombstones left: %v", tombs)
	}
	if w := recoveryServe(srv, other.Hostname); w.Code != http.StatusOK || w.Body.String() != "other" {
		t.Fatalf("published site after cleanup: %d %q", w.Code, w.Body.String())
	}
}

func TestSiteDeletionDefersRemovalToPinnedReader(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	dir := recoveryStorageDir(srv, site)
	srv.sitesMu.RLock()
	unpin := srv.pinSiteDir(dir)
	srv.sitesMu.RUnlock()
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if b, err := os.ReadFile(filepath.Join(dir, "index.html")); err != nil || string(b) != "live" {
		t.Fatalf("pinned revision moved or removed: %q, %v", b, err)
	}
	// Cleanup leaves a pinned revision alone even when it has aged.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	if err := srv.cleanupPublishedSites(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("cleanup removed a pinned revision: %v", err)
	}
	unpin()
	unpin() // releasing twice is harmless
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("last reader did not remove the deleted revision: %v", err)
	}
	if srv.siteDirPinned(dir) {
		t.Fatal("pin retained")
	}
}

func TestSiteDeletionToleratesMissingFiles(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	if err := os.RemoveAll(recoveryStorageDir(srv, site)); err != nil {
		t.Fatal(err)
	}
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("tombstones left: %v", tombs)
	}
}

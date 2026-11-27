package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

// publishedFileTotals pins site's revision and returns its file totals, as a
// stats poll does without the request plumbing.
func (s *Server) publishedFileTotals(site domain.PublishedSite) (int, int64, error) {
	s.sitesMu.RLock()
	unpin := s.pinSiteDir(filepath.Join(s.publishDir(), site.StorageID()))
	tracker := s.statsForSite(site.ID)
	s.sitesMu.RUnlock()
	defer unpin()
	return s.pinnedFileTotals(tracker, site)
}

// metadataGate holds a cold metadata read open until released.
type metadataGate struct {
	started chan string
	release chan struct{}
}

func newMetadataGate() *metadataGate {
	return &metadataGate{started: make(chan string, 16), release: make(chan struct{})}
}

func (g *metadataGate) wait(t *testing.T) string {
	t.Helper()
	select {
	case dir := <-g.started:
		return dir
	case <-time.After(5 * time.Second):
		t.Fatal("cold metadata read never started")
		return ""
	}
}

func gateManifestHashing(t *testing.T) *metadataGate {
	gate := newMetadataGate()
	original := siteManifestFiles
	siteManifestFiles = func(dir string) ([]domain.PublishedFile, error) {
		gate.started <- dir
		<-gate.release
		return original(dir)
	}
	t.Cleanup(func() { siteManifestFiles = original })
	return gate
}

func gateFileTotals(t *testing.T) *metadataGate {
	gate := newMetadataGate()
	original := siteFileTotals
	siteFileTotals = func(dir string) (int, int64, error) {
		gate.started <- dir
		<-gate.release
		return original(dir)
	}
	t.Cleanup(func() { siteFileTotals = original })
	return gate
}

func metadataRequest(srv *Server, method, path string) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- incrementalSiteRequest(srv, method, path, "owner", "", nil) }()
	return done
}

func metadataResponse(t *testing.T, done <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("metadata request did not finish")
		return nil
	}
}

// assertSitesLockFree proves the cold read does not hold sitesMu in either
// mode, then that unrelated publications commit and serve meanwhile.
func assertSitesLockFree(t *testing.T, srv *Server, label string) {
	t.Helper()
	if !srv.sitesMu.TryLock() {
		t.Fatal("cold metadata read holds sitesMu")
	}
	srv.sitesMu.Unlock()
	site := publishRecoveryTestSite(t, srv, label, label)
	if w := recoveryServe(srv, site.Hostname); w.Code != http.StatusOK || w.Body.String() != label {
		t.Fatalf("unrelated publication: %d %q", w.Code, w.Body.String())
	}
}

func decodeManifest(t *testing.T, w *httptest.ResponseRecorder) []domain.PublishedFile {
	t.Helper()
	var files []domain.PublishedFile
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &files) != nil {
		t.Fatalf("files: %d %s", w.Code, w.Body.String())
	}
	return files
}

func decodeStats(t *testing.T, w *httptest.ResponseRecorder) domain.PublishedSiteStats {
	t.Helper()
	var stats domain.PublishedSiteStats
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &stats) != nil {
		t.Fatalf("stats: %d %s", w.Code, w.Body.String())
	}
	return stats
}

func TestColdManifestHashingDoesNotHoldSitesLock(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	srv.siteManifests.delete(site.StorageID())
	gate := gateManifestHashing(t)
	done := metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs")
	if dir := gate.wait(t); dir != recoveryStorageDir(srv, site) {
		t.Fatalf("hashed %s", dir)
	}
	assertSitesLockFree(t, srv, "unrelated")
	close(gate.release)
	w := metadataResponse(t, done)
	if files := decodeManifest(t, w); len(files) != 1 || files[0].Size != int64(len("live")) {
		t.Fatalf("manifest: %+v", files)
	}
	if w.Header().Get("ETag") != publishedSiteRevision(&site) {
		t.Fatalf("ETag %s", w.Header().Get("ETag"))
	}
	if _, ok := srv.siteManifests.get(site.StorageID()); !ok {
		t.Fatal("cold manifest not cached")
	}
	if srv.siteDirPinned(recoveryStorageDir(srv, site)) {
		t.Fatal("pin leaked")
	}
}

func TestColdFileTotalsWalkDoesNotHoldSitesLock(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	// Simulate a restart: no cached manifest or totals.
	srv.siteManifests.delete(site.StorageID())
	srv.siteStats.Delete(site.ID)
	gate := gateFileTotals(t)
	done := metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats")
	gate.wait(t)
	assertSitesLockFree(t, srv, "unrelated")
	close(gate.release)
	stats := decodeStats(t, metadataResponse(t, done))
	if stats.FileCount != 1 || stats.FileBytes != int64(len("live")) {
		t.Fatalf("totals: %d %d", stats.FileCount, stats.FileBytes)
	}
	// Totals are cached for the revision; the next poll does not walk.
	srv.siteManifests.delete(site.StorageID())
	walked := make(chan struct{}, 1)
	siteFileTotals = func(string) (int, int64, error) { walked <- struct{}{}; return 0, 0, nil }
	decodeStats(t, incrementalSiteRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats", "owner", "", nil))
	select {
	case <-walked:
		t.Fatal("cached totals walked again")
	default:
	}
}

func TestFileTotalsPrimedFromPublishedManifest(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	walked := make(chan struct{}, 4)
	original := siteFileTotals
	siteFileTotals = func(dir string) (int, int64, error) { walked <- struct{}{}; return original(dir) }
	t.Cleanup(func() { siteFileTotals = original })
	check := func(step string) {
		t.Helper()
		stats := decodeStats(t, incrementalSiteRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats", "owner", "", nil))
		if stats.FileCount != 1 || stats.FileBytes != int64(len("live")) {
			t.Fatalf("%s totals: %d %d", step, stats.FileCount, stats.FileBytes)
		}
		select {
		case <-walked:
			t.Fatalf("%s walked the revision", step)
		default:
		}
	}
	check("after upload")
	// A fresh tracker can use a manifest already cached by a files listing.
	srv.siteStats.Delete(site.ID)
	check("from cached manifest")
}

// blockingVisitorStore holds stored-visitor loads open.
type blockingVisitorStore struct {
	*sqlite.Store
	siteID string
	gate   *metadataGate
}

func (s *blockingVisitorStore) ListPublishedSiteVisitors(ctx context.Context, id string) ([][32]byte, error) {
	if id == s.siteID {
		s.gate.started <- id
		<-s.gate.release
	}
	return s.Store.ListPublishedSiteVisitors(ctx, id)
}

func TestStoredVisitorLoadDoesNotHoldSitesLock(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	site := publishRecoveryTestSite(t, srv, "docs", "live")
	gate := newMetadataGate()
	srv.store = &blockingVisitorStore{Store: st, siteID: site.ID, gate: gate}
	srv.siteStats.Delete(site.ID) // the next tracker loads through the blocking store
	done := metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats")
	if id := gate.wait(t); id != site.ID {
		t.Fatalf("loaded visitors of %s", id)
	}
	assertSitesLockFree(t, srv, "unrelated")
	close(gate.release)
	decodeStats(t, metadataResponse(t, done))
}

// A files listing resolved before a replacement or deletion reports that
// revision consistently: its ETag and the manifest of its own files, and the
// stale revision is neither cached nor kept on disk afterwards.
func TestColdManifestSnapshotStableAcrossReplaceAndDelete(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	first := publishRecoveryTestSite(t, srv, "docs", "first")
	firstDir := recoveryStorageDir(srv, first)
	srv.siteManifests.delete(first.StorageID())
	gate := gateManifestHashing(t)
	done := metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs")
	gate.wait(t)
	second := publishRecoveryTestSite(t, srv, "docs", "second revision")
	if second.StorageID() == first.StorageID() {
		t.Fatal("replacement reused the revision")
	}
	if _, err := os.Stat(firstDir); err != nil {
		t.Fatalf("pinned revision removed during hashing: %v", err)
	}
	close(gate.release)
	w := metadataResponse(t, done)
	if w.Header().Get("ETag") != publishedSiteRevision(&first) {
		t.Fatalf("ETag %s, want the snapshot's revision", w.Header().Get("ETag"))
	}
	if files := decodeManifest(t, w); len(files) != 1 || files[0].Size != int64(len("first")) {
		t.Fatalf("snapshot manifest: %+v", files)
	}
	if _, ok := srv.siteManifests.get(first.StorageID()); ok {
		t.Fatal("replaced revision's manifest cached")
	}
	if _, err := os.Stat(firstDir); !os.IsNotExist(err) {
		t.Fatalf("replaced revision kept after its reader finished: %v", err)
	}
	w = incrementalSiteRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs", "owner", "", nil)
	if files := decodeManifest(t, w); w.Header().Get("ETag") != publishedSiteRevision(&second) || len(files) != 1 || files[0].Size != int64(len("second revision")) {
		t.Fatalf("current listing: %s %+v", w.Header().Get("ETag"), files)
	}

	secondDir := recoveryStorageDir(srv, second)
	srv.siteManifests.delete(second.StorageID())
	gate = gateManifestHashing(t)
	done = metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs")
	gate.wait(t)
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete during hashing: %d %s", w.Code, w.Body.String())
	}
	close(gate.release)
	w = metadataResponse(t, done)
	if files := decodeManifest(t, w); w.Header().Get("ETag") != publishedSiteRevision(&second) || len(files) != 1 {
		t.Fatalf("snapshot after delete: %s %+v", w.Header().Get("ETag"), files)
	}
	if len(srv.siteManifests.entries) != 0 {
		t.Fatalf("deleted revision's manifest cached: %d entries", len(srv.siteManifests.entries))
	}
	if _, err := os.Stat(secondDir); !os.IsNotExist(err) {
		t.Fatalf("deleted revision kept after its reader finished: %v", err)
	}
	if tombs := recoveryTombstones(t, srv); len(tombs) != 0 {
		t.Fatalf("tombstones left: %v", tombs)
	}
	if w := incrementalSiteRequest(srv, http.MethodGet, serviceapi.Sites+"/files?domain=docs", "owner", "", nil); w.Header().Get("ETag") != `"new"` {
		t.Fatalf("listing after delete: %d %s", w.Code, w.Header().Get("ETag"))
	}
}

func TestColdFileTotalsDoNotResurrectReplacedOrDeletedRevision(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	first := publishRecoveryTestSite(t, srv, "docs", "first")
	srv.siteManifests.delete(first.StorageID())
	srv.statsForSite(first.ID).primeFileTotals("", 0, 0)
	gate := gateFileTotals(t)
	done := metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats")
	gate.wait(t)
	second := publishRecoveryTestSite(t, srv, "docs", "second revision")
	close(gate.release)
	if stats := decodeStats(t, metadataResponse(t, done)); stats.FileBytes != int64(len("first")) {
		t.Fatalf("snapshot totals: %d", stats.FileBytes)
	}
	tracker := srv.statsForSite(second.ID)
	tracker.mu.Lock()
	id, size := tracker.filesStorageID, tracker.fileBytes
	tracker.mu.Unlock()
	if id != second.StorageID() || size != int64(len("second revision")) {
		t.Fatalf("stale walk replaced the new revision's totals: %s %d", id, size)
	}

	srv.siteManifests.delete(second.StorageID())
	tracker.primeFileTotals("", 0, 0)
	gate = gateFileTotals(t)
	done = metadataRequest(srv, http.MethodGet, serviceapi.Sites+"/docs/stats")
	gate.wait(t)
	if w := incrementalSiteRequest(srv, http.MethodDelete, serviceapi.Sites+"/docs", "owner", "", nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete during walk: %d %s", w.Code, w.Body.String())
	}
	close(gate.release)
	metadataResponse(t, done)
	if _, ok := srv.siteStats.Load(second.ID); ok {
		t.Fatal("stats resurrected for a deleted publication")
	}
	if _, err := os.Stat(recoveryStorageDir(srv, second)); !os.IsNotExist(err) {
		t.Fatalf("deleted revision kept after its reader finished: %v", err)
	}
}

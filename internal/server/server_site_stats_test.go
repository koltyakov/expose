package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/waf"
)

func TestPublishedStatsAccessAndTraffic(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "stats.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	owner, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIKey(ctx, "other", auth.HashAPIKey("other", "")); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath, WAFEnabled: true}, st, logger, "stats-test")
	srv.authLimiter, srv.regLimiter = nil, nil
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	api := func(method, path, key string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		return w
	}
	w := api("POST", "/_expose/v1/sites?domain=stats", "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	var site domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	snapshot := func() domain.PublishedSiteStats {
		t.Helper()
		w := api("GET", "/_expose/v1/sites/stats/stats", "owner", nil)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("stats: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "private-token") || strings.Contains(w.Body.String(), "192.0.2.") {
			t.Fatal("stats leaked request credentials/address")
		}
		var stats domain.PublishedSiteStats
		if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
			t.Fatal(err)
		}
		return stats
	}
	if stats := snapshot(); stats.HTTPRequests != 0 {
		t.Fatal("stats polling counted as traffic")
	}
	if stats := snapshot(); stats.FileCount != 2 || stats.FileBytes != 15 {
		t.Fatalf("wrong published file totals: %+v", stats)
	}
	for _, check := range []struct {
		key    string
		status int
	}{{"other", 404}, {"invalid", 401}} {
		if w := api("GET", "/_expose/v1/sites/"+site.ID+"/stats", check.key, nil); w.Code != check.status {
			t.Fatalf("stats ownership: %d", w.Code)
		}
	}
	if w := api("DELETE", "/_expose/v1/sites/"+site.ID+"/stats", "owner", nil); w.Code != 405 {
		t.Fatalf("stats endpoint accepted delete: %d", w.Code)
	}
	for _, method := range []string{"GET", "HEAD"} {
		r := httptest.NewRequest(method, "https://stats.example.com/?token=private-token", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		srv.handlePublic(w, r)
		if w.Code != 200 {
			t.Fatalf("public request: %d", w.Code)
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD wrote body")
		}
	}
	r := httptest.NewRequest("GET", "https://stats.example.com/app.js", nil)
	r.RemoteAddr = "192.0.2.2:1234"
	r.Header.Set("Range", "bytes=0-3")
	w = httptest.NewRecorder()
	srv.handlePublic(w, r)
	if w.Code != 206 || w.Body.String() != "0123" {
		t.Fatalf("range: %d %s", w.Code, w.Body.String())
	}
	handler := waf.NewMiddleware(waf.Config{Enabled: true, OnBlock: srv.recordWAFBlock, ClientAddr: srv.clientIP}, logger)(http.HandlerFunc(srv.handlePublic))
	r = httptest.NewRequest("GET", "https://stats.example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E&token=private-token", nil)
	r.RemoteAddr = "192.0.2.3:1234"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("WAF: %d", w.Code)
	}
	stats := snapshot()
	if stats.HTTPRequests != 3 || stats.ResponseBytes != 9 || stats.WAFBlocked != 1 || stats.Visitors != 3 || stats.ActiveVisitors != 3 {
		t.Fatalf("incorrect stats: %+v", stats)
	}
	if len(stats.Requests) != 4 || stats.Requests[3].WAFRule == "" || stats.LatencyP95MS <= 0 {
		t.Fatalf("missing log/latency: %+v", stats)
	}
	if !stats.WAFEnabled || stats.ServerVersion != "stats-test" || stats.ServerTLSMode != srv.serverTLSMode() {
		t.Fatal("missing server configuration")
	}
	// Republish retains the same observation session and counters.
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("updated index"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "app.js")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "style.css"), []byte(strings.Repeat("x", 2048)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "empty.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	archive.Reset()
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	if w := api("POST", "/_expose/v1/sites?domain=stats", "owner", archive.Bytes()); w.Code != 200 {
		t.Fatalf("republish: %d", w.Code)
	}
	if next := snapshot(); next.HTTPRequests != stats.HTTPRequests || next.Visitors != stats.Visitors || !next.Since.Equal(stats.Since) {
		t.Fatal("republish reset counters")
	}
	if next := snapshot(); next.FileCount != 3 || next.FileBytes != 2061 {
		t.Fatalf("republish did not refresh file totals: %+v", next)
	}
	// Audit-only matches must not be reported as blocked requests.
	srv.cfg.WAFAuditOnly = true
	srv.recordWAFBlock(waf.BlockEvent{Host: site.Hostname, Rule: "test-audit", Method: "GET", RequestURI: "/?token=private-token", RemoteAddr: "192.0.2.3"})
	if next := snapshot(); next.WAFBlocked != 1 || next.WAFAudited != 1 {
		t.Fatalf("incorrect audit counts: %+v", next)
	}
	// Visitor identities survive a database/server restart, without inventing
	// recent activity or counting a returning visitor twice. Run's shutdown
	// flushes the visitor queue before the store closes; do the same here.
	srv.flushSiteVisitors(ctx)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	srv = New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, logger, "stats-test")
	srv.authLimiter, srv.regLimiter = nil, nil
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	if next := snapshot(); next.Visitors != 3 || next.ActiveVisitors != 0 {
		t.Fatalf("restart lost tracked visitors or restored stale activity: %+v", next)
	}
	r = httptest.NewRequest("GET", "https://stats.example.com/", nil)
	r.RemoteAddr = "192.0.2.1:5678"
	srv.handlePublic(httptest.NewRecorder(), r)
	if next := snapshot(); next.Visitors != 3 || next.ActiveVisitors != 1 {
		t.Fatalf("returning visitor counted twice after restart: %+v", next)
	}
	stored, err := st.FindPublishedSite(ctx, site.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-time.Second)
	stored.ExpiresAt = &expired
	if err := st.ReplacePublishedSite(ctx, stored); err != nil {
		t.Fatal(err)
	}
	if w := api("GET", "/_expose/v1/sites/"+site.ID+"/stats", "owner", nil); w.Code != 404 {
		t.Fatalf("expired stats available: %d", w.Code)
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.siteStats.Load(site.ID); ok {
		t.Fatal("expiry retained site statistics")
	}
	if visitors, err := st.ListPublishedSiteVisitors(ctx, site.ID); err != nil || len(visitors) != 0 {
		t.Fatalf("expiry retained durable visitors: %d, %v", len(visitors), err)
	}
	w = api("POST", "/_expose/v1/sites?domain=stats", "owner", archive.Bytes())
	if w.Code != http.StatusCreated {
		t.Fatalf("publish after expiry: %d %s", w.Code, w.Body.String())
	}
	if next := snapshot(); next.Site.ID == site.ID || next.Visitors != 0 {
		t.Fatalf("new publication inherited expired visitors: %+v", next)
	}
	if err := st.RevokeAPIKey(ctx, owner.ID); err != nil {
		t.Fatal(err)
	}
	if w := api("GET", "/_expose/v1/sites/stats/stats", "owner", nil); w.Code != 401 {
		t.Fatalf("revoked owner can read stats: %d", w.Code)
	}
}

func TestNewVisitorsDoNotWaitForStore(t *testing.T) {
	srv := &Server{siteVisitors: make(chan sqlite.SiteVisitor, 16)}
	stats := srv.statsForSite("site")
	stats.persistVisitor = func(fp [32]byte) bool {
		return srv.queueSiteVisitor(sqlite.SiteVisitor{SiteID: "site", Fingerprint: fp})
	}
	// No writer is running: a synchronous write would block forever here.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 10 {
			stats.record(domain.PublishedSiteRequest{Time: time.Now()}, fmt.Sprintf("ip-%d", i), "agent")
			stats.record(domain.PublishedSiteRequest{Time: time.Now()}, fmt.Sprintf("ip-%d", i), "agent")
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("recording new visitors waited on persistence")
	}
	if got := len(srv.siteVisitors); got != 10 {
		t.Fatalf("queued %d visitor writes, want 10 (one per new visitor)", got)
	}
	st := &recordingVisitorStore{}
	srv.store = st
	srv.flushSiteVisitors(t.Context())
	if len(st.visitors) != 10 || len(srv.siteVisitors) != 0 {
		t.Fatalf("flush persisted %d visitors, %d left queued", len(st.visitors), len(srv.siteVisitors))
	}
}

func TestQueuedVisitorRetriesWhenQueueFull(t *testing.T) {
	srv := &Server{siteVisitors: make(chan sqlite.SiteVisitor, 1)}
	srv.siteVisitors <- sqlite.SiteVisitor{SiteID: "other"} // full
	stats := srv.statsForSite("site")
	stats.persistVisitor = func(fp [32]byte) bool {
		return srv.queueSiteVisitor(sqlite.SiteVisitor{SiteID: "site", Fingerprint: fp})
	}
	stats.record(domain.PublishedSiteRequest{Time: time.Now()}, "ip", "agent")
	if len(stats.visitorWrites) != 1 || srv.siteVisitorDrops.Load() != 1 {
		t.Fatalf("dropped visitor not kept for retry: pending=%d drops=%d", len(stats.visitorWrites), srv.siteVisitorDrops.Load())
	}
	<-srv.siteVisitors
	stats.record(domain.PublishedSiteRequest{Time: time.Now()}, "ip", "agent")
	stats.record(domain.PublishedSiteRequest{Time: time.Now()}, "ip", "agent")
	if len(stats.visitorWrites) != 0 || len(srv.siteVisitors) != 1 || stats.snapshot(time.Now()).Visitors != 1 {
		t.Fatalf("retry failed or duplicated: pending=%d queued=%d", len(stats.visitorWrites), len(srv.siteVisitors))
	}
}

type recordingVisitorStore struct {
	serverStore
	visitors []sqlite.SiteVisitor
}

func (*recordingVisitorStore) ListPublishedSiteVisitors(context.Context, string) ([][32]byte, error) {
	return nil, nil
}

func (s *recordingVisitorStore) RecordPublishedSiteVisitors(_ context.Context, v []sqlite.SiteVisitor) error {
	s.visitors = append(s.visitors, v...)
	return nil
}

func TestPublishedFileTotalsCacheUsesStorageIdentity(t *testing.T) {
	srv := &Server{cfg: config.ServerConfig{PublishDir: t.TempDir()}}
	site := domain.PublishedSite{ID: "site_test", ContentID: "site_first"}
	first := filepath.Join(srv.publishDir(), site.StorageID())
	if err := os.Mkdir(first, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(first, "index.html"), []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	count, size, err := srv.publishedFileTotals(site)
	if err != nil || count != 1 || size != 3 {
		t.Fatalf("initial totals: %d, %d, %v", count, size, err)
	}
	// Removing the index demonstrates that repeated polls do not walk the directory.
	// Production directories remain immutable until the storage identity changes.
	if err := os.Remove(filepath.Join(first, "index.html")); err != nil {
		t.Fatal(err)
	}
	count, size, err = srv.publishedFileTotals(site)
	if err != nil || count != 1 || size != 3 {
		t.Fatalf("totals were not cached: %d, %d, %v", count, size, err)
	}
	site.ContentID = "site_second"
	second := filepath.Join(srv.publishDir(), site.StorageID())
	if err := os.Mkdir(second, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"index.html": "second", "asset.txt": "new", "empty.txt": ""} {
		if err := os.WriteFile(filepath.Join(second, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	count, size, err = srv.publishedFileTotals(site)
	if err != nil || count != 3 || size != 9 {
		t.Fatalf("new storage totals: %d, %d, %v", count, size, err)
	}
}

func TestSiteStatsBoundedAndConcurrent(t *testing.T) {
	stats := (&Server{}).statsForSite("site_test")
	now := time.Now().UTC()
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Go(func() {
			for i := range 300 {
				stats.record(domain.PublishedSiteRequest{Time: now, Method: "GET", Path: "/\x1b[2J?secret=value", Status: 200, DurationMS: float64(i), ResponseBytes: 5}, string(rune(worker)), "agent")
				_ = stats.snapshot(now)
			}
		})
	}
	wg.Wait()
	snapshot := stats.snapshot(now.Add(2 * time.Minute))
	if snapshot.HTTPRequests != 1200 || snapshot.ResponseBytes != 6000 || snapshot.ActiveVisitors != 0 || snapshot.Visitors != 4 {
		t.Fatalf("concurrent counters: %+v", snapshot)
	}
	if len(snapshot.Requests) != siteRecentRequests {
		t.Fatal("request history is unbounded")
	}
	for _, entry := range snapshot.Requests {
		if strings.ContainsAny(entry.Path, "?\x1b") {
			t.Fatalf("unsafe request path %q", entry.Path)
		}
	}
	for i := range siteVisitorLimit + 1 {
		stats.record(domain.PublishedSiteRequest{Time: now}, string(rune(i+100)), "agent")
	}
	if snapshot := stats.snapshot(now); snapshot.Visitors != siteVisitorLimit || !snapshot.VisitorsCapped {
		t.Fatal("visitor storage is unbounded")
	}
}

type loadingVisitorStore struct {
	serverStore
	mu       sync.Mutex
	loads    int
	fail     bool
	visitors [][32]byte
}

func (s *loadingVisitorStore) ListPublishedSiteVisitors(context.Context, string) ([][32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.fail {
		return nil, errors.New("database busy")
	}
	return s.visitors, nil
}

func (*loadingVisitorStore) RecordPublishedSiteVisitors(context.Context, []sqlite.SiteVisitor) error {
	return nil
}

func (s *loadingVisitorStore) loadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loads
}

func TestSiteVisitorsLoadLazilyWithBackoff(t *testing.T) {
	returning := sha256.Sum256([]byte("192.0.2.1\x00agent"))
	st := &loadingVisitorStore{visitors: [][32]byte{returning, {7}}}
	srv := &Server{store: st, siteVisitors: make(chan sqlite.SiteVisitor, 16)}

	// Creating stats (startup, janitor, publish) does not read the store.
	stats := srv.statsForSite("site")
	if st.loadCount() != 0 {
		t.Fatal("visitors loaded before any request or stats poll")
	}

	// The first visit loads in the background and merges without
	// counting the returning visitor twice.
	stats.record(domain.PublishedSiteRequest{Time: time.Now()}, "192.0.2.1", "agent")
	deadline := time.Now().Add(2 * time.Second)
	for {
		stats.mu.Lock()
		loaded := stats.visitorsLoaded
		stats.mu.Unlock()
		if loaded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("visitors never loaded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := stats.snapshot(time.Now()); got.Visitors != 2 || got.ActiveVisitors != 1 {
		t.Fatalf("merged visitors = %d active %d, want 2 and 1", got.Visitors, got.ActiveVisitors)
	}
	stats.loadStoredVisitors()
	if st.loadCount() != 1 {
		t.Fatalf("loaded %d times, want 1", st.loadCount())
	}

	// A failed load backs off instead of retrying on every request.
	st.fail = true
	failing := srv.statsForSite("other")
	failing.loadStoredVisitors()
	for range 20 {
		failing.record(domain.PublishedSiteRequest{Time: time.Now()}, "198.51.100.1", "agent")
	}
	failing.loadStoredVisitors()
	if got := st.loadCount(); got != 2 {
		t.Fatalf("failed load retried %d times during backoff", got-2)
	}
	failing.mu.Lock()
	retryAt := failing.visitorsRetryAt
	failing.mu.Unlock()
	if until := time.Until(retryAt); until < siteVisitorLoadMinBackoff/2 {
		t.Fatalf("backoff too short: %s", until)
	}
}

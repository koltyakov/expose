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
	w := api("POST", "/v1/sites?domain=stats", "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}
	var site domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	snapshot := func() domain.PublishedSiteStats {
		t.Helper()
		w := api("GET", "/v1/sites/stats/stats", "owner", nil)
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
	for _, check := range []struct {
		key    string
		status int
	}{{"other", 404}, {"invalid", 401}} {
		if w := api("GET", "/v1/sites/"+site.ID+"/stats", check.key, nil); w.Code != check.status {
			t.Fatalf("stats ownership: %d", w.Code)
		}
	}
	if w := api("DELETE", "/v1/sites/"+site.ID+"/stats", "owner", nil); w.Code != 405 {
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
	if w := api("POST", "/v1/sites?domain=stats", "owner", archive.Bytes()); w.Code != 200 {
		t.Fatalf("republish: %d", w.Code)
	}
	if next := snapshot(); next.HTTPRequests != stats.HTTPRequests || !next.Since.Equal(stats.Since) {
		t.Fatal("republish reset counters")
	}
	// Audit-only matches must not be reported as blocked requests.
	srv.cfg.WAFAuditOnly = true
	srv.recordWAFBlock(waf.BlockEvent{Host: site.Hostname, Rule: "test-audit", Method: "GET", RequestURI: "/?token=private-token", RemoteAddr: "192.0.2.3"})
	if next := snapshot(); next.WAFBlocked != 1 || next.WAFAudited != 1 {
		t.Fatalf("incorrect audit counts: %+v", next)
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
	if w := api("GET", "/v1/sites/"+site.ID+"/stats", "owner", nil); w.Code != 404 {
		t.Fatalf("expired stats available: %d", w.Code)
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.siteStats.Load(site.ID); ok {
		t.Fatal("expiry retained site statistics")
	}
	if err := st.RevokeAPIKey(ctx, owner.ID); err != nil {
		t.Fatal(err)
	}
	if w := api("GET", "/v1/sites/stats/stats", "owner", nil); w.Code != 401 {
		t.Fatalf("revoked owner can read stats: %d", w.Code)
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

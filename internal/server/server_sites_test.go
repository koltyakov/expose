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
	"github.com/koltyakov/expose/internal/waf"
)

func TestRepublishReplacesWholeSite(t *testing.T) {
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}
	srv := New(cfg, st, logger, "test")
	srv.authLimiter, srv.regLimiter = nil, nil
	archive := func(files map[string]string) []byte {
		t.Helper()
		root := t.TempDir()
		for name, content := range files {
			file := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		var buf bytes.Buffer
		if err := publish.Archive(root, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	upload := func(query string, data []byte, status int) domain.PublishedSite {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/v1/sites?"+query, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer owner")
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		if w.Code != status {
			t.Fatalf("upload: %d %s, want %d", w.Code, w.Body.String(), status)
		}
		if status >= 400 {
			return domain.PublishedSite{}
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
	assertBody := func(host, path, body string) {
		t.Helper()
		w := httptest.NewRecorder()
		srv.handlePublic(w, httptest.NewRequest(http.MethodGet, "https://"+host+path, nil))
		if w.Code != 200 || w.Body.String() != body {
			t.Fatalf("serve %s: %d %q", path, w.Code, w.Body.String())
		}
	}
	source := strings.Repeat("b", 64)
	first := upload("source_id="+source+"&ttl=1h", archive(map[string]string{"index.html": "old", "assets/obsolete.js": "obsolete"}), 201)
	// Failed validation leaves the current content and metadata intact.
	upload("source_id="+source, []byte("invalid archive"), 400)
	// The default checks extracted bytes even when the upload compresses well.
	upload("source_id="+source, archive(map[string]string{"index.html": strings.Repeat("x", int(config.DefaultPublishMaxBytes)+1)}), http.StatusRequestEntityTooLarge)
	srv.cfg.PublishMaxBytes = 5
	// Each file fits on its own, but their combined size exceeds the limit.
	upload("source_id="+source, archive(map[string]string{"index.html": "new", "asset.js": "123"}), http.StatusRequestEntityTooLarge)
	entries, err := os.ReadDir(srv.publishDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("rejected upload left staging files: %v, %v", entries, err)
	}
	assertBody(first.Hostname, "/", "old")
	assertBody(first.Hostname, "/assets/obsolete.js", "obsolete")
	srv.cfg.PublishMaxBytes = 12 // Exactly the combined size of the next upload.
	second := upload("source_id="+source+"&ttl=48h", archive(map[string]string{"index.html": "new", "assets/new.js": "new asset"}), 200)
	if second.ID != first.ID || second.Hostname != first.Hostname || !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatal("republish changed site identity")
	}
	if second.StorageID() == first.StorageID() {
		t.Fatal("republish reused the active directory")
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), first.StorageID())); !os.IsNotExist(err) {
		t.Fatalf("old directory remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), second.StorageID(), "assets/obsolete.js")); !os.IsNotExist(err) {
		t.Fatalf("removed asset survived replacement: %v", err)
	}
	if second.ExpiresAt == nil || !second.ExpiresAt.After(*first.ExpiresAt) {
		t.Fatal("republish did not reset TTL")
	}
	assertBody(second.Hostname, "/", "new")
	assertBody(second.Hostname, "/assets/new.js", "new asset")
	label := strings.TrimSuffix(first.Hostname, ".example.com")
	third := upload("domain="+label, archive(map[string]string{"index.html": "by domain"}), 200)
	if third.ID != first.ID || third.SourceID != source {
		t.Fatal("domain replacement lost site/folder identity")
	}
	// A restart loads the committed directory pointer, including after replacement.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	srv = New(cfg, st, logger, "test")
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	assertBody(first.Hostname, "/", "by domain")
	r := httptest.NewRequest(http.MethodDelete, "/v1/sites/"+label, nil)
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	srv.handleSites(w, r)
	if w.Code != 204 {
		t.Fatalf("delete replacement: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), third.StorageID())); !os.IsNotExist(err) {
		t.Fatalf("replacement files remain after deletion: %v", err)
	}
}

func TestPublishedSiteLifecycle(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "expose.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	key, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIKey(ctx, "other", auth.HashAPIKey("other", "")); err != nil {
		t.Fatal(err)
	}
	cfg := config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(cfg, st, logger, "test")
	// Keep this lifecycle test independent of authentication and registration bursts.
	srv.authLimiter, srv.regLimiter = nil, nil
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("SPA root"), 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.handleSites(w, r)
		return w
	}
	sourceID := strings.Repeat("a", 64)
	w := request("POST", "/v1/sites?source_id="+sourceID, "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	var site domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	if site.Hostname == "" || site.ExpiresAt == nil || site.ExpiresAt.Sub(site.CreatedAt) != 7*24*time.Hour {
		t.Fatalf("bad site: %+v", site)
	}
	stored, err := st.FindPublishedSite(ctx, site.Hostname)
	if err != nil || stored.SourceID != sourceID {
		t.Fatalf("folder identifier not persisted: %+v, %v", stored, err)
	}
	for _, ttl := range []string{"-1h", "0", "invalid"} {
		w = request("POST", "/v1/sites?ttl="+ttl, "owner", archive.Bytes())
		if w.Code != 400 {
			t.Fatalf("invalid ttl %q: %d", ttl, w.Code)
		}
	}
	w = request("POST", "/v1/sites?ttl=1h", "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("TTL upload: %d %s", w.Code, w.Body.String())
	}
	var timed domain.PublishedSite
	if err := json.Unmarshal(w.Body.Bytes(), &timed); err != nil {
		t.Fatal(err)
	}
	if timed.ExpiresAt == nil || timed.ExpiresAt.Sub(timed.CreatedAt) != time.Hour {
		t.Fatalf("TTL not stored: %+v", timed)
	}
	w = request("POST", "/v1/sites", "invalid", archive.Bytes())
	if w.Code != 401 {
		t.Fatalf("unauthenticated upload: %d", w.Code)
	}
	w = request("POST", "/v1/sites", "owner", []byte("not an archive"))
	if w.Code != 400 {
		t.Fatalf("malformed archive: %d", w.Code)
	}
	entries, err := os.ReadDir(srv.publishDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("failed uploads left files: %v", entries)
	}
	if err := srv.authorizeACMEHost(ctx, site.Hostname); err != nil {
		t.Fatalf("ACME: %v", err)
	}
	w = request("GET", "/v1/sites", "other", nil)
	if w.Code != 200 || w.Body.String() != "[]\n" {
		t.Fatalf("other owner's list: %d %s", w.Code, w.Body.String())
	}
	subdomain := strings.TrimSuffix(site.Hostname, ".example.com")
	for _, method := range []string{"GET", "DELETE"} {
		w = request(method, "/v1/sites/"+subdomain, "other", nil)
		if w.Code != 404 {
			t.Fatalf("ownership %s: %d", method, w.Code)
		}
	}
	w = request("POST", "/v1/sites?domain=docs", "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("named upload: %d %s", w.Code, w.Body.String())
	}
	w = request("POST", "/v1/sites?domain=docs", "other", archive.Bytes())
	if w.Code != 409 {
		t.Fatalf("conflict: %d", w.Code)
	}
	if strings.TrimSpace(w.Body.String()) != "hostname already in use" {
		t.Fatalf("disclosed another owner's publication: %s", w.Body.String())
	}
	_, live, err := st.AllocateDomainAndTunnel(ctx, key.ID, "temporary", "live", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTunnelConnected(ctx, live.ID); err != nil {
		t.Fatal(err)
	}
	w = request("POST", "/v1/sites?domain=live", "owner", archive.Bytes())
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "expose http") || !strings.Contains(w.Body.String(), "Ctrl+C") {
		t.Fatalf("missing tunnel conflict guidance: %d %s", w.Code, w.Body.String())
	}
	w = request("PATCH", "/v1/sites/"+subdomain+"?domain=app", "owner", nil)
	if w.Code != 405 {
		t.Fatalf("unsupported method: %d %s", w.Code, w.Body.String())
	}
	w = request("DELETE", "/v1/sites/"+subdomain, "owner", nil)
	if w.Code != 204 {
		t.Fatalf("delete hashed subdomain: %d", w.Code)
	}
	w = request("POST", "/v1/sites?domain=app", "owner", archive.Bytes())
	if w.Code != 201 {
		t.Fatalf("publish app: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &site); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/v1/sites/app", "owner", nil)
	if w.Code != 200 {
		t.Fatalf("published subdomain not found: %d", w.Code)
	}
	if _, _, err := st.AllocateDomainAndTunnelWithClientMeta(ctx, key.ID, "permanent", "app", "example.com", ""); err == nil {
		t.Fatal("tunnel claimed published hostname")
	}
	// Reopen both database and server to prove hosting does not rely on a client session.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	srv = New(cfg, st, logger, "test")
	srv.authLimiter, srv.regLimiter = nil, nil
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	srv.handlePublic(w, httptest.NewRequest("GET", "https://app.example.com/client/route", nil))
	if w.Code != 200 || w.Body.String() != "SPA root" {
		t.Fatalf("restarted serving: %d %s", w.Code, w.Body.String())
	}
	handler := waf.NewMiddleware(waf.Config{Enabled: true, BodyInspectLimit: 16384}, logger)(http.HandlerFunc(srv.handlePublic))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://app.example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil))
	if w.Code != 403 {
		t.Fatalf("WAF: %d %s", w.Code, w.Body.String())
	}
	w = request("DELETE", "/v1/sites/app", "owner", nil)
	if w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), site.ID)); !os.IsNotExist(err) {
		t.Fatalf("files remain: %v", err)
	}
	if _, _, err := st.AllocateDomainAndTunnelWithClientMeta(ctx, key.ID, "permanent", "app", "example.com", ""); err != nil {
		t.Fatalf("hostname not released: %v", err)
	}
	// An expired site cannot serve or obtain a certificate even before cleanup runs.
	expires := time.Now().Add(-time.Second)
	expired := domain.PublishedSite{ID: "site_expired", APIKeyID: key.ID, Hostname: "expired.example.com", CreatedAt: expires, ExpiresAt: &expires}
	if err := st.CreatePublishedSite(ctx, expired); err != nil {
		t.Fatal(err)
	}
	srv.siteHosts.Store(expired.Hostname, struct{}{})
	if err := os.MkdirAll(filepath.Join(srv.publishDir(), expired.ID), 0700); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	if srv.servePublishedSite(w, httptest.NewRequest("GET", "https://expired.example.com/", nil), expired.Hostname) {
		t.Fatal("expired site served")
	}
	if err := srv.authorizeACMEHost(ctx, expired.Hostname); err == nil {
		t.Fatal("expired site authorized ACME")
	}
	if err := srv.cleanupPublishedSites(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(srv.publishDir(), expired.ID)); !os.IsNotExist(err) {
		t.Fatalf("expiry left files: %v", err)
	}
	if err := st.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	if srv.servePublishedSite(w, httptest.NewRequest("GET", "https://docs.example.com/", nil), "docs.example.com") {
		t.Fatal("revoked key site served")
	}
}

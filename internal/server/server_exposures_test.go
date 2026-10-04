package server

import (
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
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestExposureListing(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "exposures.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	keys := map[string]string{}
	for _, name := range []string{"owner", "other", "empty"} {
		key, err := st.CreateAPIKey(ctx, name, auth.HashAPIKey(name, ""))
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key.ID
	}
	allocate := func(key, mode, name string) domain.Tunnel {
		t.Helper()
		_, tunnel, err := st.AllocateDomainAndTunnelWithClientMeta(ctx, keys[key], mode, name, "example.com", "private-client-meta")
		if err != nil {
			t.Fatal(err)
		}
		return tunnel
	}
	old := allocate("owner", "permanent", "app")
	if err := st.SetTunnelConnected(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetTunnelDisconnected(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	latest := allocate("owner", "permanent", "app")
	if err := st.SetTunnelAccessCredentials(ctx, latest.ID, "private-user", "basic", "private-password-hash"); err != nil {
		t.Fatal(err)
	}
	temporary := allocate("owner", "temporary", "temp")
	if err := st.SetTunnelConnected(ctx, temporary.ID); err != nil {
		t.Fatal(err)
	}
	allocate("other", "permanent", "other-tunnel")
	for _, item := range []struct {
		name string
		key  string
		ttl  time.Duration
	}{
		{"docs", "owner", time.Hour},
		{"expired", "owner", -time.Hour},
		{"other-site", "other", time.Hour},
	} {
		expires := time.Now().UTC().Add(item.ttl)
		if err := st.CreatePublishedSite(ctx, domain.PublishedSite{
			ID: item.name, APIKeyID: keys[item.key], Hostname: item.name + ".example.com",
			CreatedAt: time.Now().UTC(), ExpiresAt: &expires, SourceID: "private-source", ContentID: "private-content",
		}); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com"}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.authLimiter = nil
	handler := srv.httpHandler()
	request := func(method, key, authority string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "https://"+authority+serviceapi.Exposures, nil)
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	list := func(authority string) []domain.Exposure {
		t.Helper()
		w := request(http.MethodGet, "owner", authority)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("listing: %d %s, headers %v", w.Code, w.Body.String(), w.Header())
		}
		for _, secret := range []string{"private-", "api_key", "password", "client_meta", "other-tunnel", "other-site"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatalf("listing leaked %q: %s", secret, w.Body.String())
			}
		}
		var got []domain.Exposure
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("expected four owned hostnames, got %+v", got)
		}
		return got
	}
	got := list("example.com:10443")
	if got[0].ID != latest.ID || got[0].Status != "disconnected" || got[0].Temporary || got[0].URL != "https://app.example.com:10443" {
		t.Fatalf("latest named registration: %+v", got[0])
	}
	if got[1].Type != domain.ExposureTypeSite || got[1].Status != "active" || got[1].ExpiresAt == nil || got[2].Status != "expired" {
		t.Fatalf("published sites: %+v", got[1:3])
	}
	if got[3].ID != temporary.ID || got[3].Status != "connected" || !got[3].Temporary {
		t.Fatalf("temporary tunnel: %+v", got[3])
	}
	// A resumed older session takes precedence over a newer unconnected registration.
	if err := st.SetTunnelConnected(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	got = list("example.com:443")
	if got[0].ID != old.ID || got[0].Status != "connected" || got[0].URL != "https://app.example.com" {
		t.Fatalf("resumed tunnel: %+v", got[0])
	}
	if _, _, err := st.CloseTemporaryTunnel(ctx, temporary.ID); err != nil {
		t.Fatal(err)
	}
	if got := list("example.com"); got[3].Status != "closed" {
		t.Fatalf("closed tunnel reservation: %+v", got[3])
	}
	for _, key := range []string{"", "invalid"} {
		if w := request(http.MethodGet, key, "example.com"); w.Code != http.StatusUnauthorized {
			t.Fatalf("key %q: status %d", key, w.Code)
		}
	}
	if w := request(http.MethodPost, "owner", "example.com"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("POST listing: %d, headers %v", w.Code, w.Header())
	}
	if w := request(http.MethodGet, "empty", "example.com"); w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty listing: %d %s", w.Code, w.Body.String())
	}
	if got, err := st.ListExposures(ctx, ""); err != nil || len(got) != 0 {
		t.Fatalf("empty owner must not list other keys: %+v, %v", got, err)
	}
	if err := st.RevokeAPIKey(ctx, keys["owner"]); err != nil {
		t.Fatal(err)
	}
	if w := request(http.MethodGet, "owner", "example.com"); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d %s", w.Code, w.Body.String())
	}
}

func TestExposureRetention(t *testing.T) {
	ctx := context.Background()
	srv, st := newIncrementalTestServer(t)
	keyID, err := st.ResolveAPIKeyID(ctx, auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	stale := domain.PublishedSite{ID: "stale", APIKeyID: keyID, Hostname: "stale.example.com", CreatedAt: now.Add(-8 * 24 * time.Hour)}
	if err := st.CreatePublishedSite(ctx, stale); err != nil {
		t.Fatal(err)
	}
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)
	for _, site := range []domain.PublishedSite{
		{ID: "unexpired", APIKeyID: keyID, Hostname: "unexpired.example.com", CreatedAt: stale.CreatedAt, ExpiresAt: &future},
		{ID: "expired", APIKeyID: keyID, Hostname: "expired.example.com", CreatedAt: stale.CreatedAt, ExpiresAt: &past},
		{ID: "seen", APIKeyID: keyID, Hostname: "seen.example.com", CreatedAt: stale.CreatedAt, ExpiresAt: &past},
	} {
		if err := st.CreatePublishedSite(ctx, site); err != nil {
			t.Fatal(err)
		}
	}
	// Last seen, not creation time, controls retention for inactive entries.
	if err := st.TouchDomain(ctx, "seen"); err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := st.AllocateDomainAndTunnel(ctx, keyID, "permanent", "live", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query  string
		status int
		count  int
	}{
		{"", http.StatusOK, 4},
		{"?retention=0", http.StatusOK, 5},
		{"?retention=216h", http.StatusOK, 5},
		{"?retention=1ns", http.StatusOK, 3}, // Connected tunnels and active sites survive any cutoff.
		{"?retention=-1h", http.StatusBadRequest, 0},
		{"?retention=invalid", http.StatusBadRequest, 0},
		{"?retention=", http.StatusBadRequest, 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, serviceapi.Exposures+tc.query, nil)
			r.Header.Set("Authorization", "Bearer owner")
			w := httptest.NewRecorder()
			srv.httpHandler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.status != http.StatusOK {
				return
			}
			var entries []domain.Exposure
			if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil || len(entries) != tc.count {
				t.Fatalf("listing: %s, error %v", w.Body.String(), err)
			}
			listed := make(map[string]bool, len(entries))
			for _, entry := range entries {
				listed[entry.ID] = true
			}
			for _, id := range []string{tunnel.ID, stale.ID, "unexpired"} {
				if !listed[id] {
					t.Fatalf("active exposure %q hidden: %+v", id, entries)
				}
			}
			if tc.query == "" && (!listed["seen"] || listed["expired"]) {
				t.Fatalf("inactive retention must use last seen: %+v", entries)
			}
		})
	}
	// Visiting an active site still records activity through the existing touch queue.
	root := filepath.Join(srv.publishDir(), stale.ID)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("site"), 0600); err != nil {
		t.Fatal(err)
	}
	srv.siteHosts.Store(stale.Hostname, stale)
	w := httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://"+stale.Hostname+"/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("active site is served: %d %s", w.Code, w.Body.String())
	}
	select {
	case id := <-srv.domainTouches:
		if id != stale.ID {
			t.Fatalf("touched %q, want %q", id, stale.ID)
		}
		if err := st.TouchDomain(ctx, id); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("site visit did not record activity")
	}
	r := httptest.NewRequest(http.MethodGet, serviceapi.Exposures, nil)
	r.Header.Set("Authorization", "Bearer owner")
	w = httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), stale.Hostname) {
		t.Fatalf("visited site missing from listing: %d %s", w.Code, w.Body.String())
	}
}

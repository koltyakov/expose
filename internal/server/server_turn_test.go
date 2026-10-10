package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/turnrelay"
)

func TestTURNCredentialsAPI(t *testing.T) {
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "turn.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	key, err := st.CreateAPIKey(context.Background(), "relay-app", auth.HashAPIKey("test-key", "pepper"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.ServerConfig{BaseDomain: "example.com", APIKeyPepper: "pepper", TURN: config.TURNConfig{
		Enabled: true, ListenUDP: "127.0.0.1:0", PublicIP: "127.0.0.1", Host: "relay.example.com",
		Realm: "example.com", Secret: strings.Repeat("s", 32), RelayAddress: "127.0.0.1",
		MinPort: 49160, MaxPort: 49200, MaxAllocations: 8, MaxConnections: 8, CredentialTTL: time.Hour,
	}}
	s := New(cfg, st, logger, "test")
	r, err := turnrelay.Start(cfg.TURN, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	s.turn = r
	handler := s.httpHandler()
	request := func(method, key string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "https://example.com"+serviceapi.TURNCredentials, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("credential API response can be cached")
		}
		return rr
	}
	for _, key := range []string{"", "incorrect"} {
		if rr := request(http.MethodPost, key); rr.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated request: %d", rr.Code)
		}
	}
	if rr := request(http.MethodGet, "test-key"); rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "POST" {
		t.Fatalf("incorrect method response: %d", rr.Code)
	}
	rr := request(http.MethodPost, "test-key")
	if rr.Code != http.StatusOK {
		t.Fatalf("credential request: %d %s", rr.Code, rr.Body.String())
	}
	var creds turnrelay.Credentials
	if err := json.Unmarshal(rr.Body.Bytes(), &creds); err != nil {
		t.Fatal(err)
	}
	if len(creds.ICEServers) != 1 || !strings.HasSuffix(creds.ICEServers[0].Username, ":"+key.ID) || !strings.HasPrefix(creds.ICEServers[0].URLs[0], "turn:relay.example.com:") {
		t.Fatalf("invalid credentials: %+v", creds)
	}
	if strings.Contains(rr.Body.String(), cfg.TURN.Secret) {
		t.Fatal("shared secret exposed by API")
	}
	s.turn = nil
	if rr := request(http.MethodPost, "test-key"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled relay response: %d", rr.Code)
	}
	s.turn = r
	// Exhaust the per-key bucket without exhausting the per-IP bucket.
	s.regLimiter = newConfiguredRateLimiter(0.001, 1, time.Minute)
	if rr := request(http.MethodPost, "test-key"); rr.Code != http.StatusOK {
		t.Fatalf("first rate-limited credential request: %d", rr.Code)
	}
	if rr := request(http.MethodPost, "test-key"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("credential issuance limit not enforced: %d", rr.Code)
	}
	if err := st.RevokeAPIKey(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	if rr := request(http.MethodPost, "test-key"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked API key accepted: %d", rr.Code)
	}
}

func TestAuthorizeTURNACMEHost(t *testing.T) {
	s := &Server{cfg: config.ServerConfig{BaseDomain: "example.com", TURN: config.TURNConfig{Enabled: true, ListenTLS: ":5349", Host: "relay.example.com"}}}
	if err := s.authorizeACMEHost(context.Background(), "relay.example.com"); err != nil {
		t.Fatalf("configured TURN TLS hostname was not authorized: %v", err)
	}
}

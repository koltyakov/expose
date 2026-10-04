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
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestRegisterNewerClientTriggersUpdateCheck(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name          string
		serverVersion string
		clientVersion string
		unauthorized  bool
		invalid       bool
		wantCheck     bool
	}{
		{name: "newer", serverVersion: "1.2.9", clientVersion: "1.2.10", wantCheck: true},
		{name: "client prefix", serverVersion: "1.2.9", clientVersion: "v1.2.10", wantCheck: true},
		{name: "server prefix", serverVersion: "v1.2.9", clientVersion: "1.2.10", wantCheck: true},
		{name: "equal", serverVersion: "v1.2.9", clientVersion: "1.2.9"},
		{name: "older", serverVersion: "1.2.10", clientVersion: "1.2.9"},
		{name: "missing", serverVersion: "1.2.9"},
		{name: "invalid version", serverVersion: "1.2.9", clientVersion: "unknown"},
		{name: "dev client", serverVersion: "1.2.9", clientVersion: "dev"},
		{name: "dev suffix", serverVersion: "1.2.9", clientVersion: "1.3.0-dev"},
		{name: "dev server", serverVersion: "dev", clientVersion: "1.3.0", wantCheck: true},
		{name: "versioned dev server", serverVersion: "v1.2.9-dev", clientVersion: "1.3.0", wantCheck: true},
		{name: "dev server same base", serverVersion: "v1.3.0-dev", clientVersion: "1.3.0"},
		{name: "dev server ahead", serverVersion: "v1.3.1-dev", clientVersion: "1.3.0"},
		{name: "unauthorized", serverVersion: "1.2.9", clientVersion: "1.3.0", unauthorized: true},
		{name: "invalid registration", serverVersion: "1.2.9", clientVersion: "1.3.0", invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store, err := sqlite.Open(filepath.Join(t.TempDir(), "updates.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()
			const rawKey = "update-secret"
			if _, err := store.CreateAPIKeyWithLimit(context.Background(), "updates", auth.HashAPIKey(rawKey, ""), -1); err != nil {
				t.Fatal(err)
			}
			srv := New(config.ServerConfig{
				BaseDomain:      "example.com",
				ConnectTokenTTL: time.Minute,
			}, store, slog.New(slog.NewTextHandler(io.Discard, nil)), tt.serverVersion)
			body := domain.RegisterRequest{Mode: "temporary", ClientVersion: tt.clientVersion}
			if tt.invalid {
				body.Mode = "invalid"
			}
			data, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			register := func(resumeID string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, "https://example.com/_expose/v1/tunnels/register", strings.NewReader(string(data)))
				if !tt.unauthorized {
					req.Header.Set("Authorization", "Bearer "+rawKey)
				}
				req.Header.Set(domain.RegisterResumeTunnelHeader, resumeID)
				rr := httptest.NewRecorder()
				srv.handleRegister(rr, req)
				return rr
			}
			rr := register("")
			wantStatus := http.StatusOK
			if tt.unauthorized {
				wantStatus = http.StatusUnauthorized
			} else if tt.invalid {
				wantStatus = http.StatusBadRequest
			}
			if rr.Code != wantStatus {
				t.Fatalf("register = %d, want %d: %s", rr.Code, wantStatus, rr.Body.String())
			}
			select {
			case <-srv.UpdateChecks():
				if !tt.wantCheck {
					t.Fatal("unexpected update check")
				}
			default:
				if tt.wantCheck {
					t.Fatal("newer client did not trigger an update check")
				}
			}
			if tt.wantCheck {
				var resp domain.RegisterResponse
				if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if rr := register(resp.TunnelID); rr.Code != http.StatusOK {
					t.Fatalf("repeat register = %d: %s", rr.Code, rr.Body.String())
				}
				select {
				case <-srv.UpdateChecks():
					t.Fatal("reconnect triggered another check during cooldown")
				default:
				}
			}
		})
	}
}

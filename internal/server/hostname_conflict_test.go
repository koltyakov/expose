package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestHostnameConflictDescribesOnlyOwnedExposure(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "conflicts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key, err := st.CreateAPIKey(ctx, "owner", "hash")
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com"}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if err := st.CreatePublishedSite(ctx, domain.PublishedSite{ID: "site_test", APIKeyID: key.ID, Hostname: "docs.example.com", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := st.AllocateDomainAndTunnel(ctx, key.ID, "temporary", "live", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, key, want string
	}{
		{"docs.example.com", key.ID, "expose pub delete --domain=docs"},
		{"live.example.com", key.ID, "expose http or expose static"},
		{"docs.example.com", "other", "hostname already in use"},
		{"live.example.com", "other", "hostname already in use"},
	} {
		t.Run(tc.host+"/"+tc.key, func(t *testing.T) {
			err := srv.hostnameConflict(ctx, tc.key, tc.host)
			if !errors.Is(err, sqlite.ErrHostnameInUse) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected conflict: %v", err)
			}
			if tc.key == "other" && err.Error() != tc.want {
				t.Fatalf("disclosed another owner's exposure: %v", err)
			}
		})
	}
	for _, label := range []string{"docs", "live"} {
		_, _, err := srv.allocateRegisterRoute(ctx, key.ID, preparedRegisterRequest{request: domain.RegisterRequest{Mode: "temporary", Subdomain: label}})
		w := httptest.NewRecorder()
		srv.writeRegisterAllocateError(w, key.ID, err)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "expose ") || !strings.Contains(w.Body.String(), "hostname_in_use") {
			t.Fatalf("registration lost conflict details: %d %s", w.Code, w.Body.String())
		}
	}
}

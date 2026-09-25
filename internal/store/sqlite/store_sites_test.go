package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestPublishReclaimsStoppedTunnelHostname(t *testing.T) {
	for _, mode := range []string{"temporary", "permanent"} {
		for _, scenario := range []string{"stopped", "connected", "other-owner", "rollback"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				store, err := openTestStore(t)
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				ctx := context.Background()
				key, err := store.CreateAPIKey(ctx, "owner", "owner-hash")
				if err != nil {
					t.Fatal(err)
				}
				d, tunnel, err := store.AllocateDomainAndTunnel(ctx, key.ID, mode, "docs", "example.com")
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
					t.Fatal(err)
				}
				if scenario != "connected" {
					if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := store.db.ExecContext(ctx, `INSERT INTO connect_tokens(token, tunnel_id, expires_at) VALUES('old-token', ?, ?)`, tunnel.ID, time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				site := domain.PublishedSite{ID: "site_test", APIKeyID: key.ID, Hostname: d.Hostname, CreatedAt: time.Now().UTC()}
				if scenario == "other-owner" {
					site.APIKeyID = "someone-else"
				}
				if scenario == "rollback" {
					existing := site
					existing.Hostname = "other.example.com"
					if err := store.CreatePublishedSite(ctx, existing); err != nil {
						t.Fatal(err)
					}
				}
				err = store.CreatePublishedSite(ctx, site)
				if scenario != "stopped" {
					if !errors.Is(err, ErrHostnameInUse) {
						t.Fatalf("expected hostname conflict, got %v", err)
					}
					var count int
					if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connect_tokens WHERE tunnel_id = ?`, tunnel.ID).Scan(&count); err != nil || count != 1 {
						t.Fatalf("existing token lost: count=%d, err=%v", count, err)
					}
					if _, err := store.FindRouteByHost(ctx, d.Hostname); err != nil {
						t.Fatalf("existing tunnel lost: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got, err := store.FindPublishedSite(ctx, d.Hostname); err != nil || got.ID != site.ID {
					t.Fatalf("publication missing: %+v, %v", got, err)
				}
				if _, _, err := store.ResumeTunnelSession(ctx, tunnel.ID, key.ID, ""); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("old tunnel could resume: %v", err)
				}
				if err := store.TrySetTunnelConnected(ctx, tunnel.ID); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("old tunnel could connect: %v", err)
				}
				var count int
				if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connect_tokens WHERE tunnel_id = ?`, tunnel.ID).Scan(&count); err != nil || count != 0 {
					t.Fatalf("old tokens remain: count=%d, err=%v", count, err)
				}
			})
		}
	}
}

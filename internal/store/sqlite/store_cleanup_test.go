package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestTunnelExpiry(t *testing.T) {
	for _, mode := range []string{"temporary", "permanent"} {
		for _, activity := range []string{"stale", "connected", "disconnected", "registered", "traffic"} {
			t.Run(mode+"/"+activity, func(t *testing.T) {
				st, err := openTestStore(t)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = st.Close() }()
				ctx := context.Background()
				key, err := st.CreateAPIKey(ctx, "owner", "hash")
				if err != nil {
					t.Fatal(err)
				}
				d, tunnel, err := st.AllocateDomainAndTunnel(ctx, key.ID, mode, "app", "example.com")
				if err != nil {
					t.Fatal(err)
				}
				old := time.Now().UTC().Add(-48 * time.Hour)
				if _, err := st.db.ExecContext(ctx, `UPDATE domains SET created_at = ?, last_seen_at = ? WHERE id = ?`, old, old, d.ID); err != nil {
					t.Fatal(err)
				}
				switch activity {
				case "connected", "disconnected":
					if err := st.SetTunnelConnected(ctx, tunnel.ID); err != nil {
						t.Fatal(err)
					}
					if activity == "connected" {
						// A connected session survives even without recent traffic.
						if _, err := st.db.ExecContext(ctx, `UPDATE domains SET last_seen_at = ? WHERE id = ?`, old, d.ID); err != nil {
							t.Fatal(err)
						}
					} else {
						if _, err := st.db.ExecContext(ctx, `UPDATE tunnels SET connected_at = ? WHERE id = ?`, old, tunnel.ID); err != nil {
							t.Fatal(err)
						}
						if _, err := st.db.ExecContext(ctx, `UPDATE domains SET last_seen_at = ? WHERE id = ?`, old, d.ID); err != nil {
							t.Fatal(err)
						}
						if err := st.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
							t.Fatal(err)
						}
					}
				case "registered":
					if _, _, err := st.AllocateDomainAndTunnel(ctx, key.ID, mode, "app", "example.com"); err != nil {
						t.Fatal(err)
					}
				case "traffic":
					if err := st.TouchDomain(ctx, d.ID); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := st.CreateConnectToken(ctx, tunnel.ID, time.Minute); err != nil {
					t.Fatal(err)
				}
				site := domain.PublishedSite{ID: "site", APIKeyID: key.ID, Hostname: "docs.example.com", CreatedAt: old}
				if err := st.CreatePublishedSite(ctx, site); err != nil {
					t.Fatal(err)
				}
				purged, err := st.PurgeInactiveTunnelDomains(ctx, time.Now().Add(-24*time.Hour), 1)
				if err != nil {
					t.Fatal(err)
				}
				if activity != "stale" {
					if len(purged) != 0 {
						t.Fatalf("active reservation purged: %+v", purged)
					}
					return
				}
				if len(purged) != 1 || purged[0].ID != d.ID {
					t.Fatalf("stale reservation not purged: %+v", purged)
				}
				if _, err := st.FindRouteByHost(ctx, d.Hostname); !errors.Is(err, sql.ErrNoRows) {
					t.Fatalf("expired route remains: %v", err)
				}
				for _, table := range []string{"tunnels", "connect_tokens"} {
					var count int
					if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
						t.Fatalf("%s not cleaned: %d, %v", table, count, err)
					}
				}
				if _, err := st.FindPublishedSite(ctx, site.Hostname); err != nil {
					t.Fatalf("publication must not expire with tunnels: %v", err)
				}
				other, err := st.CreateAPIKey(ctx, "other", "other-hash")
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := st.AllocateDomainAndTunnel(ctx, other.ID, mode, "app", "example.com"); err != nil {
					t.Fatalf("expired hostname not released: %v", err)
				}
			})
		}
	}
}

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestTouchDomainsCoalescesAndThrottles(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := t.Context()
	key, err := st.CreateAPIKey(ctx, "owner", "hash")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := range 8 {
		d, _, err := st.AllocateDomainAndTunnel(ctx, key.ID, "permanent", fmt.Sprintf("site%d", i), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID)
	}
	var first time.Time
	for range 2 {
		if err := st.TouchDomains(ctx, ids); err != nil {
			t.Fatal(err)
		}
		var count, timestamps int
		if err := st.db.QueryRow(`SELECT count(*), count(distinct last_seen_at) FROM domains`).Scan(&count, &timestamps); err != nil || count != len(ids) || timestamps != 1 {
			t.Fatalf("batch timestamps: domains=%d distinct=%d err=%v", count, timestamps, err)
		}
		// A repeated visit within the minimum interval must not update SQLite.
		var seen time.Time
		if err := st.db.QueryRow(`SELECT last_seen_at FROM domains LIMIT 1`).Scan(&seen); err != nil {
			t.Fatal(err)
		}
		if !first.IsZero() && !seen.Equal(first) {
			t.Fatalf("repeated touch changed timestamp from %v to %v", first, seen)
		}
		first = seen
	}
}

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

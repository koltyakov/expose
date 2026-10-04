package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestExposureLastActivity(t *testing.T) {
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
	d, tunnel, err := st.AllocateDomainAndTunnel(ctx, key.ID, "permanent", "app", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	recent := time.Now().UTC().Add(-time.Hour)
	for _, tc := range []struct {
		name         string
		seen         any
		connected    any
		disconnected any
		want         time.Time
	}{
		{"creation fallback", nil, nil, nil, old},
		{"stale", old, old, old, old},
		{"traffic or registration", recent, old, old, recent},
		{"reconnected", old, recent, nil, recent},
		{"disconnected recently", old, old, recent, recent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.db.ExecContext(ctx, `UPDATE domains SET created_at = ?, last_seen_at = ? WHERE id = ?`, old, tc.seen, d.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.db.ExecContext(ctx, `UPDATE tunnels SET connected_at = ?, disconnected_at = ? WHERE id = ?`, tc.connected, tc.disconnected, tunnel.ID); err != nil {
				t.Fatal(err)
			}
			got, err := st.ListExposures(ctx, key.ID)
			if err != nil || len(got) != 1 || !got[0].LastActiveAt.Equal(tc.want) {
				t.Fatalf("last activity: %+v, error %v, want %v", got, err, tc.want)
			}
		})
	}

	site := domain.PublishedSite{ID: "site", APIKeyID: key.ID, Hostname: "docs.example.com", CreatedAt: old}
	if err := st.CreatePublishedSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC()
	if err := st.ReplacePublishedSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	got, err := st.ListExposures(ctx, key.ID)
	if err != nil || len(got) != 2 || got[1].LastActiveAt.Before(before) || !got[1].CreatedAt.Equal(old) {
		t.Fatalf("republishing must renew activity and preserve creation time: %+v, %v", got, err)
	}
}

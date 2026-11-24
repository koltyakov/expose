package sqlite

import (
	"context"
	"testing"
	"time"
)

func TestPruneClosedTunnelsKeepsLiveHistory(t *testing.T) {
	st, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO domains(id, api_key_id, type, hostname, status, created_at, last_seen_at) VALUES('d1', 'k1', 'permanent_subdomain', 'app.example.com', 'active', ?, ?)`, old, now)
	tunnel := func(id, state string, connected, disconnected time.Time) {
		exec(`INSERT INTO tunnels(id, api_key_id, domain_id, state, is_temporary, connected_at, disconnected_at) VALUES(?, 'k1', 'd1', ?, 0, ?, ?)`, id, state, connected, disconnected)
	}
	tunnel("t-old-1", "closed", old.Add(-3*time.Hour), old.Add(-2*time.Hour))
	tunnel("t-old-2", "closed", old.Add(-90*time.Minute), old.Add(-time.Hour))
	tunnel("t-token", "closed", old.Add(-50*time.Minute), old.Add(-40*time.Minute))
	tunnel("t-recent", "closed", now.Add(-20*time.Minute), now.Add(-10*time.Minute))
	tunnel("t-newest", "closed", now.Add(-5*time.Minute), now.Add(-time.Minute))
	exec(`INSERT INTO connect_tokens(token, tunnel_id, expires_at) VALUES('live', 't-token', ?)`, now.Add(time.Hour))
	exec(`INSERT INTO connect_tokens(token, tunnel_id, expires_at, used_at) VALUES('spent', 't-old-1', ?, ?)`, old, old)

	cutoff := now.Add(-24 * time.Hour)
	n, err := st.PruneClosedTunnels(ctx, cutoff, now, 1)
	if err != nil || n != 1 {
		t.Fatalf("first batch pruned %d, %v; want 1", n, err)
	}
	n, err = st.PruneClosedTunnels(ctx, cutoff, now, 100)
	if err != nil || n != 1 {
		t.Fatalf("second batch pruned %d, %v; want 1", n, err)
	}
	if n, _ := st.PruneClosedTunnels(ctx, cutoff, now, 100); n != 0 {
		t.Fatalf("pruned %d more, want none", n)
	}
	var remaining []string
	rows, err := st.db.QueryContext(ctx, `SELECT id FROM tunnels ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		remaining = append(remaining, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	want := []string{"t-newest", "t-recent", "t-token"}
	if len(remaining) != len(want) {
		t.Fatalf("remaining tunnels = %v, want %v", remaining, want)
	}
	for i := range want {
		if remaining[i] != want[i] {
			t.Fatalf("remaining tunnels = %v, want %v", remaining, want)
		}
	}
	var tokens int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connect_tokens WHERE tunnel_id = 't-old-1'`).Scan(&tokens); err != nil || tokens != 0 {
		t.Fatalf("pruned tunnel's tokens kept: %d, %v", tokens, err)
	}
	route, err := st.FindRouteByHost(ctx, "app.example.com")
	if err != nil || route.Tunnel.ID != "t-newest" {
		t.Fatalf("route after prune = %q, %v", route.Tunnel.ID, err)
	}
}

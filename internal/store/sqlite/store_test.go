package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestAllocateTemporaryAndDisconnect(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_close_temp")
	if err != nil {
		t.Fatal(err)
	}

	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname == "" || tunnel.ID == "" {
		t.Fatalf("expected allocated domain and tunnel")
	}

	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Domain.Status != "inactive" {
		t.Fatalf("expected temporary domain to be inactive, got %s", route.Domain.Status)
	}
}

func TestSetTunnelAccessPasswordHashAndRouteLookup(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_password_route")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "pwtest", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelAccessCredentials(ctx, tunnel.ID, "admin", "form", "bcrypt-hash"); err != nil {
		t.Fatal(err)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tunnel.AccessPasswordHash != "bcrypt-hash" {
		t.Fatalf("expected access password hash to roundtrip, got %q", route.Tunnel.AccessPasswordHash)
	}
	if route.Tunnel.AccessUser != "admin" {
		t.Fatalf("expected access user to roundtrip, got %q", route.Tunnel.AccessUser)
	}
	if route.Tunnel.AccessMode != "form" {
		t.Fatalf("expected access mode to roundtrip, got %q", route.Tunnel.AccessMode)
	}
}

func TestConnectTokenConsume(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_close_perm")
	if err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "abc", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.CreateConnectToken(ctx, tunnel.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id, err := store.ConsumeConnectToken(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if id != tunnel.ID {
		t.Fatalf("expected tunnel id match")
	}
	if _, err := store.ConsumeConnectToken(ctx, token); err == nil {
		t.Fatalf("expected second consume to fail")
	}
}

func TestConsumeConnectTokenErrorDoesNotLeakTransaction(t *testing.T) {
	store, err := openTestStoreWithOptions(t, OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_token_tx")
	if err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "toktx", "example.com")
	if err != nil {
		t.Fatal(err)
	}

	token, err := store.CreateConnectToken(ctx, tunnel.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeConnectToken(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeConnectToken(ctx, token); err == nil {
		t.Fatal("expected second consume to fail")
	}
	assertStoreWritableAfterError(t, store, tunnel.ID)

	expiredToken, err := store.CreateConnectToken(ctx, tunnel.ID, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeConnectToken(ctx, expiredToken); err == nil {
		t.Fatal("expected expired token consume to fail")
	}
	assertStoreWritableAfterError(t, store, tunnel.ID)
}

func TestAllocateConflictDoesNotLeakTransaction(t *testing.T) {
	store, err := openTestStoreWithOptions(t, OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k1, err := store.CreateAPIKey(ctx, "k1", "hash_alloc_conflict_1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := store.CreateAPIKey(ctx, "k2", "hash_alloc_conflict_2")
	if err != nil {
		t.Fatal(err)
	}

	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k1.ID, "temporary", "same-sub", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AllocateDomainAndTunnel(ctx, k2.ID, "temporary", "same-sub", "example.com"); err == nil {
		t.Fatal("expected hostname conflict")
	}
	assertStoreWritableAfterError(t, store, tunnel.ID)
}

func TestSwapConflictDoesNotLeakTransaction(t *testing.T) {
	store, err := openTestStoreWithOptions(t, OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k1, err := store.CreateAPIKey(ctx, "k1", "hash_swap_conflict_1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := store.CreateAPIKey(ctx, "k2", "hash_swap_conflict_2")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k1.ID, "temporary", "swap-sub", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SwapTunnelSession(ctx, d.ID, k2.ID, "machine-other"); err == nil {
		t.Fatal("expected hostname conflict on swap")
	}
	assertStoreWritableAfterError(t, store, tunnel.ID)
}

func TestPurgeStaleConnectTokens(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_token_purge")
	if err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "purge-token", "example.com")
	if err != nil {
		t.Fatal(err)
	}

	expiredToken, err := store.CreateConnectToken(ctx, tunnel.ID, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	oldUsedToken, err := store.CreateConnectToken(ctx, tunnel.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeConnectToken(ctx, oldUsedToken); err != nil {
		t.Fatal(err)
	}
	recentUsedToken, err := store.CreateConnectToken(ctx, tunnel.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeConnectToken(ctx, recentUsedToken); err != nil {
		t.Fatal(err)
	}
	freshToken, err := store.CreateConnectToken(ctx, tunnel.ID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	oldUsedAt := now.Add(-2 * time.Hour)
	recentUsedAt := now.Add(-15 * time.Minute)
	if _, err := store.db.ExecContext(ctx, `UPDATE connect_tokens SET used_at = ? WHERE token = ?`, oldUsedAt, oldUsedToken); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `UPDATE connect_tokens SET used_at = ? WHERE token = ?`, recentUsedAt, recentUsedToken); err != nil {
		t.Fatal(err)
	}

	purged, err := store.PurgeStaleConnectTokens(ctx, now, now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if purged != 2 {
		t.Fatalf("expected 2 purged tokens, got %d", purged)
	}

	remaining := map[string]bool{}
	rows, err := store.db.QueryContext(ctx, `SELECT token FROM connect_tokens`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			t.Fatal(err)
		}
		remaining[token] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if remaining[expiredToken] {
		t.Fatal("expected expired token to be purged")
	}
	if remaining[oldUsedToken] {
		t.Fatal("expected old used token to be purged")
	}
	if !remaining[recentUsedToken] {
		t.Fatal("expected recent used token to remain")
	}
	if !remaining[freshToken] {
		t.Fatal("expected fresh token to remain")
	}
}

func TestOpenCreatesParentDirectory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "path", "expose.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db file to exist at %s: %v", dbPath, err)
	}
}

func TestCloseTemporaryTunnel(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_disconnected_closed")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	host, closed, err := store.CloseTemporaryTunnel(ctx, tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatalf("expected tunnel to be closed")
	}
	if host != d.Hostname {
		t.Fatalf("expected hostname %s, got %s", d.Hostname, host)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tunnel.State != "closed" {
		t.Fatalf("expected tunnel state closed, got %s", route.Tunnel.State)
	}
	if route.Domain.Status != "inactive" {
		t.Fatalf("expected domain inactive, got %s", route.Domain.Status)
	}
}

func TestCloseTemporaryTunnelIgnoresPermanent(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "abc", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	host, closed, err := store.CloseTemporaryTunnel(ctx, tunnel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if closed {
		t.Fatalf("did not expect permanent tunnel to be closed")
	}
	if host != "" {
		t.Fatalf("expected empty hostname for non-temporary tunnel, got %s", host)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tunnel.State != "connected" {
		t.Fatalf("expected tunnel state connected, got %s", route.Tunnel.State)
	}
}

func TestSetTunnelDisconnectedKeepsClosedState(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if _, closed, err := store.CloseTemporaryTunnel(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	} else if !closed {
		t.Fatal("expected close")
	}
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tunnel.State != "closed" {
		t.Fatalf("expected tunnel to remain closed, got %s", route.Tunnel.State)
	}

}

func TestPurgeInactiveTemporaryDomains(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_purge")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	staleTime := time.Now().Add(-48 * time.Hour).UTC()
	if _, err := store.db.ExecContext(ctx, `UPDATE tunnels SET disconnected_at = ? WHERE id = ?`, staleTime, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	hosts, err := store.PurgeInactiveTemporaryDomains(ctx, time.Now().Add(-24*time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != d.Hostname {
		t.Fatalf("expected stale hostname %s to be purged, got %v", d.Hostname, hosts)
	}

	if _, err := store.FindRouteByHost(ctx, d.Hostname); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected host to be deleted, got err=%v", err)
	}
}

func TestIsHostnameActive(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_active")
	if err != nil {
		t.Fatal(err)
	}
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.IsHostnameActive(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("expected hostname to be active")
	}

	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	active, err = store.IsHostnameActive(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("expected hostname to be inactive")
	}
}

func TestResetConnectedTunnels(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_reset")
	if err != nil {
		t.Fatal(err)
	}
	_, tempTunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	permDomain, permTunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "perm", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tempTunnel.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, permTunnel.ID); err != nil {
		t.Fatal(err)
	}

	n, err := store.ResetConnectedTunnels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 reset tunnels, got %d", n)
	}

	var tempState, permState string
	if err := store.db.QueryRowContext(ctx, `SELECT state FROM tunnels WHERE id = ?`, tempTunnel.ID).Scan(&tempState); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `SELECT state FROM tunnels WHERE id = ?`, permTunnel.ID).Scan(&permState); err != nil {
		t.Fatal(err)
	}
	if tempState != "disconnected" || permState != "disconnected" {
		t.Fatalf("expected tunnels disconnected, got temp=%s perm=%s", tempState, permState)
	}

	active, err := store.IsHostnameActive(ctx, permDomain.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("expected permanent domain to remain active")
	}
}

func TestTemporarySubdomainReusedForSameAPIKey(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_temp_reuse")
	if err != nil {
		t.Fatal(err)
	}

	d1, tunnel1, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "stable1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel1.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelDisconnected(ctx, tunnel1.ID); err != nil {
		t.Fatal(err)
	}

	d2, _, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "stable1", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if d1.ID != d2.ID {
		t.Fatalf("expected same temporary domain to be reused, got %s vs %s", d1.ID, d2.ID)
	}
}

func TestTemporarySubdomainCannotBeReusedAcrossAPIKeys(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k1, err := store.CreateAPIKey(ctx, "test1", "hash_temp_reuse_key1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := store.CreateAPIKey(ctx, "test2", "hash_temp_reuse_key2")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.AllocateDomainAndTunnel(ctx, k1.ID, "temporary", "stable2", "example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.AllocateDomainAndTunnel(ctx, k2.ID, "temporary", "stable2", "example.com"); err == nil {
		t.Fatal("expected hostname conflict across API keys")
	}
}

func TestAllocateDomainAndTunnelWithClientMeta(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_client_meta_alloc")
	if err != nil {
		t.Fatal(err)
	}

	d, tunnel, err := store.AllocateDomainAndTunnelWithClientMeta(ctx, k.ID, "temporary", "stable-meta", "example.com", "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname != "stable-meta.example.com" {
		t.Fatalf("expected hostname stable-meta.example.com, got %s", d.Hostname)
	}
	if tunnel.ClientMeta != "machine-1" {
		t.Fatalf("expected client meta machine-1, got %q", tunnel.ClientMeta)
	}

	route, err := store.FindRouteByHost(ctx, d.Hostname)
	if err != nil {
		t.Fatal(err)
	}
	if route.Tunnel.ClientMeta != "machine-1" {
		t.Fatalf("expected stored client meta machine-1, got %q", route.Tunnel.ClientMeta)
	}
}

func TestSwapTunnelSession(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_swap_session")
	if err != nil {
		t.Fatal(err)
	}
	d, oldTunnel, err := store.AllocateDomainAndTunnelWithClientMeta(ctx, k.ID, "temporary", "stable-swap", "example.com", "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, oldTunnel.ID); err != nil {
		t.Fatal(err)
	}

	newTunnel, err := store.SwapTunnelSession(ctx, d.ID, k.ID, "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if newTunnel.ID == oldTunnel.ID {
		t.Fatal("expected a new tunnel id for swapped session")
	}
	if newTunnel.DomainID != d.ID {
		t.Fatalf("expected tunnel domain %s, got %s", d.ID, newTunnel.DomainID)
	}
	if newTunnel.ClientMeta != "machine-1" {
		t.Fatalf("expected client meta machine-1, got %q", newTunnel.ClientMeta)
	}

	var oldState string
	if err := store.db.QueryRowContext(ctx, `SELECT state FROM tunnels WHERE id = ?`, oldTunnel.ID).Scan(&oldState); err != nil {
		t.Fatal(err)
	}
	if oldState != domain.TunnelStateDisconnected {
		t.Fatalf("expected old tunnel to be disconnected, got %s", oldState)
	}
}

func TestResolveServerPepperAllowsEmptyInitialization(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	current, exists, err := store.GetServerPepper(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exists || current != "" {
		t.Fatalf("expected no persisted pepper yet, got exists=%v value=%q", exists, current)
	}

	resolved, err := store.ResolveServerPepper(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "" {
		t.Fatalf("expected empty pepper to be persisted, got %q", resolved)
	}

	current, exists, err = store.GetServerPepper(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !exists || current != "" {
		t.Fatalf("expected persisted empty pepper, got exists=%v value=%q", exists, current)
	}
}

func TestAllocateRejectsConnectedDuplicateTemporary(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_dup_temp")
	if err != nil {
		t.Fatal(err)
	}

	// First allocation succeeds.
	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "dup-sub", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	// Second allocation with same subdomain while first is connected should fail.
	_, _, err = store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "dup-sub", "example.com")
	if !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("expected ErrHostnameInUse for duplicate connected tunnel, got %v", err)
	}

	// After disconnecting, the same subdomain should be allocatable again.
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	d2, tunnel2, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "dup-sub", "example.com")
	if err != nil {
		t.Fatalf("expected allocation to succeed after disconnect, got %v", err)
	}
	if d2.ID != d.ID {
		t.Fatalf("expected reused domain id %s, got %s", d.ID, d2.ID)
	}
	if tunnel2.ID == tunnel.ID {
		t.Fatal("expected a new tunnel id")
	}
}

func TestAllocateRejectsConnectedDuplicatePermanent(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_dup_perm")
	if err != nil {
		t.Fatal(err)
	}

	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "dup-perm", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}

	// Second allocation with same subdomain while first is connected should fail.
	_, _, err = store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "dup-perm", "example.com")
	if !errors.Is(err, ErrHostnameInUse) {
		t.Fatalf("expected ErrHostnameInUse for duplicate connected permanent tunnel, got %v", err)
	}

	// After disconnecting, the same subdomain should be allocatable again.
	if err := store.SetTunnelDisconnected(ctx, tunnel.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "dup-perm", "example.com")
	if err != nil {
		t.Fatalf("expected allocation to succeed after disconnect, got %v", err)
	}
}

func TestResolveServerPepperRejectsExplicitMismatch(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	if _, err := store.ResolveServerPepper(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveServerPepper(ctx, "non-empty"); err == nil {
		t.Fatal("expected explicit pepper mismatch error")
	}
}

func TestCreateAPIKeyDefaultTunnelLimit(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_default_limit")
	if err != nil {
		t.Fatal(err)
	}
	if k.TunnelLimit != -1 {
		t.Fatalf("expected default tunnel limit -1, got %d", k.TunnelLimit)
	}
	limit, err := store.GetAPIKeyTunnelLimit(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if limit != -1 {
		t.Fatalf("expected stored tunnel limit -1, got %d", limit)
	}
}

func TestCreateAPIKeyWithLimit(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKeyWithLimit(ctx, "test", "hash_custom_limit", 10)
	if err != nil {
		t.Fatal(err)
	}
	if k.TunnelLimit != 10 {
		t.Fatalf("expected tunnel limit 10, got %d", k.TunnelLimit)
	}
	limit, err := store.GetAPIKeyTunnelLimit(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if limit != 10 {
		t.Fatalf("expected stored tunnel limit 10, got %d", limit)
	}
}

func TestSetAPIKeyTunnelLimit(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash_set_limit")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAPIKeyTunnelLimit(ctx, k.ID, 5); err != nil {
		t.Fatal(err)
	}
	limit, err := store.GetAPIKeyTunnelLimit(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if limit != 5 {
		t.Fatalf("expected tunnel limit 5, got %d", limit)
	}
	// Update to unlimited
	if err := store.SetAPIKeyTunnelLimit(ctx, k.ID, -1); err != nil {
		t.Fatal(err)
	}
	limit, err = store.GetAPIKeyTunnelLimit(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if limit != -1 {
		t.Fatalf("expected tunnel limit -1, got %d", limit)
	}
}

func TestSetAPIKeyTunnelLimitNonExistent(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	err = store.SetAPIKeyTunnelLimit(ctx, "nonexistent", 5)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestListAPIKeysIncludesTunnelLimit(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	if _, err := store.CreateAPIKeyWithLimit(ctx, "unlimited", "hash_list_limit_1", -1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateAPIKeyWithLimit(ctx, "limited", "hash_list_limit_2", 3); err != nil {
		t.Fatal(err)
	}

	keys, err := store.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}
	// Keys are ordered by created_at DESC, so "limited" is first.
	found := map[string]int{}
	for _, k := range keys {
		found[k.Name] = k.TunnelLimit
	}
	if found["unlimited"] != -1 {
		t.Fatalf("expected unlimited key limit -1, got %d", found["unlimited"])
	}
	if found["limited"] != 3 {
		t.Fatalf("expected limited key limit 3, got %d", found["limited"])
	}
}

func openTestStore(t *testing.T) (*Store, error) {
	t.Helper()
	return openTestStoreWithOptions(t, OpenOptions{})
}

func openTestStoreWithOptions(t *testing.T, opts OpenOptions) (*Store, error) {
	t.Helper()
	id, err := newID("test")
	if err != nil {
		return nil, err
	}
	return OpenWithOptions(fmt.Sprintf("file:%s?mode=memory&cache=shared", id), opts)
}

func assertStoreWritableAfterError(t *testing.T, store *Store, tunnelID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := store.CreateConnectToken(ctx, tunnelID, time.Minute); err != nil {
		t.Fatalf("store should remain writable after tx error path: %v", err)
	}
}

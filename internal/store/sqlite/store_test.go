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
)

func TestAllocateTemporaryAndDisconnect(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

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

func TestConnectTokenConsume(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

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

func TestOpenCreatesParentDirectory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "path", "expose.db")

	store, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected db file to exist at %s: %v", dbPath, err)
	}
}

func TestCloseTemporaryTunnel(t *testing.T) {
	store, err := openTestStore(t)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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
	defer store.Close()

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

func openTestStore(t *testing.T) (*Store, error) {
	t.Helper()
	return Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", newID("test")))
}

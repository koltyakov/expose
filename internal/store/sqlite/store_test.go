package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAllocateTemporaryAndDisconnect(t *testing.T) {
	store, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash")
	if err != nil {
		t.Fatal(err)
	}

	d, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "temporary", "", "", "example.com")
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
	store, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	k, err := store.CreateAPIKey(ctx, "test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	_, tunnel, err := store.AllocateDomainAndTunnel(ctx, k.ID, "permanent", "abc", "", "example.com")
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

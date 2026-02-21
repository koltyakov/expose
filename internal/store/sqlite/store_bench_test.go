package sqlite

import (
	"context"
	"testing"
	"time"
)

func BenchmarkFindRouteByHost(b *testing.B) {
	store, err := OpenWithOptions(b.TempDir()+"/bench.db", OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key, err := store.CreateAPIKey(ctx, "bench", "hash_bench_find_route")
	if err != nil {
		b.Fatal(err)
	}
	domainRec, tunnelRec, err := store.AllocateDomainAndTunnel(ctx, key.ID, "temporary", "bench-route", "example.com")
	if err != nil {
		b.Fatal(err)
	}
	if err := store.SetTunnelConnected(ctx, tunnelRec.ID); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.FindRouteByHost(ctx, domainRec.Hostname); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAllocateDomainAndTunnelTemporary(b *testing.B) {
	store, err := OpenWithOptions(b.TempDir()+"/bench.db", OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key, err := store.CreateAPIKey(ctx, "bench", "hash_bench_allocate")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := store.AllocateDomainAndTunnelWithClientMeta(ctx, key.ID, "temporary", "", "example.com", "machine-bench"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConsumeConnectToken(b *testing.B) {
	store, err := OpenWithOptions(b.TempDir()+"/bench.db", OpenOptions{MaxOpenConns: 1, MaxIdleConns: 1})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key, err := store.CreateAPIKey(ctx, "bench", "hash_bench_token")
	if err != nil {
		b.Fatal(err)
	}
	_, tunnelRec, err := store.AllocateDomainAndTunnel(ctx, key.ID, "temporary", "bench-token", "example.com")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token, err := store.CreateConnectToken(ctx, tunnelRec.ID, time.Minute)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := store.ConsumeConnectToken(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

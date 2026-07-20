package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

func TestLookupGroupCoalescesConcurrentCalls(t *testing.T) {
	t.Parallel()

	var group lookupGroup[int]
	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	lookup := func() (int, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return 42, nil
	}

	const workers = 16
	results := make(chan int, workers)
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(workers)
	for range workers {
		wg.Go(func() {
			ready.Done()
			value, err := group.do(context.Background(), "host", lookup)
			if err != nil {
				t.Errorf("lookup error = %v", err)
				return
			}
			results <- value
		})
	}
	ready.Wait()
	<-started
	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)
	if got := calls.Load(); got != 1 {
		t.Fatalf("lookup calls = %d, want 1", got)
	}
	for value := range results {
		if value != 42 {
			t.Fatalf("lookup value = %d", value)
		}
	}
}

func TestRouteCacheSetGetDelete(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	route := domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-1", Hostname: "a.example.com"},
		Tunnel: domain.Tunnel{ID: "t-1"},
	}
	c.set("a.example.com", route)

	got, ok := c.get("a.example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Tunnel.ID != "t-1" {
		t.Fatalf("expected tunnel t-1, got %s", got.Tunnel.ID)
	}

	c.deleteByTunnelID("t-1")
	if _, ok := c.get("a.example.com"); ok {
		t.Fatal("expected cache miss after delete")
	}
}

func TestRouteCacheDeleteHost(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	route := domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-1", Hostname: "a.example.com"},
		Tunnel: domain.Tunnel{ID: "t-1"},
	}
	c.set("a.example.com", route)

	c.deleteHost("a.example.com")
	if _, ok := c.get("a.example.com"); ok {
		t.Fatal("expected cache miss after deleteHost")
	}
	if hosts := c.hostsByTunnel["t-1"]; len(hosts) != 0 {
		t.Fatal("expected host tracking to be cleared for deleteHost")
	}
}

func TestRouteCacheTTLExpiry(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	route := domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-2"},
		Tunnel: domain.Tunnel{ID: "t-2"},
	}
	c.set("b.example.com", route)

	// Manually expire the entry.
	c.mu.Lock()
	e := c.entries["b.example.com"]
	e.expiresAtUnixNano = time.Now().Add(-time.Second).UnixNano()
	c.entries["b.example.com"] = e
	c.mu.Unlock()

	if _, ok := c.get("b.example.com"); ok {
		t.Fatal("expected miss for expired entry")
	}
}

func TestRouteCacheMissCaching(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	c.setMiss("missing.example.com")

	if _, ok := c.get("missing.example.com"); ok {
		t.Fatal("expected negative cache entry not to be treated as route hit")
	}
	if _, found, cached := c.lookup("missing.example.com"); !cached || found {
		t.Fatal("expected cached negative lookup")
	}
	c.deleteHost("missing.example.com")
	if _, _, cached := c.lookup("missing.example.com"); cached {
		t.Fatal("expected miss entry to be deleted")
	}
}

func TestRouteCacheCapacityIsBounded(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
		maxEntries:    2,
	}
	c.setMiss("one.example.com")
	c.setMiss("two.example.com")
	c.setMiss("three.example.com")

	if got := len(c.entries); got != 2 {
		t.Fatalf("cache size = %d, want 2", got)
	}
	if _, _, cached := c.lookup("three.example.com"); cached {
		t.Fatal("expected entry beyond capacity not to be cached")
	}
}

func TestLiveRouteIndexDeleteHost(t *testing.T) {
	t.Parallel()

	idx := newLiveRouteIndex()
	idx.upsert(domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-1", APIKeyID: "k-1", Hostname: "gone.example.com"},
		Tunnel: domain.Tunnel{ID: "t-1", APIKeyID: "k-1"},
	})
	if !idx.deleteHost("gone.example.com") {
		t.Fatal("expected live route deletion")
	}
	if _, ok := idx.lookupHost("gone.example.com"); ok {
		t.Fatal("expected host lookup to miss after deletion")
	}
	if _, ok := idx.lookupTunnel("t-1"); ok {
		t.Fatal("expected tunnel lookup to miss after deletion")
	}

	idx.upsert(domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-2", Hostname: "reused.example.com"},
		Tunnel: domain.Tunnel{ID: "t-2"},
	})
	if idx.deleteHostIfDomain("reused.example.com", "old-domain") {
		t.Fatal("expected domain identity mismatch to preserve the route")
	}
}

func TestACMEAuthorizationRejectsDisconnectedTemporaryRoute(t *testing.T) {
	t.Parallel()

	idx := newLiveRouteIndex()
	route := domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-acme", Hostname: "temp.example.com", Status: domain.DomainStatusActive},
		Tunnel: domain.Tunnel{ID: "t-acme", IsTemporary: true},
	}
	idx.upsert(route)
	sess := &session{tunnelID: route.Tunnel.ID}
	idx.attachSession(route.Tunnel.ID, sess)
	idx.clearSession(route.Tunnel.ID, sess)
	srv := &Server{cfg: config.ServerConfig{BaseDomain: "example.com"}, liveRoutes: idx}
	if err := srv.authorizeACMEHost(context.Background(), route.Domain.Hostname); err == nil {
		t.Fatal("expected disconnected temporary route to be rejected")
	}
}

func TestRoutePublicationSerializesWithRegistration(t *testing.T) {
	t.Parallel()

	host := "serialized.example.com"
	storeRead := make(chan struct{})
	releaseStore := make(chan struct{})
	oldRoute := domain.TunnelRoute{
		Domain: domain.Domain{ID: "old-domain", Hostname: host, Status: domain.DomainStatusActive},
		Tunnel: domain.Tunnel{ID: "old-tunnel"},
	}
	store := &stubServerStore{findRouteByHostFn: func(context.Context, string) (domain.TunnelRoute, error) {
		close(storeRead)
		<-releaseStore
		return oldRoute, nil
	}}
	srv := &Server{
		cfg:        config.ServerConfig{RequestTimeout: time.Second},
		store:      store,
		liveRoutes: newLiveRouteIndex(),
		routes: routeCache{
			entries:       make(map[string]routeCacheEntry),
			hostsByTunnel: make(map[string]map[string]struct{}),
		},
	}
	lookupDone := make(chan struct{})
	go func() {
		defer close(lookupDone)
		_, _ = srv.resolvePublicRoute(context.Background(), host)
	}()
	<-storeRead

	newRoute := domain.TunnelRoute{
		Domain: domain.Domain{ID: "new-domain", Hostname: host, Status: domain.DomainStatusActive},
		Tunnel: domain.Tunnel{ID: "new-tunnel"},
	}
	registrationDone := make(chan struct{})
	go func() {
		defer close(registrationDone)
		srv.routeLifecycleMu.Lock()
		srv.publishRegisteredRoute(newRoute)
		srv.routeLifecycleMu.Unlock()
	}()
	close(releaseStore)
	<-lookupDone
	<-registrationDone

	if _, ok := srv.liveRoutes.lookupHost(host); ok {
		t.Fatal("offline registration should not be retained in live routes")
	}
	cached, ok := srv.routes.get(host)
	if !ok || cached.Domain.ID != newRoute.Domain.ID {
		t.Fatalf("final cached route = %+v, want new registration", cached)
	}
}

func TestRouteCacheConcurrent(t *testing.T) {
	t.Parallel()

	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	const goroutines = 16
	const opsPerGoroutine = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func() {
			defer wg.Done()
			for i := range opsPerGoroutine {
				host := fmt.Sprintf("host-%d-%d.example.com", g, i%10)
				tunnelID := fmt.Sprintf("t-%d-%d", g, i%5)
				route := domain.TunnelRoute{
					Domain: domain.Domain{ID: fmt.Sprintf("d-%d", g), Hostname: host},
					Tunnel: domain.Tunnel{ID: tunnelID},
				}
				c.set(host, route)
				c.get(host)
				if i%20 == 0 {
					c.deleteByTunnelID(tunnelID)
				}
				if i%50 == 0 {
					c.cleanup()
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkRouteCacheSetAndGet(b *testing.B) {
	c := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}
	route := domain.TunnelRoute{
		Tunnel: domain.Tunnel{ID: "t-bench"},
	}

	b.ReportAllocs()

	for i := 0; b.Loop(); i++ {
		host := fmt.Sprintf("h-%d.example.com", i%100)
		c.set(host, route)
		c.get(host)
	}
}

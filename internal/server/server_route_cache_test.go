package server

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

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
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := fmt.Sprintf("h-%d.example.com", i%100)
		c.set(host, route)
		c.get(host)
	}
}

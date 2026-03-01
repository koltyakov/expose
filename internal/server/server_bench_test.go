package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func BenchmarkRouteCacheGetHit(b *testing.B) {
	cache := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}
	host := "bench.example.com"
	cache.entries[host] = routeCacheEntry{
		route:             domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t-bench"}},
		found:             true,
		expiresAtUnixNano: time.Now().Add(24 * time.Hour).UnixNano(),
	}
	cache.hostsByTunnel["t-bench"] = map[string]struct{}{host: {}}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := cache.get(host); !ok {
			b.Fatal("expected cache hit")
		}
	}
}

func BenchmarkRouteCacheDeleteByTunnelID(b *testing.B) {
	const hostsPerTunnel = 2048

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cache := routeCache{
			entries:       make(map[string]routeCacheEntry, hostsPerTunnel),
			hostsByTunnel: make(map[string]map[string]struct{}, 1),
		}
		cache.hostsByTunnel["t-bench"] = make(map[string]struct{}, hostsPerTunnel)
		expiresAt := time.Now().Add(24 * time.Hour).UnixNano()
		for n := 0; n < hostsPerTunnel; n++ {
			host := fmt.Sprintf("h-%d.example.com", n)
			cache.entries[host] = routeCacheEntry{
				route:             domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t-bench"}},
				found:             true,
				expiresAtUnixNano: expiresAt,
			}
			cache.hostsByTunnel["t-bench"][host] = struct{}{}
		}
		b.StartTimer()

		cache.deleteByTunnelID("t-bench")
	}
}

func BenchmarkSessionWSPendingSendBuffered(b *testing.B) {
	ch := make(chan tunnelproto.Message, 1)
	sess := &session{
		wsPending: map[string]chan tunnelproto.Message{
			"stream-1": ch,
		},
	}
	msg := tunnelproto.Message{
		Kind:   tunnelproto.KindWSData,
		WSData: &tunnelproto.WSData{ID: "stream-1", MessageType: 1, DataB64: "Yg=="},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok := sess.wsPendingSend("stream-1", msg, 0); !ok {
			b.Fatal("expected ws pending send to succeed")
		}
		<-ch
	}
}

func BenchmarkQueueDomainTouchDeduplicate(b *testing.B) {
	srv := &Server{
		domainTouches: make(chan string, 1),
		domainTouched: make(map[string]struct{}),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srv.queueDomainTouch("d-bench")
		srv.queueDomainTouch("d-bench")
		domainID := <-srv.domainTouches
		srv.completeDomainTouch(domainID)
	}
}

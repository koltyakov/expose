package server

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// First burst should succeed up to the burst limit.
	for i := range int(regBurstLimit) {
		if !rl.allow("key-a") {
			t.Fatalf("expected allow on burst iteration %d", i)
		}
	}
	// Next call should be rate-limited.
	if rl.allow("key-a") {
		t.Fatal("expected rate limit after burst exhaustion")
	}
}

func TestRateLimiterIsolatesKeys(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// Exhaust key-a.
	for range int(regBurstLimit) {
		rl.allow("key-a")
	}
	if rl.allow("key-a") {
		t.Fatal("expected key-a to be rate-limited")
	}

	// key-b should still have its full burst available.
	if !rl.allow("key-b") {
		t.Fatal("expected key-b to be allowed independently")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// Exhaust burst.
	for i := 0; i < int(regBurstLimit); i++ {
		rl.allow("key-c")
	}
	if rl.allow("key-c") {
		t.Fatal("expected rate limit")
	}

	// Simulate passage of time by directly manipulating the bucket.
	s := rl.shard("key-c")
	s.mu.Lock()
	b := s.buckets["key-c"]
	b.lastCheck = b.lastCheck.Add(-1 * time.Second)
	s.mu.Unlock()

	// After 1 second at 5/s rate, at least 1 token should be available.
	if !rl.allow("key-c") {
		t.Fatal("expected allow after time passage")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()
	rl.allow("stale-key")

	// Age the bucket beyond cleanup threshold.
	s := rl.shard("stale-key")
	s.mu.Lock()
	s.buckets["stale-key"].lastCheck = time.Now().Add(-(regCleanupAge + time.Minute))
	s.mu.Unlock()

	rl.cleanup()

	s.mu.Lock()
	_, exists := s.buckets["stale-key"]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected stale bucket to be cleaned up")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()
	const goroutines = 32
	const keysPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		g := g
		go func() {
			defer wg.Done()
			for k := 0; k < keysPerGoroutine; k++ {
				key := fmt.Sprintf("key-%d-%d", g, k)
				rl.allow(key)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkRateLimiterAllowSingleKey(b *testing.B) {
	rl := newRateLimiter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.allow("bench-key")
	}
}

func BenchmarkRateLimiterAllowDistinctKeys(b *testing.B) {
	rl := newRateLimiter()
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rl.allow(keys[i%len(keys)])
	}
}

func BenchmarkRateLimiterAllowParallel(b *testing.B) {
	rl := newRateLimiter()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.allow(fmt.Sprintf("key-%d", i%100))
			i++
		}
	})
}

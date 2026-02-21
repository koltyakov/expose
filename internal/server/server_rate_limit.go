package server

import (
	"sync"
	"time"
)

// rateLimiter implements a simple per-key token-bucket rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

const (
	regRateLimit  = 5.0             // registrations per second per key
	regBurstLimit = 10.0            // max burst
	regCleanupAge = 5 * time.Minute // evict idle buckets
)

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: regBurstLimit, lastCheck: now}
		rl.buckets[key] = b
	}

	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * regRateLimit
	if b.tokens > regBurstLimit {
		b.tokens = regBurstLimit
	}
	b.lastCheck = now

	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}

// cleanup evicts idle rate-limit buckets. Called periodically by the janitor
// so that the hot allow() path is never burdened with map iteration.
func (rl *rateLimiter) cleanup() {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, v := range rl.buckets {
		if now.Sub(v.lastCheck) > regCleanupAge {
			delete(rl.buckets, k)
		}
	}
}

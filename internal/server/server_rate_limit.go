package server

import (
	"sync"
	"time"
)

const (
	regRateLimit  = 5.0             // registrations per second per key
	regBurstLimit = 10.0            // max burst
	regCleanupAge = 5 * time.Minute // evict idle buckets

	// rateLimiterShards controls how many independent shards the rate limiter
	// uses.  Each shard has its own mutex, which drastically reduces lock
	// contention under concurrent registrations from distinct API keys.
	rateLimiterShards = 16
)

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

// rateLimiter implements a sharded per-key token-bucket rate limiter.
// Keys are mapped to one of [rateLimiterShards] independent shards via FNV
// hashing so that concurrent allow() calls on different keys rarely contend
// on the same mutex.
type rateLimiter struct {
	shards [rateLimiterShards]rateLimiterShard
}

type rateLimiterShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{}
	for i := range rl.shards {
		rl.shards[i].buckets = make(map[string]*bucket)
	}
	return rl
}

func (rl *rateLimiter) shard(key string) *rateLimiterShard {
	return &rl.shards[shardIndex(key)]
}

func shardIndex(key string) int {
	const (
		fnvOffset32 = uint32(2166136261)
		fnvPrime32  = uint32(16777619)
	)
	h := fnvOffset32
	for i := 0; i < len(key); i++ {
		h ^= uint32(key[i])
		h *= fnvPrime32
	}
	return int(h % uint32(rateLimiterShards))
}

func (rl *rateLimiter) allow(key string) bool {
	s := rl.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: regBurstLimit, lastCheck: now}
		s.buckets[key] = b
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

// cleanup evicts idle rate-limit buckets across all shards.
// Called periodically by the janitor so that the hot allow() path is never
// burdened with map iteration.
func (rl *rateLimiter) cleanup() {
	now := time.Now()
	for i := range rl.shards {
		s := &rl.shards[i]
		s.mu.Lock()
		for k, v := range s.buckets {
			if now.Sub(v.lastCheck) > regCleanupAge {
				delete(s.buckets, k)
			}
		}
		s.mu.Unlock()
	}
}

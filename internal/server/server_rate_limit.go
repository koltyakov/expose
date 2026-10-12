package server

import (
	"sync"
	"time"
)

const (
	regRateLimit  = 5.0             // registrations per second per key
	regBurstLimit = 10.0            // max burst
	regCleanupAge = 5 * time.Minute // evict idle buckets

	// Failed-auth throttling for protected tunnels: after
	// accessAuthFailBurst wrong passwords from one hostname+IP, further
	// attempts are rejected before bcrypt runs, refilling one attempt
	// every 1/accessAuthFailRate seconds. Successful requests never
	// consume tokens: attempts reserve a token before checking credentials
	// and return it on success.
	accessAuthFailRate   = 0.2 // one retry allowed per 5 seconds
	accessAuthFailBurst  = 10.0
	accessAuthCleanupAge = 15 * time.Minute
	maxAccessChecks      = 4 // bound expensive password checks across all hosts/IPs

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
	rate       float64
	burst      float64
	cleanupAge time.Duration
	shards     [rateLimiterShards]rateLimiterShard
}

type rateLimiterShard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	return newConfiguredRateLimiter(regRateLimit, regBurstLimit, regCleanupAge)
}

func newConfiguredRateLimiter(rate, burst float64, cleanupAge time.Duration) *rateLimiter {
	rl := &rateLimiter{
		rate:       rate,
		burst:      burst,
		cleanupAge: cleanupAge,
	}
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
	if rl == nil {
		return true
	}
	s := rl.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b, ok := s.buckets[key]
	if !ok {
		b = &bucket{tokens: rl.burst, lastCheck: now}
		s.buckets[key] = b
	}

	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastCheck = now

	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}

// refund returns a reserved attempt without erasing failures from other requests.
func (rl *rateLimiter) refund(key string) {
	if rl == nil {
		return
	}
	s := rl.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.buckets[key]; ok {
		b.tokens = min(rl.burst, b.tokens+1)
	}
}

// exhausted reports whether key has no tokens left, without consuming one.
// Admission must use allow instead so concurrent callers reserve distinct tokens.
func (rl *rateLimiter) exhausted(key string) bool {
	if rl == nil {
		return false
	}
	s := rl.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.buckets[key]
	if !ok {
		return false
	}
	now := time.Now()
	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * rl.rate
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastCheck = now
	return b.tokens < 1.0
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
			if now.Sub(v.lastCheck) > rl.cleanupAge {
				delete(s.buckets, k)
			}
		}
		s.mu.Unlock()
	}
}

package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

// routeCache stores recently resolved hostname lookups with a short TTL. Both
// hits and misses are cached. Entries are explicitly invalidated on
// connect/disconnect to keep the data fresh; the TTL is a safety-net for any
// missed invalidation.
type routeCache struct {
	mu            sync.RWMutex
	entries       map[string]routeCacheEntry
	hostsByTunnel map[string]map[string]struct{}
	ttl           time.Duration
	maxEntries    int
	// cachedNow is updated periodically to avoid calling time.Now() on every
	// cache lookup in the hot path.
	cachedNow atomic.Int64
}

type routeCacheEntry struct {
	route             domain.TunnelRoute
	found             bool
	expiresAtUnixNano int64
}

const defaultRouteCacheTTL = time.Minute
const defaultRouteCacheMaxEntries = 10_000

// routeCacheEvictBatch caps how many expired entries a single insert reclaims,
// so eviction stays O(1)-ish rather than scanning the whole map.
const routeCacheEvictBatch = 8

func (c *routeCache) get(host string) (domain.TunnelRoute, bool) {
	route, found, cached := c.lookup(host)
	if !cached || !found {
		return domain.TunnelRoute{}, false
	}
	return route, true
}

func (c *routeCache) lookup(host string) (domain.TunnelRoute, bool, bool) {
	nowUnix := c.nowNanos()
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok {
		return domain.TunnelRoute{}, false, false
	}
	if nowUnix > e.expiresAtUnixNano {
		c.mu.Lock()
		if stale, exists := c.entries[host]; exists && nowUnix > stale.expiresAtUnixNano {
			delete(c.entries, host)
			c.untrackHostLocked(stale.route.Tunnel.ID, host)
		}
		c.mu.Unlock()
		return domain.TunnelRoute{}, false, false
	}
	return e.route, e.found, true
}

// nowNanos returns the cached monotonic timestamp if available, falling back to
// a live time.Now() call. The cached value is updated every 100ms by
// startClock, which is accurate enough for a 1-minute TTL.
func (c *routeCache) nowNanos() int64 {
	if v := c.cachedNow.Load(); v != 0 {
		return v
	}
	return time.Now().UnixNano()
}

// startClock begins a background goroutine that updates cachedNow every 100ms.
// The goroutine exits when ctx is cancelled.
func (c *routeCache) startClock(done <-chan struct{}) {
	c.cachedNow.Store(time.Now().UnixNano())
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				c.cachedNow.Store(time.Now().UnixNano())
			}
		}
	}()
}

func (c *routeCache) set(host string, route domain.TunnelRoute) {
	c.storeEntry(host, routeCacheEntry{route: route, found: true})
}

func (c *routeCache) setMiss(host string) {
	c.storeEntry(host, routeCacheEntry{found: false})
}

func (c *routeCache) storeEntry(host string, entry routeCacheEntry) {
	if host == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if prev, exists := c.entries[host]; exists {
		c.untrackHostLocked(prev.route.Tunnel.ID, host)
	} else if len(c.entries) >= c.entryLimit() {
		c.evictLocked()
	}

	entry.expiresAtUnixNano = c.nowNanos() + int64(c.cacheTTL())
	c.entries[host] = entry
	if entry.found {
		c.trackHostLocked(entry.route.Tunnel.ID, host)
	}
}

// evictLocked makes room for one new entry.
//
// A full cache used to reject inserts outright. Because negative lookups are
// cached too, a spread of unknown hostnames could fill every slot and then
// legitimate new hosts would go uncached, hitting the store on every request
// until the janitor's next sweep minutes later. Evicting instead bounds the
// damage to the entries actually displaced. Expired entries go first; failing
// that, Go's randomised map iteration gives a cheap random victim.
func (c *routeCache) evictLocked() {
	nowUnix := c.nowNanos()
	evicted := 0
	for host, e := range c.entries {
		if nowUnix > e.expiresAtUnixNano {
			delete(c.entries, host)
			c.untrackHostLocked(e.route.Tunnel.ID, host)
			evicted++
			if evicted >= routeCacheEvictBatch {
				return
			}
		}
	}
	if evicted > 0 {
		return
	}

	// Nothing expired: drop misses before hits, since a miss is cheaper to
	// recompute than an active route.
	for host, e := range c.entries {
		if !e.found {
			delete(c.entries, host)
			return
		}
	}
	for host, e := range c.entries {
		delete(c.entries, host)
		c.untrackHostLocked(e.route.Tunnel.ID, host)
		return
	}
}

func (c *routeCache) cleanup() {
	nowUnix := c.nowNanos()
	c.mu.Lock()
	defer c.mu.Unlock()
	for host, e := range c.entries {
		if nowUnix > e.expiresAtUnixNano {
			delete(c.entries, host)
			c.untrackHostLocked(e.route.Tunnel.ID, host)
		}
	}
}

// deleteHost removes a cached entry for a specific host.
func (c *routeCache) deleteHost(host string) {
	if host == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[host]; ok {
		delete(c.entries, host)
		c.untrackHostLocked(e.route.Tunnel.ID, host)
	}
}

// deleteByTunnelID removes any cached entry whose tunnel matches tunnelID.
func (c *routeCache) deleteByTunnelID(tunnelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hosts := c.hostsByTunnel[tunnelID]
	for host := range hosts {
		delete(c.entries, host)
	}
	delete(c.hostsByTunnel, tunnelID)
}

func (c *routeCache) getByTunnelID(tunnelID string) (domain.TunnelRoute, bool) {
	c.mu.RLock()
	hosts := c.hostsByTunnel[tunnelID]
	for host := range hosts {
		entry, ok := c.entries[host]
		if ok && entry.found {
			c.mu.RUnlock()
			return entry.route, true
		}
	}
	c.mu.RUnlock()
	return domain.TunnelRoute{}, false
}

func (c *routeCache) trackHostLocked(tunnelID, host string) {
	if tunnelID == "" || host == "" {
		return
	}
	if c.hostsByTunnel == nil {
		c.hostsByTunnel = make(map[string]map[string]struct{})
	}
	hosts := c.hostsByTunnel[tunnelID]
	if hosts == nil {
		hosts = make(map[string]struct{})
		c.hostsByTunnel[tunnelID] = hosts
	}
	hosts[host] = struct{}{}
}

func (c *routeCache) untrackHostLocked(tunnelID, host string) {
	if tunnelID == "" || host == "" {
		return
	}
	hosts := c.hostsByTunnel[tunnelID]
	if hosts == nil {
		return
	}
	delete(hosts, host)
	if len(hosts) == 0 {
		delete(c.hostsByTunnel, tunnelID)
	}
}

func (c *routeCache) cacheTTL() time.Duration {
	if c.ttl > 0 {
		return c.ttl
	}
	return defaultRouteCacheTTL
}

func (c *routeCache) entryLimit() int {
	if c.maxEntries > 0 {
		return c.maxEntries
	}
	return defaultRouteCacheMaxEntries
}

func (c *routeCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

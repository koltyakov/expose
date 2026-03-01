package server

import (
	"sync"
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
}

type routeCacheEntry struct {
	route             domain.TunnelRoute
	found             bool
	expiresAtUnixNano int64
}

const defaultRouteCacheTTL = time.Minute

func (c *routeCache) get(host string) (domain.TunnelRoute, bool) {
	route, found, cached := c.lookup(host)
	if !cached || !found {
		return domain.TunnelRoute{}, false
	}
	return route, true
}

func (c *routeCache) lookup(host string) (domain.TunnelRoute, bool, bool) {
	nowUnix := time.Now().UnixNano()
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

func (c *routeCache) set(host string, route domain.TunnelRoute) {
	c.mu.Lock()
	if prev, exists := c.entries[host]; exists {
		c.untrackHostLocked(prev.route.Tunnel.ID, host)
	}
	c.entries[host] = routeCacheEntry{
		route:             route,
		found:             true,
		expiresAtUnixNano: time.Now().Add(c.cacheTTL()).UnixNano(),
	}
	c.trackHostLocked(route.Tunnel.ID, host)
	c.mu.Unlock()
}

func (c *routeCache) setMiss(host string) {
	if host == "" {
		return
	}
	c.mu.Lock()
	if prev, exists := c.entries[host]; exists {
		c.untrackHostLocked(prev.route.Tunnel.ID, host)
	}
	c.entries[host] = routeCacheEntry{
		found:             false,
		expiresAtUnixNano: time.Now().Add(c.cacheTTL()).UnixNano(),
	}
	c.mu.Unlock()
}

func (c *routeCache) cleanup() {
	nowUnix := time.Now().UnixNano()
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

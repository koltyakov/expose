package server

import (
	"context"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

// siteLookupCache keeps published-site lookups for the public request path,
// which otherwise queried SQLite on every request.
//
// Publications change only through this server, which invalidates a host when
// it creates, replaces or deletes its site, and each hit is checked against
// the cached expiry. API keys are revoked by a separate CLI process, so the
// heartbeat sweep clears the cache: as with a revoked key's tunnels, its sites
// stop serving within one sweep interval.
type siteLookupCache struct {
	mu sync.RWMutex
	// gen changes on every invalidation, so a lookup that read the store
	// before one cannot cache its stale result afterwards.
	gen     uint64
	entries map[string]domain.PublishedSite
}

// get returns the cached site for host unless it has expired by now.
func (c *siteLookupCache) get(host string, now time.Time) (domain.PublishedSite, bool) {
	c.mu.RLock()
	site, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || (site.ExpiresAt != nil && !now.Before(*site.ExpiresAt)) {
		return domain.PublishedSite{}, false
	}
	return site, true
}

// generation snapshots the cache before a store lookup; see put.
func (c *siteLookupCache) generation() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.gen
}

// put caches site unless the cache was invalidated since gen was taken.
func (c *siteLookupCache) put(host string, site domain.PublishedSite, gen uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	if c.entries == nil {
		c.entries = make(map[string]domain.PublishedSite)
	}
	c.entries[host] = site
}

// invalidate forgets host after its publication changed.
func (c *siteLookupCache) invalidate(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	delete(c.entries, host)
}

// clear forgets every host, so the next request for each rereads the store.
func (c *siteLookupCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.entries = nil
}

// lookupPublishedSite resolves host through the lookup cache, falling back to
// the store. The caller holds sitesMu, which publication changes hold
// exclusively while they invalidate.
func (s *Server) lookupPublishedSite(ctx context.Context, st siteStore, host string) (domain.PublishedSite, error) {
	if site, ok := s.siteLookups.get(host, time.Now()); ok {
		return site, nil
	}
	gen := s.siteLookups.generation()
	site, err := st.FindPublishedSite(ctx, host)
	if err == nil {
		s.siteLookups.put(host, site, gen)
	}
	return site, err
}

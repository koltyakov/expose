package server

import (
	"strings"
	"sync"

	"github.com/koltyakov/expose/internal/domain"
)

type routeVersions struct {
	shards [256]routeVersionShard
}

type routeVersionShard struct {
	mu      sync.Mutex
	version uint64
}

func (v *routeVersions) current(host string) uint64 {
	host = normalizeHost(host)
	shard := v.shard(host)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	return shard.version
}

func (v *routeVersions) shard(host string) *routeVersionShard {
	const (
		fnvOffset32 = uint32(2166136261)
		fnvPrime32  = uint32(16777619)
	)
	hash := fnvOffset32
	for idx := 0; idx < len(host); idx++ {
		hash ^= uint32(host[idx])
		hash *= fnvPrime32
	}
	return &v.shards[hash%uint32(len(v.shards))]
}

func (s *Server) publishRegisteredRoute(route domain.TunnelRoute) {
	host := normalizeHost(route.Domain.Hostname)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	shard.version++
	s.routes.set(host, route)
	shard.mu.Unlock()
}

func (s *Server) publishResolvedRoute(host string, version uint64, route domain.TunnelRoute) (liveRouteSnapshot, bool) {
	host = normalizeHost(host)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.version != version {
		if snap, ok := s.liveRoutes.lookupHost(host); ok {
			return snap, false
		}
		if cached, found, ok := s.routes.lookup(host); ok && found {
			return liveRouteSnapshot{route: cached}, false
		}
		return liveRouteSnapshot{}, false
	}
	s.routes.set(host, route)
	return liveRouteSnapshot{route: route}, true
}

func (s *Server) publishRouteMiss(host string, version uint64) bool {
	host = normalizeHost(host)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.version != version {
		return false
	}
	s.routes.setMiss(host)
	return true
}

func (s *Server) removePublishedRoute(host, domainID string) {
	host = normalizeHost(host)
	domainID = strings.TrimSpace(domainID)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	shard.version++
	if domainID != "" {
		s.liveRoutes.deleteHostIfDomain(host, domainID)
	} else {
		s.liveRoutes.deleteHost(host)
	}
	s.routes.deleteHost(host)
	shard.mu.Unlock()
}

func (s *Server) attachPublishedSession(tunnelID string, sess *session) {
	snap, ok := s.liveRoutes.lookupTunnel(tunnelID)
	if !ok {
		if route, cached := s.routes.getByTunnelID(tunnelID); cached {
			s.liveRoutes.upsert(route)
			snap, ok = s.liveRoutes.lookupTunnel(tunnelID)
		}
		if !ok {
			return
		}
	}
	host := normalizeHost(snap.route.Domain.Hostname)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	shard.version++
	if attached, ok := s.liveRoutes.attachSession(tunnelID, sess); ok {
		s.routes.set(host, attached.route)
	}
	shard.mu.Unlock()
}

func (s *Server) clearPublishedSession(tunnelID string, sess *session) bool {
	snap, ok := s.liveRoutes.lookupTunnel(tunnelID)
	if !ok {
		return false
	}
	host := normalizeHost(snap.route.Domain.Hostname)
	shard := s.routeVersions.shard(host)
	shard.mu.Lock()
	shard.version++
	cleared, ok := s.liveRoutes.clearSession(tunnelID, sess)
	if ok {
		s.routes.set(host, cleared.route)
		s.liveRoutes.deleteHostIfDomain(host, cleared.route.Domain.ID)
	}
	shard.mu.Unlock()
	return ok
}

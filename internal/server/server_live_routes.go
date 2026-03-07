package server

import (
	"context"
	"database/sql"
	"strings"
	"sync"

	"github.com/koltyakov/expose/internal/domain"
)

const liveRouteShardCount = 64

type liveRouteIndex struct {
	hostShards   [liveRouteShardCount]liveRouteShard
	tunnelShards [liveRouteShardCount]liveTunnelShard
}

type liveRouteShard struct {
	mu      sync.RWMutex
	byHost  map[string]*liveRouteEntry
	byKeyID map[string]map[string]struct{}
}

type liveTunnelShard struct {
	mu       sync.RWMutex
	byTunnel map[string]*liveRouteEntry
}

type liveRouteEntry struct {
	host               string
	domainID           string
	tunnelID           string
	keyID              string
	isTemporary        bool
	accessUser         string
	accessMode         string
	accessPasswordHash string
	active             bool
	session            *session
}

type liveRouteSnapshot struct {
	route   domain.TunnelRoute
	session *session
	active  bool
}

func newLiveRouteIndex() *liveRouteIndex {
	idx := &liveRouteIndex{}
	for i := range idx.hostShards {
		idx.hostShards[i] = liveRouteShard{
			byHost:  make(map[string]*liveRouteEntry),
			byKeyID: make(map[string]map[string]struct{}),
		}
	}
	for i := range idx.tunnelShards {
		idx.tunnelShards[i] = liveTunnelShard{
			byTunnel: make(map[string]*liveRouteEntry),
		}
	}
	return idx
}

func (i *liveRouteIndex) upsert(route domain.TunnelRoute) {
	if i == nil {
		return
	}
	host := normalizeHost(route.Domain.Hostname)
	tunnelID := strings.TrimSpace(route.Tunnel.ID)
	if host == "" || tunnelID == "" {
		return
	}
	hostShard := &i.hostShards[liveRouteShardIndex(host)]
	tunnelShard := &i.tunnelShards[liveRouteShardIndex(tunnelID)]

	hostShard.mu.Lock()
	defer hostShard.mu.Unlock()
	tunnelShard.mu.Lock()
	defer tunnelShard.mu.Unlock()

	entry := hostShard.byHost[host]
	if entry == nil {
		entry = &liveRouteEntry{
			host:     host,
			domainID: route.Domain.ID,
			tunnelID: tunnelID,
			keyID:    route.Domain.APIKeyID,
		}
		hostShard.byHost[host] = entry
		tunnelShard.byTunnel[tunnelID] = entry
	} else {
		if entry.tunnelID != "" && entry.tunnelID != tunnelID {
			delete(tunnelShard.byTunnel, entry.tunnelID)
		}
		tunnelShard.byTunnel[tunnelID] = entry
	}
	i.untrackHostKeyLocked(hostShard, entry.keyID, host)
	entry.host = host
	entry.domainID = route.Domain.ID
	entry.tunnelID = tunnelID
	entry.keyID = route.Domain.APIKeyID
	entry.isTemporary = route.Tunnel.IsTemporary
	entry.accessUser = route.Tunnel.AccessUser
	entry.accessMode = route.Tunnel.AccessMode
	entry.accessPasswordHash = route.Tunnel.AccessPasswordHash
	if route.Tunnel.State != domain.TunnelStateConnected {
		entry.active = false
		entry.session = nil
	}
	i.trackHostKeyLocked(hostShard, entry.keyID, host)
}

func (i *liveRouteIndex) upsertFromStore(ctx context.Context, store serverStore, host string) (liveRouteSnapshot, error) {
	if i == nil || store == nil {
		return liveRouteSnapshot{}, sql.ErrNoRows
	}
	route, err := store.FindRouteByHost(ctx, host)
	if err != nil {
		return liveRouteSnapshot{}, err
	}
	i.upsert(route)
	if snap, ok := i.lookupHost(host); ok {
		return snap, nil
	}
	return liveRouteSnapshot{route: route}, nil
}

func (i *liveRouteIndex) upsertTunnelFromStore(ctx context.Context, store serverStore, tunnelID string) (liveRouteSnapshot, error) {
	if i == nil || store == nil {
		return liveRouteSnapshot{}, sql.ErrNoRows
	}
	route, err := store.FindRouteByTunnelID(ctx, tunnelID)
	if err != nil {
		return liveRouteSnapshot{}, err
	}
	i.upsert(route)
	if snap, ok := i.lookupTunnel(tunnelID); ok {
		return snap, nil
	}
	return liveRouteSnapshot{route: route}, nil
}

func (i *liveRouteIndex) lookupHost(host string) (liveRouteSnapshot, bool) {
	if i == nil {
		return liveRouteSnapshot{}, false
	}
	host = normalizeHost(host)
	if host == "" {
		return liveRouteSnapshot{}, false
	}
	shard := &i.hostShards[liveRouteShardIndex(host)]
	shard.mu.RLock()
	entry := shard.byHost[host]
	if entry == nil {
		shard.mu.RUnlock()
		return liveRouteSnapshot{}, false
	}
	snap := snapshotFromEntry(entry)
	shard.mu.RUnlock()
	return snap, true
}

func (i *liveRouteIndex) lookupTunnel(tunnelID string) (liveRouteSnapshot, bool) {
	if i == nil {
		return liveRouteSnapshot{}, false
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return liveRouteSnapshot{}, false
	}
	shard := &i.tunnelShards[liveRouteShardIndex(tunnelID)]
	shard.mu.RLock()
	entry := shard.byTunnel[tunnelID]
	if entry == nil {
		shard.mu.RUnlock()
		return liveRouteSnapshot{}, false
	}
	snap := snapshotFromEntry(entry)
	shard.mu.RUnlock()
	return snap, true
}

func (i *liveRouteIndex) attachSession(tunnelID string, sess *session) (liveRouteSnapshot, bool) {
	if i == nil || sess == nil {
		return liveRouteSnapshot{}, false
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return liveRouteSnapshot{}, false
	}
	shard := &i.tunnelShards[liveRouteShardIndex(tunnelID)]
	shard.mu.Lock()
	entry := shard.byTunnel[tunnelID]
	if entry == nil {
		shard.mu.Unlock()
		return liveRouteSnapshot{}, false
	}
	entry.session = sess
	entry.active = true
	snap := snapshotFromEntry(entry)
	shard.mu.Unlock()
	return snap, true
}

func (i *liveRouteIndex) clearSession(tunnelID string, sess *session) (liveRouteSnapshot, bool) {
	if i == nil {
		return liveRouteSnapshot{}, false
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return liveRouteSnapshot{}, false
	}
	shard := &i.tunnelShards[liveRouteShardIndex(tunnelID)]
	shard.mu.Lock()
	entry := shard.byTunnel[tunnelID]
	if entry == nil {
		shard.mu.Unlock()
		return liveRouteSnapshot{}, false
	}
	if sess != nil && entry.session != sess {
		snap := snapshotFromEntry(entry)
		shard.mu.Unlock()
		return snap, false
	}
	entry.session = nil
	if entry.isTemporary {
		entry.active = false
	}
	snap := snapshotFromEntry(entry)
	shard.mu.Unlock()
	return snap, true
}

func (i *liveRouteIndex) setAccess(tunnelID, user, mode, hash string) {
	if i == nil {
		return
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return
	}
	shard := &i.tunnelShards[liveRouteShardIndex(tunnelID)]
	shard.mu.Lock()
	if entry := shard.byTunnel[tunnelID]; entry != nil {
		entry.accessUser = strings.TrimSpace(user)
		entry.accessMode = strings.TrimSpace(mode)
		entry.accessPasswordHash = strings.TrimSpace(hash)
	}
	shard.mu.Unlock()
}

func (i *liveRouteIndex) hostsForTunnel(tunnelID string) []string {
	if i == nil {
		return nil
	}
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return nil
	}
	if snap, ok := i.lookupTunnel(tunnelID); ok {
		return []string{snap.route.Domain.Hostname}
	}
	return nil
}

func (i *liveRouteIndex) snapshotSessions() []*session {
	if i == nil {
		return nil
	}
	seen := make(map[*session]struct{})
	out := make([]*session, 0)
	for idx := range i.tunnelShards {
		shard := &i.tunnelShards[idx]
		shard.mu.RLock()
		for _, entry := range shard.byTunnel {
			if entry == nil || entry.session == nil {
				continue
			}
			if _, ok := seen[entry.session]; ok {
				continue
			}
			seen[entry.session] = struct{}{}
			out = append(out, entry.session)
		}
		shard.mu.RUnlock()
	}
	return out
}

func (i *liveRouteIndex) trackHostKeyLocked(shard *liveRouteShard, keyID, host string) {
	keyID = strings.TrimSpace(keyID)
	if shard == nil || keyID == "" || host == "" {
		return
	}
	hosts := shard.byKeyID[keyID]
	if hosts == nil {
		hosts = make(map[string]struct{})
		shard.byKeyID[keyID] = hosts
	}
	hosts[host] = struct{}{}
}

func (i *liveRouteIndex) untrackHostKeyLocked(shard *liveRouteShard, keyID, host string) {
	keyID = strings.TrimSpace(keyID)
	if shard == nil || keyID == "" || host == "" {
		return
	}
	hosts := shard.byKeyID[keyID]
	if hosts == nil {
		return
	}
	delete(hosts, host)
	if len(hosts) == 0 {
		delete(shard.byKeyID, keyID)
	}
}

func liveRouteShardIndex(key string) int {
	const prime = uint64(1099511628211)
	var hash uint64 = 1469598103934665603
	for i := 0; i < len(key); i++ {
		hash ^= uint64(key[i])
		hash *= prime
	}
	return int(hash % liveRouteShardCount)
}

func snapshotFromEntry(entry *liveRouteEntry) liveRouteSnapshot {
	if entry == nil {
		return liveRouteSnapshot{}
	}
	return liveRouteSnapshot{
		route: domain.TunnelRoute{
			Domain: domain.Domain{
				ID:       entry.domainID,
				APIKeyID: entry.keyID,
				Hostname: entry.host,
			},
			Tunnel: domain.Tunnel{
				ID:                 entry.tunnelID,
				APIKeyID:           entry.keyID,
				DomainID:           entry.domainID,
				IsTemporary:        entry.isTemporary,
				State:              tunnelStateForEntry(entry),
				AccessUser:         entry.accessUser,
				AccessMode:         entry.accessMode,
				AccessPasswordHash: entry.accessPasswordHash,
			},
		},
		session: entry.session,
		active:  entry.active,
	}
}

func tunnelStateForEntry(entry *liveRouteEntry) string {
	if entry == nil {
		return ""
	}
	if entry.active {
		return domain.TunnelStateConnected
	}
	return domain.TunnelStateDisconnected
}

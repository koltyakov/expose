package server

import (
	"context"
	"strings"
	"sync"
	"time"
)

type apiKeyLimitStore interface {
	GetAPIKeyTunnelLimit(ctx context.Context, keyID string) (int, error)
}

// keyLimitTTL controls how long a cached tunnel limit is considered valid.
const keyLimitTTL = 5 * time.Minute

type cachedLimit struct {
	limit     int
	expiresAt time.Time
}

type activeTunnelTracker struct {
	mu          sync.RWMutex
	keyCounts   map[string]int
	keyLimits   map[string]cachedLimit
	tunnelToKey map[string]string
}

func newActiveTunnelTracker() *activeTunnelTracker {
	return &activeTunnelTracker{
		keyCounts:   make(map[string]int),
		keyLimits:   make(map[string]cachedLimit),
		tunnelToKey: make(map[string]string),
	}
}

func (t *activeTunnelTracker) activeCount(keyID string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.keyCounts[strings.TrimSpace(keyID)]
}

func (t *activeTunnelTracker) limitFor(ctx context.Context, store apiKeyLimitStore, keyID string) (int, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return -1, nil
	}
	now := time.Now()
	t.mu.RLock()
	cached, ok := t.keyLimits[keyID]
	t.mu.RUnlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.limit, nil
	}
	if store == nil {
		return -1, nil
	}
	limit, err := store.GetAPIKeyTunnelLimit(ctx, keyID)
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	t.keyLimits[keyID] = cachedLimit{limit: limit, expiresAt: now.Add(keyLimitTTL)}
	t.mu.Unlock()
	return limit, nil
}

func (t *activeTunnelTracker) canConnect(keyID, tunnelID string, limit int) bool {
	keyID = strings.TrimSpace(keyID)
	tunnelID = strings.TrimSpace(tunnelID)
	if keyID == "" || tunnelID == "" {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if currentKey, ok := t.tunnelToKey[tunnelID]; ok && currentKey == keyID {
		return true
	}
	if limit < 0 {
		return true
	}
	return t.keyCounts[keyID] < limit
}

func (t *activeTunnelTracker) markConnected(keyID, tunnelID string) {
	keyID = strings.TrimSpace(keyID)
	tunnelID = strings.TrimSpace(tunnelID)
	if keyID == "" || tunnelID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if currentKey, ok := t.tunnelToKey[tunnelID]; ok {
		if currentKey == keyID {
			return
		}
		t.keyCounts[currentKey]--
	}
	t.tunnelToKey[tunnelID] = keyID
	t.keyCounts[keyID]++
}

func (t *activeTunnelTracker) markDisconnected(tunnelID string) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	keyID, ok := t.tunnelToKey[tunnelID]
	if !ok {
		return
	}
	delete(t.tunnelToKey, tunnelID)
	if keyID == "" {
		return
	}
	t.keyCounts[keyID]--
	if t.keyCounts[keyID] <= 0 {
		delete(t.keyCounts, keyID)
	}
}

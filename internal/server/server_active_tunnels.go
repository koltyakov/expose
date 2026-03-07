package server

import (
	"context"
	"strings"
	"sync"
)

type apiKeyLimitStore interface {
	GetAPIKeyTunnelLimit(ctx context.Context, keyID string) (int, error)
}

type activeTunnelTracker struct {
	mu          sync.Mutex
	keyCounts   map[string]int
	keyLimits   map[string]int
	tunnelToKey map[string]string
}

func newActiveTunnelTracker() *activeTunnelTracker {
	return &activeTunnelTracker{
		keyCounts:   make(map[string]int),
		keyLimits:   make(map[string]int),
		tunnelToKey: make(map[string]string),
	}
}

func (t *activeTunnelTracker) activeCount(keyID string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.keyCounts[strings.TrimSpace(keyID)]
}

func (t *activeTunnelTracker) limitFor(ctx context.Context, store apiKeyLimitStore, keyID string) (int, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return -1, nil
	}
	t.mu.Lock()
	limit, ok := t.keyLimits[keyID]
	t.mu.Unlock()
	if ok {
		return limit, nil
	}
	if store == nil {
		return -1, nil
	}
	limit, err := store.GetAPIKeyTunnelLimit(ctx, keyID)
	if err != nil {
		return 0, err
	}
	t.mu.Lock()
	t.keyLimits[keyID] = limit
	t.mu.Unlock()
	return limit, nil
}

func (t *activeTunnelTracker) canConnect(keyID, tunnelID string, limit int) bool {
	keyID = strings.TrimSpace(keyID)
	tunnelID = strings.TrimSpace(tunnelID)
	if keyID == "" || tunnelID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
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

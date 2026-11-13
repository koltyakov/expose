package server

import (
	"net/http"
	"sync"

	"github.com/koltyakov/expose/internal/config"
)

// siteUploadLimiter admits without queuing. Only active keys are retained.
// Its zero value is ready for use.
type siteUploadLimiter struct {
	mu     sync.Mutex
	active int
	byKey  map[string]int
}

func (l *siteUploadLimiter) acquire(key string, totalLimit, perKeyLimit int) (func(), int) {
	if totalLimit <= 0 {
		totalLimit = config.DefaultPublishMaxConcurrentUploads
	}
	if perKeyLimit <= 0 {
		perKeyLimit = config.DefaultPublishMaxConcurrentUploadsPerKey
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byKey[key] >= perKeyLimit {
		return nil, http.StatusTooManyRequests
	}
	if l.active >= totalLimit {
		return nil, http.StatusServiceUnavailable
	}
	if l.byKey == nil {
		l.byKey = make(map[string]int)
	}
	l.active++
	l.byKey[key]++
	return sync.OnceFunc(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.active--
		l.byKey[key]--
		if l.byKey[key] == 0 {
			delete(l.byKey, key)
		}
	}), 0
}

package server

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

const siteManifestCacheEntries = 128
const siteManifestCacheBytes = 8 << 20

// Cache the encoded manifest by immutable storage ID. Bounding retained capacity and
// entries keeps sites with many files or long paths from growing this cache
// indefinitely. Returned bytes are read-only and remain valid after eviction.
type siteManifestCache struct {
	mu      sync.Mutex
	entries map[string][]byte
	bytes   int
	loads   lookupGroup[[]byte]
}

func (c *siteManifestCache) get(id string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, ok := c.entries[id]
	return data, ok
}

func (c *siteManifestCache) put(id string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= cap(c.entries[id])
	delete(c.entries, id)
	if cap(data) > siteManifestCacheBytes {
		return
	}
	for len(c.entries) >= siteManifestCacheEntries || c.bytes+cap(data) > siteManifestCacheBytes {
		for key, previous := range c.entries {
			c.bytes -= cap(previous)
			delete(c.entries, key)
			break
		}
	}
	if c.entries == nil {
		c.entries = make(map[string][]byte)
	}
	c.entries[id] = data
	c.bytes += cap(data)
}

func (c *siteManifestCache) delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= cap(c.entries[id])
	delete(c.entries, id)
}

// The caller holds sitesMu until this returns, keeping the directory alive.
func (s *Server) publishedManifest(site domain.PublishedSite) ([]byte, error) {
	id := site.StorageID()
	if data, ok := s.siteManifests.get(id); ok {
		return data, nil
	}
	// Wait for the shared load even if the HTTP request is canceled: releasing
	// sitesMu while the loader is still hashing would allow directory removal.
	return s.siteManifests.loads.do(context.Background(), id, func() ([]byte, error) {
		if data, ok := s.siteManifests.get(id); ok {
			return data, nil
		}
		files, err := publish.Manifest(filepath.Join(s.publishDir(), id))
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(files)
		if err != nil {
			return nil, err
		}
		data = append(data, '\n')
		s.siteManifests.put(id, data)
		return data, nil
	})
}

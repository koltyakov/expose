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
	entries map[string]siteManifestEntry
	bytes   int
	loads   lookupGroup[[]byte]
}

type siteManifestEntry struct {
	data      []byte
	fileCount int
	fileBytes int64
}

func (c *siteManifestCache) get(id string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	return entry.data, ok
}

// fileTotals returns the cached manifest's file count and bytes.
func (c *siteManifestCache) fileTotals(id string) (int, int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[id]
	return entry.fileCount, entry.fileBytes, ok
}

func (c *siteManifestCache) put(id string, entry siteManifestEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= cap(c.entries[id].data)
	delete(c.entries, id)
	if cap(entry.data) > siteManifestCacheBytes {
		return
	}
	for len(c.entries) >= siteManifestCacheEntries || c.bytes+cap(entry.data) > siteManifestCacheBytes {
		for key, previous := range c.entries {
			c.bytes -= cap(previous.data)
			delete(c.entries, key)
			break
		}
	}
	if c.entries == nil {
		c.entries = make(map[string]siteManifestEntry)
	}
	c.entries[id] = entry
	c.bytes += cap(entry.data)
}

func (c *siteManifestCache) delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes -= cap(c.entries[id].data)
	delete(c.entries, id)
}

// encodeSiteManifest encodes files as the files listing body together with
// their totals.
func encodeSiteManifest(files []domain.PublishedFile) (siteManifestEntry, error) {
	data, err := json.Marshal(files)
	if err != nil {
		return siteManifestEntry{}, err
	}
	entry := siteManifestEntry{data: append(data, '\n'), fileCount: len(files)}
	for _, file := range files {
		entry.fileBytes += file.Size
	}
	return entry, nil
}

// primeSiteManifest returns totals for a verified upload, even if the manifest
// is too large for the listing cache.
func (s *Server) primeSiteManifest(id string, files []domain.PublishedFile) (int, int64, bool) {
	if len(files) == 0 {
		return 0, 0, false
	}
	entry, err := encodeSiteManifest(files)
	if err != nil {
		return 0, 0, false
	}
	s.siteManifests.put(id, entry)
	return entry.fileCount, entry.fileBytes, true
}

// cachedManifest returns the cached manifest for id without loading it.
func (s *Server) cachedManifest(id string) []domain.PublishedFile {
	data, ok := s.siteManifests.get(id)
	if !ok {
		return nil
	}
	var files []domain.PublishedFile
	if json.Unmarshal(data, &files) != nil {
		return nil
	}
	return files
}

// precompressSite writes gzip variants into an unpublished directory. They
// are optional: a failure is logged and the site is served uncompressed.
func (s *Server) precompressSite(dir, baseDir string, maxBytes int64) {
	if err := publish.Precompress(dir, baseDir, maxBytes); err != nil && s.log != nil {
		s.log.Warn("precompress published site", "err", err)
	}
}

// siteManifestFiles hashes a revision; tests replace it to hold hashing open.
var siteManifestFiles = publish.Manifest

// publishedManifest returns the encoded manifest of site's revision. On a
// cache miss it hashes every file, so callers pin the revision directory
// (pinSiteDir) and release sitesMu first. A revision retired while it was
// being hashed is still returned, matching the caller's snapshot, but is not
// cached.
func (s *Server) publishedManifest(site domain.PublishedSite) ([]byte, error) {
	id := site.StorageID()
	if data, ok := s.siteManifests.get(id); ok {
		return data, nil
	}
	// Wait for the shared load even if the HTTP request is canceled: the
	// caller's pin is what keeps the directory alive while it is hashed.
	return s.siteManifests.loads.do(context.Background(), id, func() ([]byte, error) {
		if data, ok := s.siteManifests.get(id); ok {
			return data, nil
		}
		dir := filepath.Join(s.publishDir(), id)
		files, err := siteManifestFiles(dir)
		if err != nil {
			return nil, err
		}
		entry, err := encodeSiteManifest(files)
		if err != nil {
			return nil, err
		}
		s.unlessSiteDirRetired(dir, func() { s.siteManifests.put(id, entry) })
		return entry.data, nil
	})
}

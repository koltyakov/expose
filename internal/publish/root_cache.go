package publish

import (
	"os"
	"sync"
	"sync/atomic"
)

// RootCache keeps publication directories open across requests. Each upload
// gets a new directory that never changes afterwards, so a root opened once
// stays valid until the directory is deleted. Reopening it was the largest
// per-request cost of serving a small published file.
//
// Callers must Close a directory before deleting it, once no request is
// serving it. A nil *RootCache opens the directory for every request.
type RootCache struct {
	roots sync.Map // directory -> *os.Root
	count atomic.Int64
	max   int64
}

// NewRootCache returns a cache holding at most max open directories. Requests
// for further directories open them per request, as without a cache.
func NewRootCache(max int) *RootCache {
	return &RootCache{max: int64(max)}
}

// open returns the root for dir. When cached is false the caller owns root and
// must close it.
func (c *RootCache) open(dir string) (root *os.Root, cached bool, err error) {
	if c != nil {
		if existing, ok := c.roots.Load(dir); ok {
			return existing.(*os.Root), true, nil
		}
	}
	root, err = os.OpenRoot(dir)
	if err != nil || c == nil {
		return root, false, err
	}
	if c.count.Add(1) > c.max {
		c.count.Add(-1)
		return root, false, nil
	}
	if existing, loaded := c.roots.LoadOrStore(dir, root); loaded {
		c.count.Add(-1)
		_ = root.Close()
		return existing.(*os.Root), true, nil
	}
	return root, true, nil
}

// Len reports how many directories the cache holds open.
func (c *RootCache) Len() int {
	if c == nil {
		return 0
	}
	return int(c.count.Load())
}

// Close closes and forgets the cached root for dir, if there is one.
func (c *RootCache) Close(dir string) {
	if c == nil {
		return
	}
	if existing, ok := c.roots.LoadAndDelete(dir); ok {
		c.count.Add(-1)
		_ = existing.(*os.Root).Close()
	}
}

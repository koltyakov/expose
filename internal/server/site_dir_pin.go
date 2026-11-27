package server

import (
	"os"
	"sync"
)

type siteDirPin struct {
	readers int
	retired bool
}

// siteDirPinSet keeps unpublished revision directories alive for readers that
// work on them outside sitesMu: delta preparation, manifest hashing and file
// totals. Its own mutex lets readers pin under the shared sitesMu.
//
// Lock order is sitesMu, then mu. A pin is created only while sitesMu is held
// in either mode, right after confirming the revision is published. Retirement
// runs with sitesMu held exclusively, so once it sees no pin, none can appear.
// Releasing a pin needs only mu.
type siteDirPinSet struct {
	mu   sync.Mutex
	dirs map[string]*siteDirPin
}

// pinSiteDir is called with sitesMu held, shared or exclusive, for a published
// revision. Release the pin without holding sitesMu; it is safe to call more
// than once.
func (s *Server) pinSiteDir(dir string) func() {
	pins := &s.siteDirPins
	pins.mu.Lock()
	if pins.dirs == nil {
		pins.dirs = make(map[string]*siteDirPin)
	}
	p := pins.dirs[dir]
	if p == nil {
		p = new(siteDirPin)
		pins.dirs[dir] = p
	}
	p.readers++
	pins.mu.Unlock()
	return sync.OnceFunc(func() {
		pins.mu.Lock()
		p.readers--
		last := p.readers == 0
		if last {
			delete(pins.dirs, dir)
		}
		remove := last && p.retired
		pins.mu.Unlock()
		if remove {
			s.removeRetiredSiteDir(dir)
		}
	})
}

// deferPinnedRemoval is called with sitesMu held exclusively once dir is no
// longer published. It reports whether the last reader will remove dir.
func (s *Server) deferPinnedRemoval(dir string) bool {
	s.siteDirPins.mu.Lock()
	defer s.siteDirPins.mu.Unlock()
	if p := s.siteDirPins.dirs[dir]; p != nil {
		p.retired = true
		return true
	}
	return false
}

// siteDirPinned reports whether a reader holds dir.
func (s *Server) siteDirPinned(dir string) bool {
	s.siteDirPins.mu.Lock()
	defer s.siteDirPins.mu.Unlock()
	return s.siteDirPins.dirs[dir] != nil
}

// unlessSiteDirRetired runs cache unless dir has been retired. A reader that
// derived metadata from a pinned revision stores it this way, so a deletion
// or replacement that raced the read does not resurrect cached state:
// retirement marks the pin before dropping caches (see retireSiteRevision).
func (s *Server) unlessSiteDirRetired(dir string, cache func()) {
	s.siteDirPins.mu.Lock()
	defer s.siteDirPins.mu.Unlock()
	if p := s.siteDirPins.dirs[dir]; p != nil && p.retired {
		return
	}
	cache()
}

// removeSiteDir is os.RemoveAll; tests replace it to hold a removal open.
var removeSiteDir = os.RemoveAll

func (s *Server) removeRetiredSiteDir(dir string) {
	if err := removeSiteDir(dir); err != nil && s.log != nil {
		s.log.Warn("remove retired site files", "dir", dir, "err", err)
	}
}

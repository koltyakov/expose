package server

import "os"

type siteDirPin struct {
	readers int
	retired bool
}

// pinSiteDir is called with sitesMu held. Release the pin without holding it.
func (s *Server) pinSiteDir(dir string) func() {
	if s.siteDirPins == nil {
		s.siteDirPins = make(map[string]*siteDirPin)
	}
	p := s.siteDirPins[dir]
	if p == nil {
		p = new(siteDirPin)
		s.siteDirPins[dir] = p
	}
	p.readers++
	return func() {
		s.sitesMu.Lock()
		p.readers--
		last := p.readers == 0
		if last {
			delete(s.siteDirPins, dir)
		}
		remove := last && p.retired
		s.sitesMu.Unlock()
		if remove {
			s.removeRetiredSiteDir(dir)
		}
	}
}

// Called under sitesMu after the directory is no longer published.
func (s *Server) deferPinnedRemoval(dir string) bool {
	if p := s.siteDirPins[dir]; p != nil {
		p.retired = true
		return true
	}
	return false
}

// removeSiteDir is os.RemoveAll; tests replace it to hold a removal open.
var removeSiteDir = os.RemoveAll

func (s *Server) removeRetiredSiteDir(dir string) {
	if err := removeSiteDir(dir); err != nil && s.log != nil {
		s.log.Warn("remove retired site files", "dir", dir, "err", err)
	}
}

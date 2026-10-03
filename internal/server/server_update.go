package server

import (
	"time"

	"github.com/koltyakov/expose/internal/selfupdate"
)

const clientUpdateCheckCooldown = time.Minute

// UpdateChecks signals that a newer client registered. The receiver should
// check for an update using the server's auto-update policy.
func (s *Server) UpdateChecks() <-chan struct{} {
	return s.updateChecks
}

func (s *Server) notifyNewerClient(clientVersion string) {
	if !selfupdate.IsNewer(s.version, clientVersion) {
		return
	}
	s.updateCheckMu.Lock()
	defer s.updateCheckMu.Unlock()
	if time.Since(s.lastUpdateCheck) < clientUpdateCheckCooldown {
		return
	}
	select {
	case s.updateChecks <- struct{}{}:
		s.lastUpdateCheck = time.Now()
	default:
	}
}

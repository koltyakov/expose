package sqlite

import (
	"context"
	"strings"
	"time"
)

func (s *Store) TouchDomain(ctx context.Context, domainID string) error {
	now := time.Now().UTC()
	if !s.reserveDomainTouch(domainID, now) {
		return nil
	}

	_, err := s.db.ExecContext(ctx, `UPDATE domains SET last_seen_at = ? WHERE id = ?`, now, domainID)
	if err != nil {
		s.rollbackDomainTouch(domainID, now)
	}
	return err
}

func (s *Store) reserveDomainTouch(domainID string, now time.Time) bool {
	domainID = strings.TrimSpace(domainID)
	if domainID == "" {
		return false
	}

	s.touchMu.Lock()
	defer s.touchMu.Unlock()

	if now.After(s.nextTouchCleanupAt) {
		s.cleanupStaleTouchEntriesLocked(now)
		s.nextTouchCleanupAt = now.Add(s.touchCleanupInterval)
	}
	if last, ok := s.lastDomainTouch[domainID]; ok && now.Sub(last) < s.touchMinInterval {
		return false
	}
	s.lastDomainTouch[domainID] = now
	return true
}

func (s *Store) rollbackDomainTouch(domainID string, reservedAt time.Time) {
	s.touchMu.Lock()
	defer s.touchMu.Unlock()

	if last, ok := s.lastDomainTouch[domainID]; ok && last.Equal(reservedAt) {
		delete(s.lastDomainTouch, domainID)
	}
}

func (s *Store) cleanupStaleTouchEntriesLocked(now time.Time) {
	cutoff := now.Add(-(s.touchMinInterval * 4))
	for domainID, last := range s.lastDomainTouch {
		if last.Before(cutoff) {
			delete(s.lastDomainTouch, domainID)
		}
	}
}

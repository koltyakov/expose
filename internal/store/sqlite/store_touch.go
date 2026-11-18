package sqlite

import (
	"context"
	"strings"
	"time"
)

func (s *Store) TouchDomain(ctx context.Context, domainID string) error {
	return s.TouchDomains(ctx, []string{domainID})
}

func (s *Store) TouchDomains(ctx context.Context, ids []string) error {
	s.writerGate.RLock()
	if s.closing {
		s.writerGate.RUnlock()
		return ErrStoreClosed
	}
	now := time.Now().UTC()
	reserved := s.reserveDomainTouches(ids, now)
	if len(reserved) == 0 {
		s.writerGate.RUnlock()
		return nil
	}

	req := storeTouchRequest{
		ids:  reserved,
		done: acquireStoreWriteCompletion(),
	}
	select {
	case s.touchRequests <- req:
		s.writerGate.RUnlock()
	case <-ctx.Done():
		s.writerGate.RUnlock()
		releaseStoreWriteCompletion(req.done)
		for _, id := range reserved {
			s.rollbackDomainTouch(id, now)
		}
		return ctx.Err()
	}

	select {
	case err := <-req.done.ch:
		releaseStoreWriteCompletion(req.done)
		if err != nil {
			for _, id := range reserved {
				s.rollbackDomainTouch(id, now)
			}
		}
		return err
	case <-ctx.Done():
		// The writer may still flush this touch; keep the reservation intact.
		return ctx.Err()
	}
}

func (s *Store) reserveDomainTouches(ids []string, now time.Time) []string {
	s.touchMu.Lock()
	defer s.touchMu.Unlock()

	if now.After(s.nextTouchCleanupAt) {
		s.cleanupStaleTouchEntriesLocked(now)
		s.nextTouchCleanupAt = now.Add(s.touchCleanupInterval)
	}
	var reserved []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if last, ok := s.lastDomainTouch[id]; ok && now.Sub(last) < s.touchMinInterval {
			continue
		}
		s.lastDomainTouch[id] = now
		reserved = append(reserved, id)
	}
	return reserved
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

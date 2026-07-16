package sqlite

import (
	"context"
	"strings"
	"time"
)

func (s *Store) TouchDomain(ctx context.Context, domainID string) error {
	s.writerGate.RLock()
	if s.closing {
		s.writerGate.RUnlock()
		return ErrStoreClosed
	}
	now := time.Now().UTC()
	if !s.reserveDomainTouch(domainID, now) {
		s.writerGate.RUnlock()
		return nil
	}

	req := storeTouchRequest{
		ctx:      ctx,
		domainID: domainID,
		done:     acquireStoreWriteCompletion(),
	}
	select {
	case s.touchRequests <- req:
		s.writerGate.RUnlock()
	case <-ctx.Done():
		s.writerGate.RUnlock()
		releaseStoreWriteCompletion(req.done)
		return ctx.Err()
	}

	select {
	case err := <-req.done.ch:
		releaseStoreWriteCompletion(req.done)
		if err != nil {
			s.rollbackDomainTouch(domainID, now)
		}
		return err
	case <-ctx.Done():
		// The writer may still flush this touch; keep the reservation intact.
		return ctx.Err()
	}
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

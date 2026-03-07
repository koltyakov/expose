package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	sqliteBusyRetryMaxAttempts = 6
	sqliteBusyRetryInitialWait = 10 * time.Millisecond
	sqliteBusyRetryMaxWait     = 250 * time.Millisecond
)

type storeWriteRequest struct {
	ctx  context.Context
	op   func() error
	done *storeWriteCompletion
}

type storeTouchRequest struct {
	ctx      context.Context
	domainID string
	done     *storeWriteCompletion
}

type storeWriteCompletion struct {
	ch chan error
}

var storeWriteCompletionPool = sync.Pool{
	New: func() any {
		return &storeWriteCompletion{ch: make(chan error, 1)}
	},
}

func withSQLiteBusyRetry(ctx context.Context, op func() error) error {
	if op == nil {
		return nil
	}

	wait := sqliteBusyRetryInitialWait
	var lastErr error
	for attempt := 0; attempt <= sqliteBusyRetryMaxAttempts; attempt++ {
		lastErr = op()
		if !isSQLiteBusyError(lastErr) {
			return lastErr
		}
		if attempt == sqliteBusyRetryMaxAttempts {
			return lastErr
		}
		if err := waitForContext(ctx, wait); err != nil {
			return err
		}
		wait = min(wait*2, sqliteBusyRetryMaxWait)
	}
	return lastErr
}

func (s *Store) execWithSQLiteBusyRetry(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var (
		res sql.Result
		err error
	)
	err = s.withSerializedWrite(ctx, func() error {
		res, err = s.db.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
}

func (s *Store) withSerializedWrite(ctx context.Context, op func() error) error {
	if op == nil {
		return nil
	}
	req := storeWriteRequest{
		ctx:  ctx,
		op:   op,
		done: acquireStoreWriteCompletion(),
	}
	select {
	case s.writeRequests <- req:
	case <-ctx.Done():
		releaseStoreWriteCompletion(req.done)
		return ctx.Err()
	}
	select {
	case err := <-req.done.ch:
		releaseStoreWriteCompletion(req.done)
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Store) runWriterLoop() {
	defer close(s.writerDone)

	ticker := time.NewTicker(s.touchFlushInterval)
	defer ticker.Stop()

	pendingTouches := make(map[string][]*storeWriteCompletion)

	flushTouches := func() {
		if len(pendingTouches) == 0 {
			return
		}
		err := s.flushTouchBatch(pendingTouches)
		for _, waiters := range pendingTouches {
			for _, done := range waiters {
				done.ch <- err
			}
		}
		clear(pendingTouches)
	}

	drainTouches := func() {
		for {
			select {
			case req := <-s.touchRequests:
				pendingTouches[req.domainID] = append(pendingTouches[req.domainID], req.done)
			default:
				return
			}
		}
	}

	drainWrites := func() {
		for {
			select {
			case req := <-s.writeRequests:
				flushTouches()
				req.done.ch <- withSQLiteBusyRetry(req.ctx, req.op)
			default:
				return
			}
		}
	}

	for {
		select {
		case req := <-s.writeRequests:
			flushTouches()
			req.done.ch <- withSQLiteBusyRetry(req.ctx, req.op)
			// Drain any additional pending writes that arrived while we were
			// executing the first one. This reduces SQLite WAL contention
			// during mass-connect/disconnect bursts.
			for drained := true; drained; {
				select {
				case r := <-s.writeRequests:
					r.done.ch <- withSQLiteBusyRetry(r.ctx, r.op)
				default:
					drained = false
				}
			}
		case req := <-s.touchRequests:
			pendingTouches[req.domainID] = append(pendingTouches[req.domainID], req.done)
			if len(pendingTouches) >= defaultTouchQueueSize/8 {
				flushTouches()
			}
		case <-ticker.C:
			flushTouches()
		case <-s.writerStop:
			drainTouches()
			flushTouches()
			drainWrites()
			return
		}
	}
}

func (s *Store) stopWriterLoop() {
	if s == nil || s.writerStop == nil || s.writerDone == nil {
		return
	}
	select {
	case <-s.writerDone:
		return
	default:
	}
	close(s.writerStop)
	<-s.writerDone
}

func (s *Store) flushTouchBatch(pending map[string][]*storeWriteCompletion) error {
	if len(pending) == 0 {
		return nil
	}
	now := time.Now().UTC()
	domainIDs := make([]string, 0, len(pending))
	for domainID := range pending {
		if strings.TrimSpace(domainID) != "" {
			domainIDs = append(domainIDs, domainID)
		}
	}
	if len(domainIDs) == 0 {
		return nil
	}
	return withSQLiteBusyRetry(context.Background(), func() error {
		placeholders := strings.Repeat("?,", len(domainIDs))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, 0, len(domainIDs)+1)
		args = append(args, now)
		for _, domainID := range domainIDs {
			args = append(args, domainID)
		}
		_, err := s.db.ExecContext(context.Background(),
			fmt.Sprintf(`UPDATE domains SET last_seen_at = ? WHERE id IN (%s)`, placeholders),
			args...,
		)
		return err
	})
}

func acquireStoreWriteCompletion() *storeWriteCompletion {
	comp := storeWriteCompletionPool.Get().(*storeWriteCompletion)
	select {
	case <-comp.ch:
	default:
	}
	return comp
}

func releaseStoreWriteCompletion(comp *storeWriteCompletion) {
	if comp == nil {
		return
	}
	select {
	case <-comp.ch:
	default:
	}
	storeWriteCompletionPool.Put(comp)
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database is busy") ||
		strings.Contains(msg, "sqlite_busy") ||
		strings.Contains(msg, "sqlite_locked")
}

func waitForContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

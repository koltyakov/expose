package sqlite

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const (
	sqliteBusyRetryMaxAttempts = 6
	sqliteBusyRetryInitialWait = 10 * time.Millisecond
	sqliteBusyRetryMaxWait     = 250 * time.Millisecond
)

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
	err = withSQLiteBusyRetry(ctx, func() error {
		res, err = s.db.ExecContext(ctx, query, args...)
		return err
	})
	return res, err
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

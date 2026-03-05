package sqlite

import (
	"context"
	"errors"
	"testing"
)

func TestWithSQLiteBusyRetryRetriesBusyThenSucceeds(t *testing.T) {
	t.Parallel()

	var attempts int
	err := withSQLiteBusyRetry(context.Background(), func() error {
		attempts++
		if attempts <= 2 {
			return errors.New("database is locked (5) (SQLITE_BUSY)")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestWithSQLiteBusyRetryDoesNotRetryNonBusyErrors(t *testing.T) {
	t.Parallel()

	var attempts int
	wantErr := errors.New("some permanent failure")
	err := withSQLiteBusyRetry(context.Background(), func() error {
		attempts++
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected %v, got %v", wantErr, err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}
}

func TestWithSQLiteBusyRetryRespectsContextCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := withSQLiteBusyRetry(ctx, func() error {
		return errors.New("database is locked (5) (SQLITE_BUSY)")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

package client

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/selfupdate"
)

func TestAutoUpdateLoopRunsVersionChangeChecksInBackground(t *testing.T) {
	c := New(config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.SetVersion("1.0.0")
	c.SetSkipStartupUpdateCheck(true)
	release := make(chan struct{})
	checks := make(chan struct{}, 4)
	c.checkAndApply = func(ctx context.Context, _ string) (*selfupdate.Result, error) {
		checks <- struct{}{}
		select {
		case <-release: // a slow release API
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &selfupdate.Result{Updated: true, LatestVersion: "1.0.1"}, nil
	}
	checkNow := make(chan struct{}, 1)
	updated := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.runAutoUpdateLoop(ctx, checkNow, updated)
	}()

	select {
	case <-checks:
		t.Fatal("checked at startup although the process was just updated")
	case <-time.After(50 * time.Millisecond):
	}

	// The session loop's request returns at once, even while a check runs.
	start := time.Now()
	requestUpdateCheck(checkNow)
	<-checks
	requestUpdateCheck(checkNow)
	requestUpdateCheck(checkNow)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("requesting an update check blocked for %s", elapsed)
	}
	close(release)
	select {
	case <-updated:
	case <-time.After(time.Second):
		t.Fatal("applied update was not signalled")
	}
	<-done
}

func TestAutoUpdateLoopChecksAtStartup(t *testing.T) {
	c := New(config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.SetVersion("1.0.0")
	c.checkAndApply = func(context.Context, string) (*selfupdate.Result, error) {
		return &selfupdate.Result{Updated: true, LatestVersion: "1.0.1"}, nil
	}
	updated := make(chan struct{}, 1)
	c.runAutoUpdateLoop(t.Context(), nil, updated)
	select {
	case <-updated:
	default:
		t.Fatal("startup check did not apply the update")
	}
}

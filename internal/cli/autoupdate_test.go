package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/selfupdate"
)

func TestAutoUpdateLoopClientTrigger(t *testing.T) {
	original := autoUpdateCheckAndApply
	t.Cleanup(func() { autoUpdateCheckAndApply = original })
	checks := make(chan struct{}, 1)
	checks <- struct{}{}
	calls := 0
	autoUpdateCheckAndApply = func(ctx context.Context, version string) (*selfupdate.Result, error) {
		calls++
		if version != "1.2.9" {
			t.Fatalf("checked version = %q", version)
		}
		switch calls {
		case 1:
			checks <- struct{}{}
			return &selfupdate.Result{CurrentVersion: version}, nil
		case 2:
			checks <- struct{}{}
			return nil, errors.New("release service unavailable")
		default:
			return &selfupdate.Result{CurrentVersion: version, LatestVersion: "1.2.10", Updated: true}, nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	restarts := 0
	startAutoUpdateLoop(ctx, "1.2.9", slog.New(slog.NewTextHandler(io.Discard, nil)), false, checks, func() {
		restarts++
		if calls != 3 {
			t.Errorf("restart before update applied, checks = %d", calls)
		}
	})
	if calls != 3 || restarts != 1 {
		t.Fatalf("checks = %d, restarts = %d; want 3, 1", calls, restarts)
	}
}

func TestAutoUpdateDevelopmentBuilds(t *testing.T) {
	original := autoUpdateCheckAndApply
	t.Cleanup(func() { autoUpdateCheckAndApply = original })
	for _, version := range []string{"dev", "1.2.9-dev", "v1.2.9-3-gabc123-dev"} {
		t.Run(version, func(t *testing.T) {
			calls := 0
			autoUpdateCheckAndApply = func(_ context.Context, current string) (*selfupdate.Result, error) {
				calls++
				if current != version {
					t.Fatalf("checked version = %q, want %q", current, version)
				}
				return &selfupdate.Result{CurrentVersion: current, LatestVersion: "1.2.10", Updated: true}, nil
			}
			checks := make(chan struct{}, 1)
			checks <- struct{}{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			restarts := 0
			startAutoUpdateLoop(ctx, version, logger, true, nil, func() {
				restarts++
			})
			if calls != 1 || restarts != 1 {
				t.Fatalf("startup checks = %d, restarts = %d; want 1, 1", calls, restarts)
			}
			startAutoUpdateLoop(ctx, version, logger, false, checks, func() {
				restarts++
			})
			if calls != 2 || restarts != 2 {
				t.Fatalf("checks = %d, restarts = %d; want 2, 2", calls, restarts)
			}
		})
	}
}

func TestAutoUpdateStartupCheckRunsInLoop(t *testing.T) {
	original := autoUpdateCheckAndApply
	t.Cleanup(func() { autoUpdateCheckAndApply = original })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The startup check runs inside the loop, which callers start beside the
	// service, so an unreachable release API delays nothing else.
	started := make(chan struct{})
	autoUpdateCheckAndApply = func(ctx context.Context, version string) (*selfupdate.Result, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		startAutoUpdateLoop(ctx, "1.2.9", logger, true, nil, func() { t.Error("unexpected restart") })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("startup check did not run without a trigger")
	}
	cancel()
	<-done

	// A process an update just restarted waits for the interval or a trigger.
	autoUpdateCheckAndApply = func(context.Context, string) (*selfupdate.Result, error) {
		t.Error("checked at startup after an update restart")
		return &selfupdate.Result{}, nil
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	startAutoUpdateLoop(ctx, "1.2.9", logger, false, nil, func() { t.Error("unexpected restart") })
}

func TestIsAutoUpdateEnabled(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"Yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"maybe", false},
		{"  true  ", true},
		{"  ", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("EXPOSE_AUTOUPDATE", tt.value)
			got := isAutoUpdateEnabled()
			if got != tt.want {
				t.Errorf("isAutoUpdateEnabled() with EXPOSE_AUTOUPDATE=%q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsAutoUpdateEnabled_Unset(t *testing.T) {
	t.Setenv("EXPOSE_AUTOUPDATE", "")
	if isAutoUpdateEnabled() {
		t.Error("isAutoUpdateEnabled() should be false when EXPOSE_AUTOUPDATE is empty")
	}
}

func TestAutoUpdateActiveRequiresPinnedReleaseKeys(t *testing.T) {
	original := autoUpdateSupported
	t.Cleanup(func() { autoUpdateSupported = original })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Setenv("EXPOSE_AUTOUPDATE", "true")
	autoUpdateSupported = func() error { return errors.New("no pinned release keys configured") }
	if autoUpdateActive(logger) {
		t.Fatal("auto-update active for a build that cannot verify releases")
	}
	autoUpdateSupported = func() error { return nil }
	if !autoUpdateActive(logger) {
		t.Fatal("auto-update inactive for a verifiable build")
	}
	t.Setenv("EXPOSE_AUTOUPDATE", "false")
	if autoUpdateActive(logger) {
		t.Fatal("auto-update active while disabled")
	}
}

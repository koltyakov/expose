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
	startAutoUpdateLoop(ctx, "1.2.9", slog.New(slog.NewTextHandler(io.Discard, nil)), checks, func() {
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
			if !autoUpdateOnStart(ctx, version, logger) {
				t.Fatal("startup did not request restart after update")
			}
			restarts := 0
			startAutoUpdateLoop(ctx, version, logger, checks, func() {
				restarts++
			})
			if calls != 2 || restarts != 1 {
				t.Fatalf("checks = %d, loop restarts = %d; want 2, 1", calls, restarts)
			}
		})
	}
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

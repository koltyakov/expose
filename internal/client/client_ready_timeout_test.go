package client

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
)

func TestRunReadyTimeoutStopsRetryingBeforeFirstTunnel(t *testing.T) {
	t.Parallel()
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(config.ClientConfig{
		ServerURL:    srv.URL,
		APIKey:       "test-key",
		LocalPort:    1,
		ReadyTimeout: 300 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := time.Now()
	err := c.Run(ctx)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "not ready within 300ms") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("Run returned after %s, want about the 300ms deadline", elapsed)
	}
	if attempts < 1 {
		t.Fatalf("register attempts = %d, want at least one", attempts)
	}
}

func TestRunReadyTimeoutBoundsHungRegister(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := New(config.ClientConfig{
		ServerURL:    srv.URL,
		APIKey:       "test-key",
		LocalPort:    1,
		ReadyTimeout: 300 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Now()
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready within") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("hung register held Run for %s past a 300ms ready timeout", elapsed)
	}
}

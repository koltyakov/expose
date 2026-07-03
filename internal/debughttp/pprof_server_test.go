package debughttp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStartPprofServerEmptyAddr(t *testing.T) {
	t.Parallel()

	if err := StartPprofServer(t.Context(), "   ", nil, "client"); err != nil {
		t.Fatalf("StartPprofServer(empty) error = %v", err)
	}
}

func TestStartPprofServerAddressConflict(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	if err := StartPprofServer(t.Context(), ln.Addr().String(), nil, "client"); err == nil {
		t.Fatal("StartPprofServer() error = nil, want bind error")
	}
}

func TestStartPprofServerServesAndStops(t *testing.T) {
	addr := freeTCPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	if err := StartPprofServer(ctx, addr, logger, " client "); err != nil {
		t.Fatalf("StartPprofServer() error = %v", err)
	}

	url := "http://" + addr + "/debug/pprof/"
	waitFor(t, time.Second, func() bool {
		resp, err := http.Get(url)
		if err != nil {
			return false
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Errorf("Body.Close() error = %v", err)
			}
		}()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}
		return resp.StatusCode == http.StatusOK && strings.Contains(string(body), "profile?debug=1")
	})

	waitFor(t, time.Second, func() bool {
		return strings.Contains(logBuf.String(), "pprof listening")
	})

	cancel()

	waitFor(t, time.Second, func() bool {
		client := http.Client{Timeout: 50 * time.Millisecond}
		resp, err := client.Get(url)
		if err == nil {
			if closeErr := resp.Body.Close(); closeErr != nil {
				t.Errorf("Body.Close() error = %v", closeErr)
			}
		}
		return err != nil
	})
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return addr
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func TestStartPprofServerRefusesNonLoopback(t *testing.T) {
	if err := StartPprofServer(t.Context(), "0.0.0.0:0", nil, "client"); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("StartPprofServer(0.0.0.0) error = %v, want non-loopback refusal", err)
	}
	if err := StartPprofServer(t.Context(), ":0", nil, "client"); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("StartPprofServer(:port) error = %v, want non-loopback refusal (empty host binds all interfaces)", err)
	}

	t.Setenv("EXPOSE_PPROF_ALLOW_REMOTE", "true")
	if err := StartPprofServer(t.Context(), "0.0.0.0:0", nil, "client"); err != nil {
		t.Fatalf("StartPprofServer(0.0.0.0, opt-in) error = %v", err)
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost", "LOCALHOST", "127.0.0.53"}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = false, want true", h)
		}
	}
	public := []string{"", "0.0.0.0", "::", "192.168.1.10", "example.com"}
	for _, h := range public {
		if isLoopbackHost(h) {
			t.Errorf("isLoopbackHost(%q) = true, want false", h)
		}
	}
}

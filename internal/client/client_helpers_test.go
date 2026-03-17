package client

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/traffic"
)

func TestRegisterErrorError(t *testing.T) {
	t.Parallel()

	err := &registerError{Message: "hostname already in use"}
	if got := err.Error(); got != "hostname already in use" {
		t.Fatalf("Error() = %q, want %q", got, "hostname already in use")
	}
}

func TestShortenError(t *testing.T) {
	t.Parallel()

	nested := &url.Error{
		Op:  "Get",
		URL: "https://example.com",
		Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
	}
	if got := shortenError(nested); got != "connection refused" {
		t.Fatalf("shortenError(nested) = %q, want %q", got, "connection refused")
	}

	plain := errors.New("plain failure")
	if got := shortenError(plain); got != "plain failure" {
		t.Fatalf("shortenError(plain) = %q, want %q", got, "plain failure")
	}
}

func TestTrafficSinkFuncRecordTraffic(t *testing.T) {
	t.Parallel()

	called := false
	sink := TrafficSinkFunc(func(direction traffic.Direction, bytes int64) {
		called = true
		if direction != traffic.DirectionOutbound {
			t.Fatalf("direction = %v, want %v", direction, traffic.DirectionOutbound)
		}
		if bytes != 42 {
			t.Fatalf("bytes = %d, want %d", bytes, 42)
		}
	})
	sink.RecordTraffic(traffic.DirectionOutbound, 42)
	if !called {
		t.Fatal("RecordTraffic() did not invoke sink")
	}

	var nilSink TrafficSinkFunc
	nilSink.RecordTraffic(traffic.DirectionInbound, 1)
}

func TestClientSetters(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	display := NewDisplay(false)

	client := &Client{}
	client.SetLogger(logger)
	client.SetVersion("v1.2.3")
	client.SetAutoUpdate(true)
	client.SetDisplay(display)

	if client.log != logger {
		t.Fatal("SetLogger() did not update client logger")
	}
	if client.version != "v1.2.3" {
		t.Fatalf("SetVersion() stored %q, want %q", client.version, "v1.2.3")
	}
	if !client.autoUpdate {
		t.Fatal("SetAutoUpdate(true) did not enable auto-update")
	}
	if client.display != display {
		t.Fatal("SetDisplay() did not update client display")
	}
}

func TestNonRetriableSessionError(t *testing.T) {
	t.Parallel()

	inner := errors.New("handshake failed")
	err := nonRetriableSessionError{err: inner}

	if got := err.Error(); got != "handshake failed" {
		t.Fatalf("Error() = %q, want %q", got, "handshake failed")
	}
	if !errors.Is(err, inner) {
		t.Fatal("errors.Is() did not unwrap nonRetriableSessionError")
	}
	if !isNonRetriableSessionError(err) {
		t.Fatal("isNonRetriableSessionError() = false, want true")
	}

	var zero nonRetriableSessionError
	if got := zero.Error(); got != "session error" {
		t.Fatalf("zero Error() = %q, want %q", got, "session error")
	}
	if zero.Unwrap() != nil {
		t.Fatal("zero Unwrap() = non-nil, want nil")
	}
}

func TestLocalTargetDialAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		wantCache string
		wantDial  string
		wantOK    bool
	}{
		{name: "http default port", raw: "http://example.com/path", wantCache: "example.com:80", wantDial: "example.com:80", wantOK: true},
		{name: "https default port", raw: " https://example.com/path ", wantCache: "example.com:443", wantDial: "example.com:443", wantOK: true},
		{name: "explicit port", raw: "http://127.0.0.1:8080", wantCache: "127.0.0.1:8080", wantDial: "127.0.0.1:8080", wantOK: true},
		{name: "unsupported scheme", raw: "tcp://example.com", wantOK: false},
		{name: "missing host", raw: "http:///path", wantOK: false},
		{name: "invalid url", raw: "://bad", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotCache, gotDial, gotOK := localTargetDialAddr(tt.raw)
			if gotOK != tt.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tt.wantOK)
			}
			if gotCache != tt.wantCache {
				t.Fatalf("cacheKey = %q, want %q", gotCache, tt.wantCache)
			}
			if gotDial != tt.wantDial {
				t.Fatalf("dialAddr = %q, want %q", gotDial, tt.wantDial)
			}
		})
	}
}

func TestAppendLatencySampleLocked(t *testing.T) {
	t.Parallel()

	d := NewDisplay(false)

	d.mu.Lock()
	d.appendLatencySampleLocked(-5 * time.Millisecond)
	for i := range make([]struct{}, displayLatencySampleMax+2) {
		d.appendLatencySampleLocked(time.Duration(i+1) * time.Millisecond)
	}
	d.mu.Unlock()

	if got := d.latencySamples[0]; got != 3*time.Millisecond {
		t.Fatalf("first sample = %v, want %v", got, 3*time.Millisecond)
	}
	if got := d.latencySamples[len(d.latencySamples)-1]; got != time.Duration(displayLatencySampleMax+2)*time.Millisecond {
		t.Fatalf("last sample = %v, want %v", got, time.Duration(displayLatencySampleMax+2)*time.Millisecond)
	}
	if len(d.latencySamples) != displayLatencySampleMax {
		t.Fatalf("len(latencySamples) = %d, want %d", len(d.latencySamples), displayLatencySampleMax)
	}
	for _, sample := range d.latencySamples {
		if sample < 0 {
			t.Fatalf("found negative sample %v", sample)
		}
	}
}

func TestTrafficSnapshotForDisplayAtNilDisplay(t *testing.T) {
	t.Parallel()

	if got := trafficSnapshotForDisplayAt(nil, time.Now()); got != (traffic.Snapshot{}) {
		t.Fatalf("trafficSnapshotForDisplayAt(nil) = %#v, want zero snapshot", got)
	}

	d := &Display{}
	if got := trafficSnapshotForDisplayAt(d, time.Now()); got != (traffic.Snapshot{}) {
		t.Fatalf("trafficSnapshotForDisplayAt(display without meter) = %#v, want zero snapshot", got)
	}
}

func TestSessionDetailFallbacks(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)

	if got := (&Display{}).sessionDetail(now); got != "" {
		t.Fatalf("sessionDetail(empty) = %q, want empty string", got)
	}

	startOnly := &Display{sessionStart: now}
	if got := startOnly.sessionDetail(now); !strings.HasPrefix(got, "Started: ") {
		t.Fatalf("sessionDetail(start only) = %q, want Started prefix", got)
	}

	idOnly := &Display{tunnelID: "tun_123"}
	if got := idOnly.sessionDetail(now); got != "ID: tun_123" {
		t.Fatalf("sessionDetail(id only) = %q, want %q", got, "ID: tun_123")
	}
}

func TestDisplayShowWAFStats(t *testing.T) {
	t.Parallel()

	d, buf := newTestDisplay(false)
	d.ShowVersions("v1.0.0", "v2.0.0", true)
	buf.Reset()

	d.ShowWAFStats(3)

	if got := buf.String(); !strings.Contains(got, "blocked 3") {
		t.Fatalf("output missing WAF blocked count: %s", got)
	}
}

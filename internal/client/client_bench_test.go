package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func BenchmarkForwardLocalInlineResponse(b *testing.B) {
	const responseSize = 32 * 1024

	c, base := newBenchmarkForwardClient(b, responseSize)
	req := &tunnelproto.HTTPRequest{
		ID:      "req_inline",
		Method:  http.MethodGet,
		Path:    "/bench",
		Headers: map[string][]string{"X-Bench": {"1"}},
	}

	resp := c.forwardLocal(context.Background(), base, req)
	if resp.Status != http.StatusOK {
		b.Fatalf("expected 200 warmup response, got %d", resp.Status)
	}

	b.ReportAllocs()
	b.SetBytes(responseSize)

	for b.Loop() {
		resp = c.forwardLocal(context.Background(), base, req)
		if resp.Status != http.StatusOK {
			b.Fatalf("expected 200 response, got %d", resp.Status)
		}
	}
}

func BenchmarkForwardAndSendInlineResponse(b *testing.B) {
	const responseSize = 32 * 1024

	c, base := newBenchmarkForwardClient(b, responseSize)
	req := &tunnelproto.HTTPRequest{
		ID:      "req_send_inline",
		Method:  http.MethodGet,
		Path:    "/bench",
		Headers: map[string][]string{"X-Bench": {"1"}},
	}

	var responseCount int
	writeMsg := func(msg tunnelproto.Message) error {
		if msg.Kind == tunnelproto.KindResponse && msg.Response != nil && msg.Response.Status == http.StatusOK {
			responseCount++
		}
		return nil
	}

	c.forwardAndSend(context.Background(), base, req, nil, writeMsg, nil)
	if responseCount != 1 {
		b.Fatalf("expected one warmup response, got %d", responseCount)
	}

	b.ReportAllocs()
	b.SetBytes(responseSize)

	for b.Loop() {
		c.forwardAndSend(context.Background(), base, req, nil, func(msg tunnelproto.Message) error {
			if msg.Kind != tunnelproto.KindResponse || msg.Response == nil || msg.Response.Status != http.StatusOK {
				b.Fatalf("unexpected inline response message: %+v", msg)
			}
			return nil
		}, nil)
	}
}

func BenchmarkForwardAndSendStreamedResponse(b *testing.B) {
	responseSize := streamingThreshold + (2 * streamingChunkSize)

	c, base := newBenchmarkForwardClient(b, responseSize)
	req := &tunnelproto.HTTPRequest{
		ID:      "req_send_stream",
		Method:  http.MethodGet,
		Path:    "/bench",
		Headers: map[string][]string{"X-Bench": {"1"}},
	}

	var (
		streamedResp bool
		chunkBytes   int
	)
	c.forwardAndSend(context.Background(), base, req, nil, func(msg tunnelproto.Message) error {
		if msg.Kind == tunnelproto.KindResponse && msg.Response != nil {
			streamedResp = msg.Response.Streamed
		}
		return nil
	}, func(_ string, payload []byte) error {
		chunkBytes += len(payload)
		return nil
	})
	if !streamedResp {
		b.Fatal("expected warmup response to use streamed path")
	}
	if chunkBytes != responseSize {
		b.Fatalf("expected %d streamed bytes, got %d", responseSize, chunkBytes)
	}

	b.ReportAllocs()
	b.SetBytes(int64(responseSize))

	for b.Loop() {
		var (
			gotStream bool
			gotBytes  int
		)
		c.forwardAndSend(context.Background(), base, req, nil, func(msg tunnelproto.Message) error {
			if msg.Kind == tunnelproto.KindResponse && msg.Response != nil {
				gotStream = msg.Response.Streamed
			}
			return nil
		}, func(_ string, payload []byte) error {
			gotBytes += len(payload)
			return nil
		})
		if !gotStream {
			b.Fatal("expected streamed response")
		}
		if gotBytes != responseSize {
			b.Fatalf("expected %d streamed bytes, got %d", responseSize, gotBytes)
		}
	}
}

func BenchmarkForwardAndSendParallel(b *testing.B) {
	const responseSize = 8 * 1024

	c, base := newBenchmarkForwardClient(b, responseSize)
	req := &tunnelproto.HTTPRequest{
		ID:      "req_parallel",
		Method:  http.MethodGet,
		Path:    "/bench",
		Headers: map[string][]string{"X-Bench": {"1"}},
	}

	c.forwardAndSend(context.Background(), base, req, nil, func(tunnelproto.Message) error { return nil }, nil)

	b.ReportAllocs()
	b.SetBytes(responseSize)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.forwardAndSend(context.Background(), base, req, nil, func(msg tunnelproto.Message) error {
				if msg.Kind != tunnelproto.KindResponse || msg.Response == nil || msg.Response.Status != http.StatusOK {
					b.Fatalf("unexpected parallel response message: %+v", msg)
				}
				return nil
			}, nil)
		}
	})
}

func newBenchmarkForwardClient(b *testing.B, responseSize int) (*Client, *url.URL) {
	b.Helper()

	payload := make([]byte, responseSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	b.Cleanup(upstream.Close)

	base, err := url.Parse(upstream.URL)
	if err != nil {
		b.Fatalf("parse benchmark upstream url: %v", err)
	}

	c := New(config.ClientConfig{
		Timeout:               5 * time.Second,
		MaxConcurrentForwards: 512,
	}, nil)
	return c, base
}

// BenchmarkDisplayLogRequest measures the per-request dashboard cost once the
// latency window and request log are full, which is the steady state of a
// busy tunnel.
func BenchmarkDisplayLogRequest(b *testing.B) {
	d := NewDisplay(true)
	d.out = io.Discard
	d.refreshInterval = 0
	d.terminalColumnsFn = func() int { return 120 }
	d.ShowTunnelInfo("https://bench.example.com", "http://127.0.0.1:3000", "wildcard", "t-bench", false, "ws")
	headers := map[string][]string{
		"X-Forwarded-For": {"203.0.113.10"},
		"User-Agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
	}
	for i := range displayLatencySampleMax {
		d.LogRequest("GET", "/assets/app.js", 200, time.Duration(i%97)*time.Millisecond, headers)
	}

	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		d.LogRequest("GET", "/assets/app.js", 200, time.Duration(i%97)*time.Millisecond, headers)
	}
}

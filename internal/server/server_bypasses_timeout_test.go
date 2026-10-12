package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
)

func TestBypassHTTP3StalledBodyReleasesSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	canceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-ctx.Done():
		}
	}))
	defer upstream.Close()
	defer cancel()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.RequestTimeout = 100 * time.Millisecond
	srv.cfg.MaxPendingPerTunnel = 1
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: bypassTestPort(t, upstream)}}
	srv.initBypasses(st)
	addr, shutdown := startHTTP3IntegrationServer(t, srv.httpHandler())
	defer shutdown()
	_, client, closeClient := newHTTP3IntegrationClient(t, addr)
	defer closeClient()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/stall", nil)
	req.Host = "app.example.com"
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("body inactivity timeout did not cancel the upstream request")
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("stalled response should be aborted, not reported complete")
	}
	// The aborted HTTP/3 request must release its only route slot.
	deadline := time.Now().Add(time.Second)
	for srv.bypasses["app.example.com"].pending.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stalled request retained its pending slot")
		}
		time.Sleep(time.Millisecond)
	}
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr+"/ok", nil)
	req.Host = "app.example.com"
	resp, err = client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("request after timeout: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}

func TestBypassBodyTimeoutAllowsActiveStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 20 {
			_, _ = io.WriteString(w, "x")
			w.(http.Flusher).Flush()
			time.Sleep(25 * time.Millisecond)
		}
	}))
	defer upstream.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: bypassTransport{transport, 300 * time.Millisecond}, Timeout: 5 * time.Second}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func(body io.ReadCloser) { _ = body.Close() }(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != strings.Repeat("x", 20) {
		t.Fatalf("active stream interrupted: body=%q err=%v", body, err)
	}
}

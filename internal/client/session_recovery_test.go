package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/quic-go/quic-go/http3"
)

func TestQUICConnectionFailuresRemainRetryable(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "connect failed", status)
			}))
			defer shutdown()
			c := New(config.ClientConfig{Transport: "quic"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
			_, err := c.connectSessionTransport(t.Context(), domain.RegisterResponse{
				H3URL: "https://" + addr + "/connect", Capabilities: []string{tunnelCapabilityH3CompatV1},
			})
			if err == nil || isNonRetriableSessionError(err) {
				t.Fatalf("connection failure should permit fresh registration: %v", err)
			}
		})
	}
}

func TestQUICFallbackRefreshesSingleUseToken(t *testing.T) {
	var mu sync.Mutex
	var tokens []string
	addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		mu.Lock()
		tokens = append(tokens, token)
		mu.Unlock()
		if r.Header.Get("X-Expose-H3-Mode") != "" {
			http.Error(w, "session setup failed after consuming token", http.StatusServiceUnavailable)
			return
		}
		if token != "Bearer fresh-token" {
			http.Error(w, "token already used", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = w.(http3.HTTPStreamer).HTTPStream()
	}))
	defer shutdown()
	reg := domain.RegisterResponse{
		TunnelID: "original-tunnel", WSURL: "wss://example.com/connect",
		H3URL:        "https://" + addr + "/connect?token=old-token",
		Capabilities: []string{tunnelCapabilityH3MultistreamV2, tunnelCapabilityH3CompatV1, domain.CapabilityConnectTokenHeader},
	}
	var registrations atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registrations.Add(1)
		if r.Header.Get(domain.RegisterResumeTunnelHeader) != reg.TunnelID {
			t.Error("fallback did not resume the original tunnel")
		}
		fresh := reg
		fresh.H3URL = "https://" + addr + "/connect?token=fresh-token"
		_ = json.NewEncoder(w).Encode(fresh)
	}))
	defer api.Close()
	c := New(config.ClientConfig{Transport: "quic", ServerURL: api.URL}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	conn, err := c.connectSessionTransport(t.Context(), reg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.writer.Close()
	if conn.protocol != tunnelCapabilityH3CompatV1 || registrations.Load() != 1 {
		t.Fatalf("fallback protocol=%s registrations=%d", conn.protocol, registrations.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tokens) != 2 || tokens[0] != "Bearer old-token" || tokens[1] != "Bearer fresh-token" {
		t.Fatalf("unexpected connection tokens: %v", tokens)
	}
}

func TestCanceledQUICConnectDoesNotRefreshRegistration(t *testing.T) {
	var registrations atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { registrations.Add(1) }))
	defer api.Close()
	c := New(config.ClientConfig{Transport: "quic", ServerURL: api.URL}, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := c.connectSessionTransport(ctx, domain.RegisterResponse{
		H3URL: "https://127.0.0.1:1/connect", Capabilities: []string{tunnelCapabilityH3MultistreamV2, tunnelCapabilityH3CompatV1},
	})
	if err != context.Canceled || registrations.Load() != 0 {
		t.Fatalf("canceled connection: err=%v registrations=%d", err, registrations.Load())
	}
}

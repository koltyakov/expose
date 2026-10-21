package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

type pumpLifecycleStore struct {
	stubServerStore
	reject bool
}

func (*pumpLifecycleStore) ConsumeConnectToken(context.Context, string) (string, error) {
	return "pump-tunnel", nil
}

func (*pumpLifecycleStore) FindRouteByTunnelID(context.Context, string) (domain.TunnelRoute, error) {
	return domain.TunnelRoute{
		Domain: domain.Domain{ID: "pump-domain", APIKeyID: "pump-key", Hostname: "pump.example.com"},
		Tunnel: domain.Tunnel{ID: "pump-tunnel", APIKeyID: "pump-key"},
	}, nil
}

func (s *pumpLifecycleStore) GetAPIKeyTunnelLimit(context.Context, string) (int, error) {
	if s.reject {
		return 0, errors.New("admission unavailable")
	}
	return -1, nil
}

func serverIdleWritePumpCount() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return bytes.Count(buf[:n], []byte("tunneltransport.(*WritePump).next"))
}

func assertNoIdlePumpGrowth(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for serverIdleWritePumpCount() > before && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if after := serverIdleWritePumpCount(); after > before {
		t.Fatalf("idle write pumps before=%d after=%d", before, after)
	}
}

func TestQUICV2ServerConnectionsReleaseAllWritePumps(t *testing.T) {
	// Keep process-wide goroutine assertions outside parallel tests.
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.store = &pumpLifecycleStore{}
	connected := make(chan struct{}, 3)
	addr, shutdown := startHTTP3IntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.handleConnectH3(w, r)
		connected <- struct{}{}
	}))
	defer shutdown()
	before := serverIdleWritePumpCount()
	for range 3 {
		_, client, closeClient := newHTTP3IntegrationClient(t, addr)
		stream, err := client.OpenRequestStream(t.Context())
		if err != nil {
			closeClient()
			t.Fatal(err)
		}
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/connect", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		req.Header.Set("X-Expose-H3-Mode", "multistream-v2")
		if err := stream.SendRequestHeader(req); err != nil {
			closeClient()
			t.Fatal(err)
		}
		resp, err := stream.ReadResponse()
		if err != nil {
			closeClient()
			t.Fatal(err)
		}
		select {
		case <-connected:
		case <-time.After(time.Second):
			closeClient()
			t.Fatal("session activation did not finish")
		}
		closeClient()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("connect status=%d", resp.StatusCode)
		}
		if !waitGroupWait(&srv.hub.wg, time.Second) {
			t.Fatal("session failed to close")
		}
	}
	assertNoIdlePumpGrowth(t, before)
}

func TestRejectedWebSocketConnectDoesNotStartWritePump(t *testing.T) {
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.store = &pumpLifecycleStore{reject: true}
	done := make(chan struct{})
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		srv.handleConnect(w, r)
	}))
	defer public.Close()
	before := serverIdleWritePumpCount()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(public.URL, "http")+"?token=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connect handler did not return")
	}
	assertNoIdlePumpGrowth(t, before)
}

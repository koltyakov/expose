package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
)

func TestBypassAdmissionLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.ServerBypass
		want bypassLimits
	}{
		{"default", config.ServerBypass{}, bypassLimits{128, 128, 96}},
		{"tiny", config.ServerBypass{MaxInFlight: 1}, bypassLimits{1, 1, 1}},
		{"override", config.ServerBypass{MaxInFlight: 10, MaxHTTPRequests: 3, MaxUpgrades: 6}, bypassLimits{10, 3, 6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bypassLimitsFor(tc.cfg, config.ServerConfig{}); got != tc.want {
				t.Fatalf("limits = %+v, want %+v", got, tc.want)
			}
		})
	}
	owner := &Server{}
	b := &serverBypass{owner: owner, limits: bypassLimits{4, 4, 3}}
	var wg sync.WaitGroup
	var accepted int
	var mu sync.Mutex
	for range 32 {
		wg.Go(func() {
			if b.acquire(true) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if accepted != 3 || !b.acquire(false) || b.acquire(false) {
		t.Fatalf("class isolation: upgrades=%d total=%d", accepted, b.pending.Load())
	}
	for range accepted {
		b.release(true)
	}
	b.release(false)
	if b.pending.Load() != 0 {
		t.Fatal("admission leaked")
	}
	owner.bypassWG.Wait()
}

func TestBypassUpgradesReserveHTTPAndCloseOnShutdown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/http" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		u := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := u.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: bypassTestPort(t, upstream), MaxInFlight: 4}}
	srv.initBypasses(st)
	front := httptest.NewServer(srv.httpHandler())
	defer front.Close()
	defer srv.closeBypasses()
	header := http.Header{"Host": {"app.example.com"}}
	dialer := websocket.Dialer{HandshakeTimeout: time.Second}
	var sockets []*websocket.Conn
	for range 3 {
		conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/ws", header)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		sockets = append(sockets, conn)
	}
	conn, resp, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/ws", header)
	if conn != nil {
		_ = conn.Close()
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("upgrade limit: response=%v err=%v", resp, err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+"/http", nil)
	req.Host = "app.example.com"
	client := &http.Client{Timeout: time.Second}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP starved: %d", resp.StatusCode)
	}
	metrics := httptest.NewRecorder()
	srv.MetricsHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
	for _, want := range []string{
		`expose_bypass_active_upgrades{route="app.example.com"} 3`,
		`expose_bypass_limit{route="app.example.com",class="upgrade"} 3`,
		`expose_bypass_rejections_total{route="app.example.com",reason="upgrade"} 1`,
	} {
		if !strings.Contains(metrics.Body.String(), want) {
			t.Errorf("missing metric %s", want)
		}
	}
	srv.closeBypasses()
	if !waitGroupWait(&srv.bypassWG, time.Second) {
		t.Fatal("shutdown retained proxy handlers")
	}
	for _, c := range sockets {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := c.ReadMessage(); err == nil {
			t.Fatal("shutdown left upgrade connected")
		}
	}
	b := srv.bypasses["app.example.com"]
	if b.pending.Load() != 0 || b.acquire(true) || b.acquire(false) {
		t.Fatal("shutdown admission or cleanup failed")
	}
}

func TestBypassLateUpgradeAndFailedHandshakeRelease(t *testing.T) {
	owner := &Server{}
	b := &serverBypass{owner: owner, limits: bypassLimits{4, 4, 3}, upgrades: make(map[*trackedBypassUpgrade]struct{})}
	if !b.acquire(true) {
		t.Fatal("admission")
	}
	rw := &bypassTestReadWriteCloser{}
	transport := trackingBypassTransport{bypassTestRoundTripper(func(*http.Request) (*http.Response, error) {
		b.mu.Lock()
		b.closing = true
		b.mu.Unlock()
		return &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: rw}, nil
	}), b}
	_, err := transport.RoundTrip(httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
	if err == nil || !rw.closed {
		t.Fatal("late upgrade escaped shutdown")
	}
	b.release(true)
	if b.pending.Load() != 0 {
		t.Fatal("failed handshake retained admission")
	}
}

type bypassTestReadWriteCloser struct{ closed bool }

func (*bypassTestReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (*bypassTestReadWriteCloser) Write(b []byte) (int, error) { return len(b), nil }
func (b *bypassTestReadWriteCloser) Close() error              { b.closed = true; return nil }

type bypassTestRoundTripper func(*http.Request) (*http.Response, error)

func (f bypassTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBypassCanceledRequestReleasesAdmission(t *testing.T) {
	entered := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer upstream.Close()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: bypassTestPort(t, upstream)}}
	srv.initBypasses(st)
	defer srv.closeBypasses()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); srv.httpHandler().ServeHTTP(httptest.NewRecorder(), req) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upstream not reached")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not cancel")
	}
	if srv.bypasses["app.example.com"].pending.Load() != 0 {
		t.Fatal("cancellation retained admission")
	}
}

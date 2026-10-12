package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func bypassTestPort(t *testing.T, upstream *httptest.Server) int {
	t.Helper()
	_, rawPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestBypassProxyHTTP(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	requests := make(chan *http.Request, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		w.Header().Set("X-Upstream", "local")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: bypassTestPort(t, upstream)}}
	srv.cfg.WAFEnabled = true
	srv.cfg.WAFBodyInspectLimit = 16 * 1024
	srv.initBypasses(st)
	handler := srv.httpHandler()
	body := strings.Repeat("upload data\n", 100000)
	r := httptest.NewRequest(http.MethodPost, "https://APP.EXAMPLE.COM:10443/a%2Fb?keep=1&keep=2", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:1234"
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Authorization", "Bearer application-token")
	r.Header.Set("X-Forwarded-For", "spoofed")
	r.Header.Set("X-Real-IP", "127.0.0.1")
	r.Header.Set("X-Forwarded-Host", "spoofed.example")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("Forwarded", "for=spoofed")
	r.Header.Set("Cookie", publicAccessCookieName+"=secret; app=value")
	r.Header.Set("Connection", "X-Hop")
	r.Header.Set("X-Hop", "remove me")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || w.Body.String() != body || w.Header().Get("X-Upstream") != "local" {
		t.Fatalf("proxy response: status=%d body length=%d", w.Code, w.Body.Len())
	}
	got := <-requests
	if got.Host != r.Host || got.Method != r.Method || got.URL.EscapedPath() != "/a%2Fb" || got.URL.RawQuery != "keep=1&keep=2" {
		t.Fatalf("request changed: %s %s %s", got.Method, got.Host, got.URL)
	}
	for name, want := range map[string]string{
		"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "203.0.113.7", "X-Forwarded-Host": r.Host,
		"X-Forwarded-Proto": "https", "X-Forwarded-Port": "10443",
		"Authorization": "Bearer application-token", "Cookie": "app=value",
		"Forwarded": "", "X-Hop": "",
	} {
		if got.Header.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, got.Header.Get(name), want)
		}
	}
}

func TestBypassSecurityDefaultsAndOptOuts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	srv, st := newIncrementalTestServer(t)
	port := bypassTestPort(t, upstream)
	srv.cfg.Bypasses = []config.ServerBypass{
		{Subdomain: "secure", Port: port},
		{Subdomain: "nowaf", Port: port, DisableWAF: true},
		{Subdomain: "norate", Port: port, DisableRateLimit: true},
	}
	srv.cfg.WAFEnabled = true
	srv.cfg.WAFBodyInspectLimit = 16384
	srv.initBypasses(st)
	handler := srv.httpHandler()
	for _, tc := range []struct {
		host, path, body string
		status           int
	}{
		{"secure", "/?x=<script>alert(1)</script>", "", 403},
		{"secure", "/", `{"x":"<script>alert(1)</script>"}`, 403},
		{"nowaf", "/?x=<script>alert(1)</script>", "", 200},
		{"nowaf", "/", `{"x":"<script>alert(1)</script>"}`, 200},
		{"norate", "/?x=<script>alert(1)</script>", "", 403},
		{"other", "/?x=<script>alert(1)</script>", "", 403},
		{"nowaf", serviceapi.V1 + "/unknown?x=<script>alert(1)</script>", "", 403},
		{"nowaf", serviceapi.V1 + "/unknown", "", 404},
		{"nowaf", serviceapi.Health, "", 200},
	} {
		r := httptest.NewRequest(http.MethodPost, "https://"+tc.host+".example.com"+tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Expose-Disable-WAF", "true")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s%s body=%q: %d %s, want %d", tc.host, tc.path, tc.body, w.Code, w.Body.String(), tc.status)
		}
	}
	srv.publicLimiter = newConfiguredRateLimiter(0, 1, time.Minute)
	for _, host := range []string{"secure", "nowaf", "norate"} {
		for i := range 2 {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://"+host+".example.com/", nil))
			want := http.StatusOK
			if i == 1 && host != "norate" {
				want = http.StatusTooManyRequests
			}
			if w.Code != want {
				t.Errorf("rate limit %s request %d: %d, want %d", host, i, w.Code, want)
			}
		}
	}
}

func TestBypassRoutingPrecedenceAndIsolation(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local app"))
	}))
	defer app.Close()
	ci := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("local ci"))
	}))
	defer ci.Close()
	srv, st := newIncrementalTestServer(t)
	keyID, err := srv.store.ResolveAPIKeyID(context.Background(), auth.HashAPIKey("owner", ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePublishedSite(context.Background(), domain.PublishedSite{ID: "site_old", APIKeyID: keyID, Hostname: "app.example.com", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	srv.cfg.Bypasses = []config.ServerBypass{
		{Subdomain: "app", Port: bypassTestPort(t, app)},
		{Subdomain: "ci", Port: bypassTestPort(t, ci)},
	}
	srv.cfg.WAFEnabled = true
	srv.initBypasses(st)
	// A former tunnel's client-configured path rules must not affect a bypass.
	srv.routes.set("app.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{WAFPathRules: &domain.WAFPathRules{IgnorePaths: []string{"/"}}}})
	handler := srv.httpHandler()
	for host, want := range map[string]string{"app": "local app", "ci": "local ci"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://"+host+".example.com/", nil))
		if w.Code != http.StatusOK || w.Body.String() != want {
			t.Errorf("%s route: %d %q, want %q", host, w.Code, w.Body.String(), want)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://app.example.com/.env", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("old client WAF path opt-out affected bypass: %d", w.Code)
	}
}

func TestBypassReservedSubdomainConflict(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	srv.cfg.ConnectTokenTTL = time.Minute
	r := httptest.NewRequest(http.MethodPost, "https://example.com"+serviceapi.Register, strings.NewReader(`{"mode":"permanent","subdomain":"app","client_machine_id":"same-client"}`))
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("initial registration: %d %s", w.Code, w.Body.String())
	}
	var registered domain.RegisterResponse
	if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: 3000}}
	srv.initBypasses(st)
	for _, mode := range []string{"temporary", "permanent"} {
		r := httptest.NewRequest(http.MethodPost, "https://example.com"+serviceapi.Register, strings.NewReader(`{"mode":"`+mode+`","subdomain":"APP","client_machine_id":"same-client"}`))
		r.Header.Set("Authorization", "Bearer owner")
		r.Header.Set(domain.RegisterResumeTunnelHeader, registered.TunnelID)
		w := httptest.NewRecorder()
		srv.httpHandler().ServeHTTP(w, r)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"error_code":"hostname_in_use"`) {
			t.Fatalf("%s registration: %d %s", mode, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{serviceapi.Connect, serviceapi.ConnectH3} {
		token, err := st.CreateConnectToken(context.Background(), registered.TunnelID, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://example.com"+path+"?token="+token, nil)
		w := httptest.NewRecorder()
		srv.httpHandler().ServeHTTP(w, r)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"error_code":"hostname_in_use"`) {
			t.Fatalf("reserved tunnel connect %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	r = httptest.NewRequest(http.MethodPost, "https://example.com"+serviceapi.Sites+"?domain=app", strings.NewReader("not an archive"))
	r.Header.Set("Authorization", "Bearer owner")
	w = httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("publication: %d %s", w.Code, w.Body.String())
	}
	if err := srv.authorizeACMEHost(context.Background(), "APP.EXAMPLE.COM"); err != nil {
		t.Fatalf("reserved hostname TLS authorization: %v", err)
	}
	r = httptest.NewRequest(http.MethodPost, "https://example.com"+serviceapi.Register, strings.NewReader(`{"mode":"temporary","subdomain":"other","disable_waf":true}`))
	r.Header.Set("Authorization", "Bearer owner")
	w = httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("client security opt-out accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestBypassWebSocket(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: []string{"echo"}}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, data, err := conn.ReadMessage()
		if err == nil {
			_ = conn.WriteMessage(kind, data)
		}
	}))
	defer upstream.Close()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "ws", Port: bypassTestPort(t, upstream)}}
	srv.cfg.WAFEnabled = true
	srv.cfg.RequestTimeout = 50 * time.Millisecond
	srv.initBypasses(st)
	front := httptest.NewServer(srv.httpHandler())
	defer front.Close()
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second, Subprotocols: []string{"echo"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(front.URL, "http")+"/socket", http.Header{"Host": {"ws.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if conn.Subprotocol() != "echo" {
		t.Fatalf("subprotocol = %q", conn.Subprotocol())
	}
	// Response-body inactivity timeouts must not terminate upgraded sockets.
	time.Sleep(100 * time.Millisecond)
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, data, err := conn.ReadMessage()
	if err != nil || string(data) != "hello" {
		t.Fatalf("websocket echo = %q, %v", data, err)
	}
}

func TestBypassUnavailableAndOverloaded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	port := bypassTestPort(t, upstream)
	upstream.Close()
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "app", Port: port}}
	srv.cfg.MaxPendingPerTunnel = 1
	srv.initBypasses(st)
	handler := srv.httpHandler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("offline upstream: %d", w.Code)
	}
	route := srv.bypasses["app.example.com"]
	route.pending.Store(1)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil))
	if w.Code != http.StatusServiceUnavailable || route.pending.Load() != 1 {
		t.Fatalf("overloaded upstream: %d pending=%d", w.Code, route.pending.Load())
	}
}

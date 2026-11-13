package client

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

func TestRegisterDelegatedAccessOmitsEdgeCredentials(t *testing.T) {
	t.Parallel()
	payload := make(chan domain.RegisterRequest, 1)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req domain.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		payload <- req
		_, _ = io.WriteString(w, `{"ws_url":"wss://example.com/connect"}`)
	}))
	defer api.Close()
	c := New(config.ClientConfig{
		ServerURL: api.URL, APIKey: "key", LocalPort: 8080,
		ProtectMode: access.ModeUpstreamBasic, User: "operator", Password: "not-an-app-password",
	}, nil)
	if _, err := c.register(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := <-payload
	if got.AccessMode != access.ModeUpstreamBasic || got.User != "" || got.Password != "" {
		t.Fatal("delegated registration leaked edge credentials")
	}
}

func TestDelegatedAccessEndToEnd(t *testing.T) {
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			var reject atomic.Bool
			var requests atomic.Int64
			h := newEndToEndProtectedTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				user, password, ok := r.BasicAuth()
				if !ok || user != "alice" || password != " app:password " || reject.Load() {
					w.Header().Set("WWW-Authenticate", `Basic realm="local-app"`)
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, "upstream rejection must not be returned")
					return
				}
				if strings.Contains(r.Header.Get("Cookie"), access.CookieName) {
					t.Error("expose session cookie reached the local app")
				}
				if r.URL.Path == "/socket" {
					conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
					if err == nil {
						_ = conn.WriteMessage(websocket.TextMessage, []byte("authenticated"))
						_ = conn.Close()
					}
					return
				}
				if r.Method == http.MethodGet {
					if body, _ := io.ReadAll(r.Body); len(body) != 0 {
						t.Error("login form body reached upstream")
					}
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "app accepted "+r.Method)
			}), 5*time.Second, access.ModeUpstreamBasic)
			h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			send := func(method, path, body string, cookie *http.Cookie) *http.Response {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), method, h.url+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "bench.example.com"
				if method == http.MethodPost {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				if cookie != nil {
					req.AddCookie(cookie)
					req.Header.Set("Authorization", "Bearer must-not-override")
				}
				resp, err := h.client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				return resp
			}
			check := func(resp *http.Response, status int, contains string) {
				t.Helper()
				defer func() { _ = resp.Body.Close() }()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != status || !strings.Contains(string(body), contains) || resp.Header.Get("WWW-Authenticate") != "" {
					t.Fatalf("response: status=%d body=%q challenge=%q", resp.StatusCode, body, resp.Header.Get("WWW-Authenticate"))
				}
			}
			check(send(http.MethodGet, "/private", "", nil), http.StatusUnauthorized, "application's credentials")
			if requests.Load() != 0 {
				t.Fatal("unauthenticated public request reached upstream")
			}
			form := url.Values{
				access.FormActionField: {"login"}, access.FormUserField: {"alice"},
				access.FormPasswordField: {"wrong"}, access.FormNextField: {"/private?tab=1"},
			}
			check(send(http.MethodPost, "/private", form.Encode(), nil), http.StatusUnauthorized, "Incorrect username or password.")
			form.Set(access.FormPasswordField, " app:password ")
			login := send(http.MethodPost, "/private", form.Encode(), nil)
			var cookie *http.Cookie
			for _, candidate := range login.Cookies() {
				if candidate.Name == access.CookieName {
					cookie = candidate
				}
			}
			if cookie == nil || !cookie.Secure || !cookie.HttpOnly || login.Header.Get("Location") != "/private?tab=1" {
				t.Fatal("missing secure session and safe redirect")
			}
			check(login, http.StatusSeeOther, "")
			check(send(http.MethodGet, "/private?tab=1", "", cookie), http.StatusOK, "app accepted GET")
			check(send(http.MethodPost, "/private", "app=data", cookie), http.StatusOK, "app accepted POST")

			headers := http.Header{"Host": {"bench.example.com"}, "Cookie": {cookie.String()}, "Origin": {"https://bench.example.com"}}
			dialer := websocket.Dialer{TLSClientConfig: h.client.Transport.(*http.Transport).TLSClientConfig.Clone()}
			dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
			conn, resp, err := dialer.DialContext(t.Context(), "wss"+strings.TrimPrefix(h.url, "https")+"/socket", headers)
			if err != nil {
				t.Fatalf("authenticated websocket failed: %v, response=%v", err, resp)
			}
			_, message, err := conn.ReadMessage()
			_ = conn.Close()
			if err != nil || string(message) != "authenticated" {
				t.Fatalf("websocket message=%q error=%v", message, err)
			}
			reject.Store(true)
			_, resp, err = dialer.DialContext(t.Context(), "wss"+strings.TrimPrefix(h.url, "https")+"/socket", headers)
			if err == nil || resp == nil {
				t.Fatal("upstream websocket rejection ignored")
			}
			if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "" {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("websocket challenge escaped delegated form handling: %d %v %s", resp.StatusCode, resp.Header, body)
			}
			_ = resp.Body.Close()
			before := requests.Load()
			check(send(http.MethodGet, "/private", "", cookie), http.StatusUnauthorized, "application's credentials")
			if requests.Load() != before {
				t.Fatal("revoked session reached upstream")
			}
		})
	}
}

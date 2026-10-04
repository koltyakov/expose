package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

var applicationServicePaths = []string{
	"/v1/auth", "/v1/sites", "/v1/sites/docs/stats",
	"/v1/tunnels/register", "/v1/tunnels/connect",
	"/v1/tunnels/connect-h3", "/v1/tunnels/connect-h3/stream",
	"/healthz", "/_expose/v10/app",
}

func TestServiceNamespacePublishedSiteAndWAF(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	srv.cfg.WAFEnabled = true
	srv.cfg.WAFBodyInspectLimit = 16 * 1024
	handler := srv.httpHandler()
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", "site root")
	for _, path := range applicationServicePaths {
		writeIncrementalTestFile(t, root, strings.TrimPrefix(path, "/")+"/index.html", "site:"+path)
	}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		t.Fatal(err)
	}
	upload := httptest.NewRequest(http.MethodPost, "https://example.com/_expose/v1/sites?domain=docs", &archive)
	upload.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, upload)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish through service API: %d %s", w.Code, w.Body.String())
	}
	for _, path := range applicationServicePaths {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://docs.example.com"+path+"/", nil))
		if w.Code != http.StatusOK || w.Body.String() != "site:"+path {
			t.Errorf("application path %s: %d %q", path, w.Code, w.Body.String())
		}
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/_expose/healthz?x=<script>alert(1)</script>", http.StatusOK},
		{"/_expose/v1/sites", http.StatusUnauthorized},
		{"/_expose/v1/unknown", http.StatusNotFound},
		{"/_expose/v1", http.StatusNotFound},
		{"/healthz?x=<script>alert(1)</script>", http.StatusForbidden},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://docs.example.com"+tc.path, nil))
		if w.Code != tc.status {
			t.Errorf("%s: status %d, want %d", tc.path, w.Code, tc.status)
		}
	}
	for _, path := range []string{"/v1/auth", "/healthz"} {
		r := httptest.NewRequest(http.MethodPost, "https://docs.example.com"+path, strings.NewReader(`{"input":"<script>alert(1)</script>"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("application body WAF %s: status %d", path, w.Code)
		}
	}
}

func TestServiceNamespaceTunnelForwarding(t *testing.T) {
	srv, _ := newIncrementalTestServer(t)
	srv.cfg.ConnectTokenTTL = time.Minute
	srv.cfg.RequestTimeout = 5 * time.Second
	srv.cfg.ClientPingTimeout = time.Minute
	server := httptest.NewServer(srv.httpHandler())
	defer server.Close()
	defer func() {
		srv.forceCloseAllSessions("test complete")
		srv.hub.wg.Wait()
	}()

	r := httptest.NewRequest(http.MethodPost, "https://example.com/_expose/v1/tunnels/register", strings.NewReader(`{"mode":"temporary","subdomain":"app","local_port":"3000"}`))
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	srv.httpHandler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg domain.RegisterResponse
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil {
		t.Fatal(err)
	}
	connect, err := url.Parse(reg.WSURL)
	if err != nil {
		t.Fatal(err)
	}
	if connect.Path != "/_expose/v1/tunnels/connect" {
		t.Fatalf("connect URL: %s", reg.WSURL)
	}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+connect.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatal(err)
	}
	var pong tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(conn, &pong); err != nil {
		t.Fatal(err)
	}
	if pong.Kind != tunnelproto.KindPong {
		t.Fatalf("not ready: %s", pong.Kind)
	}
	public, err := url.Parse(reg.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range applicationServicePaths {
		t.Run(path, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				var msg tunnelproto.Message
				if err := tunnelproto.ReadWSMessage(conn, &msg); err != nil {
					done <- err
					return
				}
				if msg.Kind != tunnelproto.KindRequest || msg.Request == nil {
					done <- io.ErrUnexpectedEOF
					return
				}
				req := msg.Request
				body := req.Method + ":" + req.Path + "?" + req.Query + ":" + http.Header(req.Headers).Get("Authorization")
				done <- conn.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{
					ID: req.ID, Status: http.StatusOK, BodyB64: base64.StdEncoding.EncodeToString([]byte(body)),
				}})
			}()
			req, err := http.NewRequest(http.MethodGet, server.URL+path+"?keep=1", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = public.Host
			req.Header.Set("Authorization", "Bearer application-token")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			want := "GET:" + path + "?keep=1:Bearer application-token"
			if resp.StatusCode != http.StatusOK || string(body) != want {
				t.Fatalf("forward: %d %q, want %q", resp.StatusCode, body, want)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
		if t.Failed() {
			break
		}
	}
}

package server

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/turn/v5"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/turnrelay"
)

func TestWebRTCSignalingBehindBypass(t *testing.T) {
	secret := strings.Repeat("signaling-test-secret", 2)
	var backendICE atomic.Value
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("GET /ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool {
			return r.Header.Get("Origin") == "https://"+r.Host
		}}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteJSON(map[string]any{"iceServers": []turnrelay.ICEServer{backendICE.Load().(turnrelay.ICEServer)}}); err != nil {
			return
		}
		for {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(kind, data); err != nil {
				return
			}
		}
	})
	upstream := httptest.NewServer(mux)
	t.Cleanup(upstream.Close)
	srv, st := newIncrementalTestServer(t)
	srv.cfg.Bypasses = []config.ServerBypass{{Subdomain: "signal", Port: bypassTestPort(t, upstream)}}
	srv.cfg.WAFEnabled = true
	srv.cfg.WAFBodyInspectLimit = 16 * 1024
	srv.cfg.RequestTimeout = 250 * time.Millisecond
	srv.initBypasses(st)
	front := httptest.NewTLSServer(srv.httpHandler())
	t.Cleanup(front.Close)

	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	allocationPort := socket.LocalAddr().(*net.UDPAddr).Port
	_ = socket.Close()
	relay, err := turnrelay.Start(config.TURNConfig{
		Enabled: true, ListenUDP: "127.0.0.1:0", ListenTCP: "127.0.0.1:0", ListenTLS: "127.0.0.1:0",
		Host: "127.0.0.1", PublicIP: "127.0.0.1", RelayAddress: "127.0.0.1", Realm: "example.com",
		Secret: secret, MinPort: allocationPort, MaxPort: allocationPort,
		MaxAllocations: 8, MaxConnections: 8, CredentialTTL: time.Hour,
	}, front.TLS, srv.log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = relay.Close() })
	// A separate trusted backend can mint standard TURN REST credentials.
	username, password, err := turn.GenerateLongTermTURNRESTCredentials(secret, "test-peer", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ice := turnrelay.ICEServer{URLs: relay.URLs(), Username: username, Credential: password}
	backendICE.Store(ice)

	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/healthz", http.StatusOK},
		{"/healthz?x=%3Cscript%3Ealert(1)%3C/script%3E", http.StatusForbidden},
	} {
		req, err := http.NewRequest(http.MethodGet, front.URL+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "signal.example.com"
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %d, want %d", tc.path, resp.StatusCode, tc.status)
		}
	}
	trust := front.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	dialer := websocket.Dialer{TLSClientConfig: trust, HandshakeTimeout: 3 * time.Second}
	endpoint := "wss" + strings.TrimPrefix(front.URL, "https") + "/ws"
	bad, resp, err := dialer.Dial(endpoint, http.Header{"Host": {"signal.example.com"}, "Origin": {"https://untrusted.example"}})
	if bad != nil {
		_ = bad.Close()
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatal("upstream origin check was not preserved")
	}
	conn, _, err := dialer.Dial(endpoint, http.Header{"Host": {"signal.example.com"}, "Origin": {"https://signal.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var credentials turnrelay.Credentials
	if err := conn.ReadJSON(&credentials); err != nil || len(credentials.ICEServers) != 1 {
		t.Fatalf("ICE credential delivery: %+v, %v", credentials, err)
	}
	received := credentials.ICEServers[0]
	if !slices.Equal(received.URLs, ice.URLs) || received.Username != ice.Username || received.Credential != ice.Credential {
		t.Fatal("ICE credentials changed during proxying")
	}
	for _, rawURL := range received.URLs {
		t.Run(rawURL, func(t *testing.T) {
			checkSignalingTURNAllocation(t, rawURL, received, trust)
		})
	}
	// Upgraded signaling connections must outlive the HTTP request deadline.
	<-time.After(2 * srv.cfg.RequestTimeout)
	pongs := make(chan string, 1)
	conn.SetPongHandler(func(data string) error {
		select {
		case pongs <- data:
		default:
		}
		return nil
	})
	if err := conn.WriteControl(websocket.PingMessage, []byte("keepalive"), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// SDP and ICE candidates are WebSocket messages, not HTTP request bodies.
	payload := json.RawMessage(`{"sdp":"v=0\r\na=fingerprint:sha-256 AA:BB\r\n","candidate":"candidate:1 1 UDP 1 203.0.113.1 49160 typ relay"}`)
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatal(err)
	}
	_, forwarded, err := conn.ReadMessage()
	if err != nil || string(forwarded) != string(payload) {
		t.Fatalf("signaling payload changed or connection expired: %q, %v", forwarded, err)
	}
	select {
	case data := <-pongs:
		if data != "keepalive" {
			t.Fatalf("WebSocket control payload changed: %q", data)
		}
	default:
		t.Fatal("WebSocket ping/pong control frames were not forwarded")
	}
}

func checkSignalingTURNAllocation(t *testing.T, rawURL string, ice turnrelay.ICEServer, trust *tls.Config) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	var socket net.PacketConn
	if u.Query().Get("transport") == "udp" {
		socket, err = net.ListenPacket("udp4", "127.0.0.1:0")
	} else {
		var conn net.Conn
		if u.Scheme == "turns" {
			conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp4", u.Opaque, trust)
		} else {
			conn, err = net.DialTimeout("tcp4", u.Opaque, 3*time.Second)
		}
		if err == nil {
			socket = turn.NewSTUNConn(conn)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	client, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: u.Opaque, Conn: socket, Username: ice.Username, Password: ice.Credential, RTO: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	allocated, err := client.Allocate()
	if err != nil {
		t.Fatalf("backend-issued credentials rejected by Expose TURN: %v", err)
	}
	t.Cleanup(func() { _ = allocated.Close() })
	if addr, ok := allocated.LocalAddr().(*net.UDPAddr); !ok || addr.Port == 0 {
		t.Fatalf("invalid relay candidate: %s", allocated.LocalAddr())
	}
}

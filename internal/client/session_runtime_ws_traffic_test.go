package client

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func TestClientSessionRuntimeTracksWebSocketTraffic(t *testing.T) {
	t.Parallel()

	recorder := &testTrafficRecorder{}

	localClientConn, localServerConn, closeLocal := dialTestWebSocketPair(t)
	defer closeLocal()

	rt := &clientSessionRuntime{
		client:  &Client{trafficSink: recorder},
		wsConns: map[string]*websocket.Conn{"ws_traffic": localClientConn},
	}

	rt.handleWSData(&tunnelproto.WSData{
		ID:          "ws_traffic",
		MessageType: websocket.TextMessage,
		Data:        []byte("ping"),
	})

	msgType, payload, err := localServerConn.ReadMessage()
	if err != nil {
		t.Fatalf("read local websocket message: %v", err)
	}
	if msgType != websocket.TextMessage || string(payload) != "ping" {
		t.Fatalf("unexpected local websocket payload: type=%d payload=%q", msgType, string(payload))
	}
	if got := recorder.inbound.Load(); got != int64(len("ping")) {
		t.Fatalf("expected inbound bytes %d, got %d", len("ping"), got)
	}

	tunnelClientConn, tunnelServerConn, closeTunnel := dialTestWebSocketPair(t)
	defer closeTunnel()

	rt.writer = tunneltransport.NewWebSocketWritePump(tunnelClientConn, time.Second, 8, 8)
	defer rt.writer.Close()
	rt.startLocalWSReader("ws_traffic", localClientConn)

	if err := localServerConn.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
		t.Fatalf("write local websocket response: %v", err)
	}
	if _, _, err := tunnelServerConn.ReadMessage(); err != nil {
		t.Fatalf("read tunneled websocket frame: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if recorder.outbound.Load() == int64(len("pong")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := recorder.outbound.Load(); got != int64(len("pong")) {
		t.Fatalf("expected outbound bytes %d, got %d", len("pong"), got)
	}

	_ = localClientConn.Close()
	rt.requestWG.Wait()
}

func dialTestWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	connCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade test websocket: %v", err)
			return
		}
		connCh <- conn
	}))

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		srv.Close()
		t.Fatalf("dial test websocket: %v", err)
	}

	var serverConn *websocket.Conn
	select {
	case serverConn = <-connCh:
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		srv.Close()
		t.Fatal("timed out waiting for websocket upgrade")
	}

	cleanup := func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		srv.Close()
	}
	return clientConn, serverConn, cleanup
}

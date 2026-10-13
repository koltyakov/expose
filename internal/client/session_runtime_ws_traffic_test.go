package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		client: &Client{trafficSink: recorder},
	}
	if !rt.setWSConn("ws_traffic", localClientConn) {
		t.Fatal("register local websocket")
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
	// The writer records traffic just after the local write completes.
	for deadline := time.Now().Add(2 * time.Second); recorder.inbound.Load() != int64(len("ping")) && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
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
	errCh := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			recordAsyncTestError(errCh, "upgrade test websocket: %v", err)
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
	case err := <-errCh:
		_ = clientConn.Close()
		srv.Close()
		t.Fatal(err)
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

func TestSlowLocalWebSocketHandshakeDoesNotBlockTunnelMessages(t *testing.T) {
	t.Parallel()

	releaseHandshake := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-releaseHandshake
		conn, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer local.Close()
	defer close(releaseHandshake)
	base, err := url.Parse(local.URL)
	if err != nil {
		t.Fatal(err)
	}

	tunnelClientConn, _, closeTunnel := dialTestWebSocketPair(t)
	defer closeTunnel()
	localClientConn, localServerConn, closeLocal := dialTestWebSocketPair(t)
	defer closeLocal()

	ctx, cancel := context.WithCancel(context.Background())
	rt := &clientSessionRuntime{client: &Client{}, ctx: ctx, cancel: cancel, localBase: base}
	rt.writer = tunneltransport.NewWebSocketWritePump(tunnelClientConn, time.Second, 8, 8)
	defer func() {
		cancel()
		rt.writer.Close()
		rt.closeWSConns()
	}()
	if !rt.setWSConn("ws_existing", localClientConn) {
		t.Fatal("register local websocket")
	}

	handled := make(chan error, 1)
	go func() {
		if err := rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindWSOpen, WSOpen: &tunnelproto.WSOpen{ID: "ws_slow", Method: http.MethodGet, Path: "/slow"}}); err != nil {
			handled <- err
			return
		}
		handled <- rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindWSData, WSData: &tunnelproto.WSData{ID: "ws_existing", MessageType: websocket.TextMessage, Data: []byte("still flowing")}})
	}()
	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("message loop blocked behind a local websocket handshake")
	}
	_ = localServerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, payload, err := localServerConn.ReadMessage(); err != nil || string(payload) != "still flowing" {
		t.Fatalf("existing stream did not receive data during the slow handshake: %q, %v", payload, err)
	}
}

func TestOverflowingLocalWebSocketIsClosedWithoutBlocking(t *testing.T) {
	t.Parallel()

	tunnelClientConn, tunnelServerConn, closeTunnel := dialTestWebSocketPair(t)
	defer closeTunnel()
	localClientConn, _, closeLocal := dialTestWebSocketPair(t)
	defer closeLocal()

	rt := &clientSessionRuntime{client: &Client{}}
	rt.writer = tunneltransport.NewWebSocketWritePump(tunnelClientConn, time.Second, 8, 8)
	defer rt.writer.Close()
	// No writer goroutine drains this stream, as if its local consumer stalled.
	stream := &localWebSocket{conn: localClientConn, writes: make(chan localWSWrite, 2), done: make(chan struct{})}
	rt.wsConns = map[string]*localWebSocket{"ws_stalled": stream}

	started := time.Now()
	for range 3 {
		rt.handleWSData(&tunnelproto.WSData{ID: "ws_stalled", MessageType: websocket.BinaryMessage, Data: []byte("x")})
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("a stalled local consumer blocked the message loop for %v", elapsed)
	}
	if _, ok := rt.getWSConn("ws_stalled"); ok {
		t.Fatal("overflowing stream was not closed")
	}
	_ = tunnelServerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(tunnelServerConn, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Kind != tunnelproto.KindWSClose || msg.WSClose == nil || msg.WSClose.ID != "ws_stalled" || msg.WSClose.Code != websocket.ClosePolicyViolation {
		t.Fatalf("expected a policy-violation close for the stalled stream, got %#v", msg)
	}
}

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func TestWaitForPublicWSOpenAck(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	streamCh := make(chan tunnelproto.Message, 2)
	streamCh <- tunnelproto.Message{Kind: tunnelproto.KindPing}
	streamCh <- tunnelproto.Message{
		Kind: tunnelproto.KindWSOpenAck,
		WSOpenAck: &tunnelproto.WSOpenAck{
			ID:     "ws_1",
			OK:     true,
			Status: http.StatusSwitchingProtocols,
		},
	}

	ack, status, message := srv.waitForPublicWSOpenAck(
		httptest.NewRequest(http.MethodGet, "https://demo.example.com/ws", nil),
		time.NewTimer(time.Second),
		streamCh,
	)
	if ack == nil || ack.ID != "ws_1" || status != 0 || message != "" {
		t.Fatalf("waitForPublicWSOpenAck() = (%+v, %d, %q)", ack, status, message)
	}
}

func TestWaitForPublicWSOpenAckErrors(t *testing.T) {
	t.Parallel()

	srv := &Server{}

	req, cancel := context.WithCancel(context.Background())
	cancel()
	_, status, message := srv.waitForPublicWSOpenAck(
		httptest.NewRequest(http.MethodGet, "https://demo.example.com/ws", nil).WithContext(req),
		time.NewTimer(time.Second),
		make(chan tunnelproto.Message),
	)
	if status != 0 || message != "" {
		t.Fatalf("canceled wait = (%d, %q), want zero values", status, message)
	}

	streamCh := make(chan tunnelproto.Message)
	close(streamCh)
	_, status, message = srv.waitForPublicWSOpenAck(
		httptest.NewRequest(http.MethodGet, "https://demo.example.com/ws", nil),
		time.NewTimer(time.Second),
		streamCh,
	)
	if status != http.StatusBadGateway || message != "tunnel closed" {
		t.Fatalf("closed tunnel = (%d, %q)", status, message)
	}

	_, status, message = srv.waitForPublicWSOpenAck(
		httptest.NewRequest(http.MethodGet, "https://demo.example.com/ws", nil),
		time.NewTimer(10*time.Millisecond),
		make(chan tunnelproto.Message),
	)
	if status != http.StatusGatewayTimeout || message != "upstream timeout" {
		t.Fatalf("timed out wait = (%d, %q)", status, message)
	}
}

func TestPublicWSOpenFailure(t *testing.T) {
	t.Parallel()

	if status, message := publicWSOpenFailure(&tunnelproto.WSOpenAck{Status: 0}); status != http.StatusBadGateway || message != "websocket upstream open failed" {
		t.Fatalf("publicWSOpenFailure(default) = (%d, %q)", status, message)
	}
	if status, message := publicWSOpenFailure(&tunnelproto.WSOpenAck{Status: http.StatusForbidden, Error: "forbidden"}); status != http.StatusForbidden || message != "forbidden" {
		t.Fatalf("publicWSOpenFailure(custom) = (%d, %q)", status, message)
	}
}

func TestStartPublicWSWriteRelayWritesDataAndClose(t *testing.T) {
	t.Parallel()

	publicConn, peerConn := newServerWebSocketPair(t)
	defer closeServerWebSocketPair(publicConn, peerConn)

	srv := &Server{hub: &hub{}}
	streamCh := make(chan tunnelproto.Message, 2)
	relayStop := make(chan struct{})
	writeDone := make(chan struct{})
	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/ws", nil)

	srv.startPublicWSWriteRelay(req, publicConn, streamCh, relayStop, writeDone)
	streamCh <- tunnelproto.Message{
		Kind: tunnelproto.KindWSData,
		WSData: &tunnelproto.WSData{
			ID:          "ws_1",
			MessageType: websocket.TextMessage,
			Data:        []byte("hello"),
		},
	}

	if err := peerConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	msgType, payload, err := peerConn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if msgType != websocket.TextMessage || string(payload) != "hello" {
		t.Fatalf("ReadMessage() = (%d, %q)", msgType, payload)
	}

	streamCh <- tunnelproto.Message{
		Kind: tunnelproto.KindWSClose,
		WSClose: &tunnelproto.WSClose{
			ID:   "ws_1",
			Code: websocket.CloseNormalClosure,
			Text: "bye",
		},
	}

	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for write relay to stop")
	}
}

func TestStartPublicWSReadRelayWritesWSFramesAndClose(t *testing.T) {
	t.Parallel()

	publicConn, peerConn := newServerWebSocketPair(t)
	defer closeServerWebSocketPair(publicConn, peerConn)

	writerConn, writerPeer := newServerWebSocketPair(t)
	defer closeServerWebSocketPair(writerConn, writerPeer)

	srv := &Server{hub: &hub{}}
	sess := &session{
		writer: tunneltransport.NewWebSocketWritePump(writerConn, time.Second, 8, 8),
	}
	defer sess.writer.Close()

	readDone := make(chan struct{})
	srv.startPublicWSReadRelay("ws_1", sess, publicConn, readDone)

	if err := peerConn.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatalf("WriteMessage() error = %v", err)
	}

	if err := writerPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	var first tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(writerPeer, &first); err != nil {
		t.Fatalf("ReadWSMessage(first) error = %v", err)
	}
	if first.Kind != tunnelproto.KindWSData || first.WSData == nil {
		t.Fatalf("unexpected first message: %+v", first)
	}
	payload, err := first.WSData.Payload()
	if err != nil {
		t.Fatalf("Payload() error = %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("payload = %q, want %q", payload, "hello")
	}

	if err := peerConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "closing"), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("WriteControl() error = %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for read relay to stop")
	}

	if err := writerPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}
	var second tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(writerPeer, &second); err != nil {
		t.Fatalf("ReadWSMessage(second) error = %v", err)
	}
	if second.Kind != tunnelproto.KindWSClose || second.WSClose == nil || second.WSClose.Code != websocket.CloseGoingAway {
		t.Fatalf("unexpected close message: %+v", second)
	}
	if !strings.Contains(second.WSClose.Text, "closing") {
		t.Fatalf("close text = %q, want substring %q", second.WSClose.Text, "closing")
	}
}

func newServerWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	serverConnCh := make(chan *websocket.Conn, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade() error = %v", err)
			return
		}
		serverConnCh <- conn
	}))
	t.Cleanup(server.Close)

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Dial(%q) error = %v", url, err)
	}

	select {
	case serverConn := <-serverConnCh:
		return clientConn, serverConn
	case <-time.After(time.Second):
		_ = clientConn.Close()
		t.Fatal("timed out waiting for websocket upgrade")
		return nil, nil
	}
}

func closeServerWebSocketPair(clientConn, serverConn *websocket.Conn) {
	if clientConn != nil {
		_ = clientConn.Close()
	}
	if serverConn != nil {
		_ = serverConn.Close()
	}
}

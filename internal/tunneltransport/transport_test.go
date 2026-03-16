package tunneltransport

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type unknownTransport struct{}

func (unknownTransport) ReadMessage(*tunnelproto.Message) error { return nil }
func (unknownTransport) SetReadLimit(int64)                     {}
func (unknownTransport) Close() error                           { return nil }

type testStream struct {
	bytes.Buffer
	closeErr    error
	deadlineErr error
	deadlines   []time.Time
}

func (s *testStream) Close() error {
	return s.closeErr
}

func (s *testStream) SetWriteDeadline(deadline time.Time) error {
	if s.deadlineErr != nil {
		return s.deadlineErr
	}
	s.deadlines = append(s.deadlines, deadline)
	return nil
}

func TestNameOf(t *testing.T) {
	t.Parallel()

	if got := NameOf(nil); got != "" {
		t.Fatalf("NameOf(nil) = %q, want empty string", got)
	}
	if got := NameOf(unknownTransport{}); got != "unknown" {
		t.Fatalf("NameOf(unknownTransport) = %q, want %q", got, "unknown")
	}
	if got := NameOf(NewStreamTransport("quic", &testStream{}, nil)); got != "quic" {
		t.Fatalf("NameOf(stream) = %q, want %q", got, "quic")
	}
}

func TestStreamTransportReadsAndCloses(t *testing.T) {
	t.Parallel()

	stream := &testStream{}
	if err := tunnelproto.WriteStreamJSON(stream, tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatalf("WriteStreamJSON() error = %v", err)
	}

	closeErr := errors.New("close failure")
	closed := false
	transport := NewStreamTransport("stream", stream, func() error {
		closed = true
		return closeErr
	})
	transport.SetReadLimit(1024)

	var got tunnelproto.Message
	if err := transport.ReadMessage(&got); err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got.Kind != tunnelproto.KindPing {
		t.Fatalf("ReadMessage() kind = %q, want %q", got.Kind, tunnelproto.KindPing)
	}
	if transport.Name() != "stream" {
		t.Fatalf("Name() = %q, want %q", transport.Name(), "stream")
	}
	if err := transport.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if !closed {
		t.Fatal("Close() did not invoke closeFn")
	}
}

func TestStreamTransportV2ReadsBinaryFrames(t *testing.T) {
	t.Parallel()

	stream := &testStream{}
	wantPayload := []byte("payload")
	if err := tunnelproto.WriteStreamBinaryFrameV2(stream, tunnelproto.BinaryFrameRespBody, "req-1", 0, wantPayload); err != nil {
		t.Fatalf("WriteStreamBinaryFrameV2() error = %v", err)
	}

	transport := NewStreamTransportV2("quic", stream, nil)
	transport.SetReadLimit(1024)

	var got tunnelproto.Message
	if err := transport.ReadMessage(&got); err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got.Kind != tunnelproto.KindRespBody || got.BodyChunk == nil {
		t.Fatalf("unexpected message: %#v", got)
	}
	payload, err := got.BodyChunk.Payload()
	if err != nil {
		t.Fatalf("BodyChunk.Payload() error = %v", err)
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Fatalf("payload = %q, want %q", payload, wantPayload)
	}
}

func TestStreamTransportCloseHandlesNilStream(t *testing.T) {
	t.Parallel()

	if err := (&StreamTransport{}).Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
}

func TestWebSocketTransportReadsMessages(t *testing.T) {
	clientConn, serverConn := newWebSocketPair(t)
	defer closeWebSocketPair(clientConn, serverConn)

	transport := NewWebSocketTransport(clientConn)
	transport.SetReadLimit(1024)

	if err := serverConn.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	var got tunnelproto.Message
	if err := transport.ReadMessage(&got); err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got.Kind != tunnelproto.KindPing {
		t.Fatalf("ReadMessage() kind = %q, want %q", got.Kind, tunnelproto.KindPing)
	}
	if transport.Name() != "ws" {
		t.Fatalf("Name() = %q, want %q", transport.Name(), "ws")
	}
	if got := NameOf(transport); got != "ws" {
		t.Fatalf("NameOf(transport) = %q, want %q", got, "ws")
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWebSocketTransportCloseHandlesNilConn(t *testing.T) {
	t.Parallel()

	if err := (&WebSocketTransport{}).Close(); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
}

func TestWebSocketWritePumpWritesMessages(t *testing.T) {
	clientConn, serverConn := newWebSocketPair(t)
	defer closeWebSocketPair(clientConn, serverConn)

	pump := NewWebSocketWritePump(clientConn, time.Second, 4, 4)
	defer pump.Close()

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var got tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(serverConn, &got); err != nil {
		t.Fatalf("ReadWSMessage() error = %v", err)
	}
	if got.Kind != tunnelproto.KindPing {
		t.Fatalf("first message kind = %q, want %q", got.Kind, tunnelproto.KindPing)
	}

	serverConn.SetReadDeadline(time.Now().Add(time.Second))
	if err := pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "req-1", 0, []byte("body")); err != nil {
		t.Fatalf("WriteBinaryFrame() error = %v", err)
	}

	var frameMsg tunnelproto.Message
	if err := tunnelproto.ReadWSMessage(serverConn, &frameMsg); err != nil {
		t.Fatalf("ReadWSMessage() error = %v", err)
	}
	if frameMsg.Kind != tunnelproto.KindRespBody || frameMsg.BodyChunk == nil {
		t.Fatalf("unexpected frame message: %#v", frameMsg)
	}
	payload, err := frameMsg.BodyChunk.Payload()
	if err != nil {
		t.Fatalf("BodyChunk.Payload() error = %v", err)
	}
	if !bytes.Equal(payload, []byte("body")) {
		t.Fatalf("payload = %q, want %q", payload, []byte("body"))
	}
}

func TestWebSocketWritePumpHandlesNilConn(t *testing.T) {
	t.Parallel()

	pump := NewWebSocketWritePump(nil, time.Second, 1, 1)
	defer pump.Close()

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("WriteJSON() error = %v, want %v", err, ErrWritePumpClosed)
	}
}

func TestStreamWritePumpWritesMessages(t *testing.T) {
	t.Parallel()

	stream := &testStream{}
	pump := NewStreamWritePump(stream, time.Second, 4, 4, nil)
	defer pump.Close()

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	if err := pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "req-1", 0, []byte("body")); err != nil {
		t.Fatalf("WriteBinaryFrame() error = %v", err)
	}

	var first tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(stream, 1024, &first); err != nil {
		t.Fatalf("ReadStreamMessage() error = %v", err)
	}
	if first.Kind != tunnelproto.KindPing {
		t.Fatalf("first message kind = %q, want %q", first.Kind, tunnelproto.KindPing)
	}

	var second tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(stream, 1024, &second); err != nil {
		t.Fatalf("ReadStreamMessage() error = %v", err)
	}
	if second.Kind != tunnelproto.KindRespBody || second.BodyChunk == nil {
		t.Fatalf("unexpected second message: %#v", second)
	}

	if len(stream.deadlines) == 0 {
		t.Fatal("expected write deadlines to be applied")
	}
}

func TestStreamWritePumpV2WritesMessages(t *testing.T) {
	t.Parallel()

	stream := &testStream{}
	pump := NewStreamWritePumpV2(stream, time.Second, 4, 4, nil)
	defer pump.Close()

	if err := pump.WriteBinaryFrame(tunnelproto.BinaryFrameRespBody, "req-1", 0, []byte("body")); err != nil {
		t.Fatalf("WriteBinaryFrame() error = %v", err)
	}

	var got tunnelproto.Message
	if err := tunnelproto.ReadStreamMessageV2(stream, 1024, &got); err != nil {
		t.Fatalf("ReadStreamMessageV2() error = %v", err)
	}
	if got.Kind != tunnelproto.KindRespBody || got.BodyChunk == nil {
		t.Fatalf("unexpected message: %#v", got)
	}
}

func TestStreamWritePumpHandlesDeadlineErrorAndNilStream(t *testing.T) {
	t.Parallel()

	deadlineErr := errors.New("deadline failed")
	stream := &testStream{deadlineErr: deadlineErr}
	closed := false
	pump := NewStreamWritePump(stream, time.Second, 1, 1, func() {
		closed = true
	})
	defer pump.Close()

	if err := pump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); !errors.Is(err, deadlineErr) {
		t.Fatalf("WriteJSON() error = %v, want %v", err, deadlineErr)
	}
	if !closed {
		t.Fatal("expected closeFn to run on deadline error")
	}

	nilPump := NewStreamWritePump(nil, time.Second, 1, 1, nil)
	defer nilPump.Close()
	if err := nilPump.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); !errors.Is(err, ErrWritePumpClosed) {
		t.Fatalf("WriteJSON() error = %v, want %v", err, ErrWritePumpClosed)
	}
}

func newWebSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
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

func closeWebSocketPair(clientConn, serverConn *websocket.Conn) {
	if clientConn != nil {
		_ = clientConn.Close()
	}
	if serverConn != nil {
		_ = serverConn.Close()
	}
}

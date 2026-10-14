package server

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type blockedRegressionSessionWriter struct {
	release chan struct{}
	async   chan tunnelproto.Message
}

func (w *blockedRegressionSessionWriter) WriteJSON(tunnelproto.Message) error {
	<-w.release
	return nil
}
func (w *blockedRegressionSessionWriter) WriteJSONAsync(msg tunnelproto.Message) error {
	w.async <- msg
	return nil
}
func (*blockedRegressionSessionWriter) WriteBinaryFrame(byte, string, int, []byte) error { return nil }
func (*blockedRegressionSessionWriter) Close()                                           {}

type regressionMessageTransport struct {
	msgs   chan tunnelproto.Message
	closed chan struct{}
	once   sync.Once
}

func (s *regressionMessageTransport) ReadMessage(dst *tunnelproto.Message) error {
	select {
	case *dst = <-s.msgs:
		return nil
	case <-s.closed:
		return io.EOF
	}
}
func (*regressionMessageTransport) SetReadLimit(int64) {}
func (s *regressionMessageTransport) Close() error     { s.once.Do(func() { close(s.closed) }); return nil }

func TestSessionOverflowCloseDoesNotBlockResponseDispatch(t *testing.T) {
	writer := &blockedRegressionSessionWriter{release: make(chan struct{}), async: make(chan tunnelproto.Message, 2)}
	defer close(writer.release)
	transport := &regressionMessageTransport{msgs: make(chan tunnelproto.Message, 2), closed: make(chan struct{})}
	defer func() { _ = transport.Close() }()
	pending := newPendingRequest()
	ws := newWSStream(1)
	ws.ch <- tunnelproto.Message{Kind: tunnelproto.KindWSData}
	sess := &session{tunnelID: "control-regression", writer: writer, transport: transport, pending: map[string]*pendingRequest{"http": pending}, wsPending: map[string]*wsStream{"stalled": ws}}
	sess.pendingCount.Store(1)
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.hub.sessions[sess.tunnelID] = sess
	done := make(chan struct{})
	go func() { defer close(done); srv.readLoop(sess) }()
	defer func() {
		_ = transport.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}()
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindWSData, WSData: &tunnelproto.WSData{ID: "stalled", Data: []byte("overflow")}}
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: "http", Status: 200}}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, ok := pending.waitHeader(ctx); !ok {
		t.Fatal("HTTP response dispatch blocked behind overflow close")
	}
	select {
	case msg := <-writer.async:
		if msg.Kind != tunnelproto.KindWSClose {
			t.Fatalf("unexpected async control %q", msg.Kind)
		}
	default:
		t.Fatal("overflow close was not queued asynchronously")
	}
}

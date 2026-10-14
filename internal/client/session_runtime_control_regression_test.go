package client

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

type blockedControlTestStream struct {
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

func (s *blockedControlTestStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *blockedControlTestStream) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return len(p), nil
}
func (s *blockedControlTestStream) Close() error {
	s.closeOnce.Do(func() { close(s.release) })
	return nil
}

func TestSessionControlsDoNotWaitForBlockedWriter(t *testing.T) {
	for _, control := range []string{"pong", "h3-pong", "overflow-close"} {
		t.Run(control, func(t *testing.T) {
			stream := &blockedControlTestStream{started: make(chan struct{}), release: make(chan struct{})}
			writer := tunneltransport.NewStreamWritePump(stream, time.Second, 1, 1, func() { _ = stream.Close() })
			defer writer.Close()
			defer func() { _ = stream.Close() }()
			firstDone := make(chan error, 1)
			go func() { firstDone <- writer.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}) }()
			<-stream.started
			rt := &clientSessionRuntime{client: &Client{}, ctx: t.Context(), writer: writer}
			if control == "overflow-close" {
				conn, _, closeLocal := dialTestWebSocketPair(t)
				defer closeLocal()
				local := &localWebSocket{conn: conn, writes: make(chan localWSWrite, 1), done: make(chan struct{})}
				local.writes <- localWSWrite{messageType: websocket.TextMessage, payload: []byte("queued")}
				rt.wsConns = map[string]*localWebSocket{"stalled": local}
			}
			handled := make(chan error, 1)
			go func() {
				switch control {
				case "h3-pong":
					h3 := &clientH3MultiStreamRuntime{client: rt.client, ctx: rt.ctx, writer: writer}
					handled <- h3.handleControlMessage(tunnelproto.Message{Kind: tunnelproto.KindPing})
				case "overflow-close":
					handled <- rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindWSData, WSData: &tunnelproto.WSData{ID: "stalled", MessageType: websocket.TextMessage, Data: []byte("overflow")}})
				default:
					handled <- rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindPing})
				}
			}()
			select {
			case err := <-handled:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("control handling blocked behind a tunnel write")
			}
			// Saturation is bounded and drops a self-contained pong rather than
			// blocking the dispatcher or tearing down unrelated requests.
			if control == "pong" {
				if err := rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
					t.Fatal(err)
				}
			}
			_ = stream.Close()
			if err := <-firstDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

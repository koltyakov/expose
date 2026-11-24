package client

import (
	"errors"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

// silentTestStream accepts every write and never delivers a read, like a
// path that died without FIN or RST.
type silentTestStream struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newSilentTestStream() *silentTestStream {
	return &silentTestStream{closed: make(chan struct{})}
}

func (s *silentTestStream) Read([]byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *silentTestStream) Write(p []byte) (int, error) { return len(p), nil }

func (s *silentTestStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestSessionEndsWhenServerGoesSilent(t *testing.T) {
	stream := newSilentTestStream()
	defer func() { _ = stream.Close() }()
	writer := tunneltransport.NewStreamWritePump(stream, time.Second, 4, 4, func() { _ = stream.Close() })
	c := New(config.ClientConfig{PingInterval: 20 * time.Millisecond}, nil)
	base, _ := url.Parse("http://127.0.0.1:1")
	rt, err := newClientSessionRuntimeFromConn(c, t.Context(), base, sessionTransportConn{
		transport: tunneltransport.NewStreamTransport("test", stream, nil),
		writer:    writer,
		name:      "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.close()

	done := make(chan error, 1)
	go func() { done <- rt.run() }()
	select {
	case err := <-done:
		if !errors.Is(err, errTunnelUnresponsive) {
			t.Fatalf("run() = %v, want errTunnelUnresponsive", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session stayed up although the server sent nothing")
	}
}

// A server that answers only every other ping, as when async pongs are
// dropped under backpressure, keeps the session alive.
func TestSessionToleratesDroppedPongs(t *testing.T) {
	stream := newSilentTestStream()
	defer func() { _ = stream.Close() }()
	writer := tunneltransport.NewStreamWritePump(stream, time.Second, 4, 4, func() { _ = stream.Close() })
	msgs := make(chan tunnelproto.Message, 16)
	transport := &chanTestTransport{msgs: msgs, closed: stream.closed}
	c := New(config.ClientConfig{PingInterval: 20 * time.Millisecond}, nil)
	base, _ := url.Parse("http://127.0.0.1:1")
	rt, err := newClientSessionRuntimeFromConn(c, t.Context(), base, sessionTransportConn{
		transport: transport,
		writer:    writer,
		name:      "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.close()

	// One message every two ping intervals stays inside the silence limit.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				select {
				case msgs <- tunnelproto.Message{Kind: tunnelproto.KindPong}:
				default:
				}
			}
		}
	}()

	done := make(chan error, 1)
	go func() { done <- rt.run() }()
	select {
	case err := <-done:
		t.Fatalf("session ended while the server was still answering: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
}

type chanTestTransport struct {
	msgs   chan tunnelproto.Message
	closed chan struct{}
}

func (t *chanTestTransport) ReadMessage(dst *tunnelproto.Message) error {
	select {
	case msg := <-t.msgs:
		*dst = msg
		return nil
	case <-t.closed:
		return io.EOF
	}
}

func (t *chanTestTransport) SetReadLimit(int64) {}

func (t *chanTestTransport) Close() error { return nil }

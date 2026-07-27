package server

import (
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

// TestWSPendingSendDoesNotBlockOtherStreams is the regression test for the
// head-of-line stall: wsPendingSend used to hold wsMu for the whole duration
// of a blocking send, so one stalled consumer blocked every other stream on
// the session (Go's RWMutex queues new readers behind a waiting writer).
func TestWSPendingSendDoesNotBlockOtherStreams(t *testing.T) {
	t.Parallel()

	sess := &session{wsPending: make(map[string]*wsStream)}
	stalled := newWSStream(0) // unbuffered: nothing is reading it
	sess.wsPendingStore("stalled", stalled)

	blocking := make(chan struct{})
	go func() {
		defer close(blocking)
		sess.wsPendingSend("stalled", tunnelproto.Message{Kind: tunnelproto.KindWSData}, 2*time.Second)
	}()

	// Give the sender time to be parked inside the send.
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// All of these take wsMu. None may wait on the stalled send.
		healthy := newWSStream(1)
		sess.wsPendingStore("healthy", healthy)
		sess.wsPendingSend("healthy", tunnelproto.Message{Kind: tunnelproto.KindWSData}, 0)
		sess.wsPendingDelete("healthy")
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("unrelated stream operations blocked behind a stalled send")
	}

	stalled.close()
	select {
	case <-blocking:
	case <-time.After(time.Second):
		t.Fatal("stalled send did not unblock after close")
	}
}

// TestWSStreamCloseRacesWithSend checks that tearing a stream down while it is
// being written to is safe. Signalling shutdown on a separate channel is what
// lets send run without the session lock held; closing the message channel
// instead would panic here.
func TestWSStreamCloseRacesWithSend(t *testing.T) {
	t.Parallel()

	for range 200 {
		stream := newWSStream(1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			stream.send(tunnelproto.Message{Kind: tunnelproto.KindWSData}, 10*time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			stream.close()
		}()
		wg.Wait()
	}
}

// TestWSStreamCloseIsIdempotent covers abort followed by session teardown,
// which both reach for close.
func TestWSStreamCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	stream := newWSStream(1)
	stream.close()
	stream.close()

	select {
	case <-stream.closed:
	default:
		t.Fatal("stream not marked closed")
	}
	if !stream.send(tunnelproto.Message{Kind: tunnelproto.KindWSData}, 0) {
		t.Fatal("send on a closed stream should report delivered, not backpressure")
	}
}

// TestCloseWSPendingWakesStalledSend makes sure session teardown releases a
// sender parked on a slow consumer.
func TestCloseWSPendingWakesStalledSend(t *testing.T) {
	t.Parallel()

	sess := &session{wsPending: make(map[string]*wsStream)}
	sess.wsPendingStore("stream-1", newWSStream(0))

	sent := make(chan bool, 1)
	go func() {
		sent <- sess.wsPendingSend("stream-1", tunnelproto.Message{Kind: tunnelproto.KindWSData}, 5*time.Second)
	}()

	time.Sleep(20 * time.Millisecond)
	sess.closeWSPending()

	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("closeWSPending did not release the parked sender")
	}
}

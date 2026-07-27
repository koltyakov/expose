package server

import (
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/timerpool"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

// wsStream carries tunnel messages to the relay goroutines serving one public
// WebSocket connection.
//
// Shutdown is signalled by closing a separate channel rather than the message
// channel itself. Closing the message channel would require holding the
// session lock for the whole duration of a send to avoid a send-on-closed
// panic, which is exactly what made one stalled consumer stall every other
// WebSocket on the session.
type wsStream struct {
	ch     chan tunnelproto.Message
	closed chan struct{}
	once   sync.Once
}

func newWSStream(buffer int) *wsStream {
	if buffer < 0 {
		buffer = 0
	}
	return &wsStream{
		ch:     make(chan tunnelproto.Message, buffer),
		closed: make(chan struct{}),
	}
}

// close signals consumers to stop. It is safe to call more than once and
// concurrently with send.
func (w *wsStream) close() {
	w.once.Do(func() { close(w.closed) })
}

// send delivers msg, waiting up to wait for room in the buffer. It reports
// false only when the consumer is too slow to keep up; a closed stream counts
// as delivered because the stream is already being torn down.
func (w *wsStream) send(msg tunnelproto.Message, wait time.Duration) bool {
	select {
	case w.ch <- msg:
		return true
	case <-w.closed:
		return true
	default:
	}

	if wait <= 0 {
		return false
	}

	timer := timerpool.Acquire(wait)
	defer timerpool.Release(timer)
	select {
	case w.ch <- msg:
		return true
	case <-w.closed:
		return true
	case <-timer.C:
		return false
	}
}

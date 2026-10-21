package client

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (c *Client) upstreamIdleTimeout(req *tunnelproto.HTTPRequest) time.Duration {
	if req != nil && req.TimeoutMs > 0 {
		return time.Duration(req.TimeoutMs) * time.Millisecond
	}
	if c.cfg.Timeout > 0 {
		return c.cfg.Timeout
	}
	return 2 * time.Minute
}

// requestActivity bounds an upstream header wait while allowing an active
// upload to outlive that timeout. A timer callback rechecks the deadline under
// the lock so a concurrent touch cannot be canceled by an expired callback.
type requestActivity struct {
	mu       sync.Mutex
	timer    *time.Timer
	deadline time.Time
	timeout  time.Duration
	cancel   context.CancelFunc
	stopped  bool
	active   bool
	headers  bool
}

func newRequestActivity(timeout time.Duration, cancel context.CancelFunc) *requestActivity {
	a := &requestActivity{timeout: timeout, cancel: cancel, headers: true}
	if timeout > 0 {
		a.mu.Lock()
		a.deadline = time.Now().Add(timeout)
		a.active = true
		a.timer = time.AfterFunc(timeout, a.expire)
		a.mu.Unlock()
	}
	return a
}

func (a *requestActivity) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil && !a.stopped && a.active && a.headers {
		a.deadline = time.Now().Add(a.timeout)
		// The callback rechecks this deadline. Busy uploads need not modify
		// the runtime timer heap on every chunk.
	}
}

func (a *requestActivity) expire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped || !a.active {
		return
	}
	if remaining := time.Until(a.deadline); remaining > 0 {
		a.timer.Reset(remaining)
		return
	}
	a.stopped = true
	a.cancel()
}

func (a *requestActivity) finishHeaders() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.headers = false
	a.pauseLocked()
}

func (a *requestActivity) beginRead() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.timer != nil && !a.stopped {
		a.active = true
		a.deadline = time.Now().Add(a.timeout)
		a.timer.Reset(a.timeout)
	}
}

func (a *requestActivity) endRead() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pauseLocked()
}

func (a *requestActivity) pauseLocked() {
	a.active = false
	if a.timer != nil {
		a.timer.Stop()
	}
}

func (a *requestActivity) stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	a.pauseLocked()
}

// idleResponseBody bounds each upstream read, not time spent forwarding an
// already-read chunk to the tunnel. Canceling the HTTP request interrupts a
// stalled network read without retaining a goroutine for every chunk.
type idleResponseBody struct {
	io.ReadCloser
	activity *requestActivity
}

func (b idleResponseBody) Read(p []byte) (int, error) {
	b.activity.beginRead()
	defer b.activity.endRead()
	return b.ReadCloser.Read(p)
}

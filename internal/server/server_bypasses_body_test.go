package server

import (
	"context"
	"io"
	"testing"
	"time"
)

// ctxBlockingBody blocks every Read after the first until ctx is cancelled.
type ctxBlockingBody struct {
	ctx   context.Context
	reads int
}

func (b *ctxBlockingBody) Read(p []byte) (int, error) {
	b.reads++
	if b.reads == 1 {
		p[0] = 'x'
		return 1, nil
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (*ctxBlockingBody) Close() error { return nil }

func TestBypassResponseBodyReusesStallTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var failed bool
	body := newBypassResponseBody(&ctxBlockingBody{ctx: ctx}, cancel, 50*time.Millisecond, &failed)
	timer := body.stall
	if _, err := body.Read(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := body.Read(make([]byte, 8))
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("stalled upstream body was not cancelled: %v after %s", err, time.Since(started))
	}
	if !failed {
		t.Fatal("stalled body not reported as failed")
	}
	if body.stall != timer {
		t.Fatal("stall timer was not reused across reads")
	}
	_ = body.Close()
	if body.stall.Stop() {
		t.Fatal("stall timer still running after Close")
	}
}

func TestBypassResponseBodyFastReadsDoNotCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	body := newBypassResponseBody(io.NopCloser(io.LimitReader(zeroReader{}, 1<<20)), cancel, 20*time.Millisecond, nil)
	if _, err := io.Copy(io.Discard, body); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if ctx.Err() != nil {
		t.Fatal("timer fired after reads completed")
	}
	_ = body.Close()
}

package server

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

type pendingRequest struct {
	headerCh chan *tunnelproto.HTTPResponse
	bodyCh   chan []byte
	doneCh   chan struct{}
	aborted  atomic.Bool

	bodyMu   sync.Mutex
	doneOnce sync.Once
}

// newPendingRequest allocates a pending request.
//
// This is deliberately not pooled. The read loop resolves a *pendingRequest
// from session.pending under the map lock but then uses it after releasing
// that lock, so a recycled object could be handed to a late body chunk from a
// previous request and cross responses between visitors. Making that safe
// needs refcounting on every map lookup in the response hot path, which buys
// 3 allocations out of ~200 per proxied request (well under 1% of round-trip
// cost, see BenchmarkPublicHTTPRoundTripSingleTunnel) — not worth the failure
// mode. Without pooling, a stale pointer is merely a live object whose doneCh
// is already closed, which every method handles.
func newPendingRequest() *pendingRequest {
	return &pendingRequest{
		headerCh: make(chan *tunnelproto.HTTPResponse, 1),
		doneCh:   make(chan struct{}),
	}
}

func (p *pendingRequest) waitHeader(ctx context.Context) (*tunnelproto.HTTPResponse, bool) {
	if p == nil {
		return nil, false
	}
	select {
	case resp := <-p.headerCh:
		return resp, resp != nil
	case <-p.doneCh:
		select {
		case resp := <-p.headerCh:
			return resp, resp != nil
		default:
			return nil, false
		}
	case <-ctx.Done():
		return nil, false
	}
}

func (p *pendingRequest) deliverHeader(resp *tunnelproto.HTTPResponse) bool {
	if p == nil || resp == nil {
		return false
	}
	select {
	case <-p.doneCh:
		return false
	default:
	}
	select {
	case p.headerCh <- resp:
		return true
	default:
		return false
	}
}

func (p *pendingRequest) ensureBodyCh() chan []byte {
	if p == nil {
		return nil
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	if p.bodyCh == nil {
		p.bodyCh = make(chan []byte, streamingChanSize)
	}
	return p.bodyCh
}

func (p *pendingRequest) bodyStream() (<-chan []byte, <-chan struct{}) {
	if p == nil {
		return nil, nil
	}
	return p.ensureBodyCh(), p.doneCh
}

func (p *pendingRequest) sendBody(sess *session, payload []byte, wait time.Duration) bool {
	if p == nil || sess == nil {
		return false
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	select {
	case <-p.doneCh:
		return false
	default:
	}
	if p.bodyCh == nil {
		p.bodyCh = make(chan []byte, streamingChanSize)
	}
	return sess.streamSend(p.bodyCh, payload, wait)
}

func (p *pendingRequest) discardBody() {
	if p == nil {
		return
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	for p.bodyCh != nil {
		select {
		case chunk := <-p.bodyCh:
			tunnelproto.ReleaseBodyChunk(chunk)
		default:
			return
		}
	}
}

func (p *pendingRequest) finish() {
	if p == nil {
		return
	}
	p.doneOnce.Do(func() { close(p.doneCh) })
}

func (p *pendingRequest) abort() {
	if p == nil {
		return
	}
	p.aborted.Store(true)
	p.finish()
}

// wasAborted reports whether the stream ended via abort rather than a clean
// finish, meaning any streamed body already written is truncated.
func (p *pendingRequest) wasAborted() bool {
	return p != nil && p.aborted.Load()
}

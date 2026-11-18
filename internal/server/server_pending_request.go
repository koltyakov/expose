package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

type pendingRequest struct {
	headerCh      chan *tunnelproto.HTTPResponse
	doneCh        chan struct{}
	aborted       atomic.Bool
	sessionBudget *byteBudget
	globalBudget  *byteBudget

	bodyMu    sync.Mutex
	bodyReady chan struct{}
	bodyQueue [][]byte
	bodyHead  int
	bodyLen   int
	doneOnce  sync.Once
}

var (
	errResponseClosed              = errors.New("response stream closed")
	errResponseQueueBudgetExceeded = errors.New("response queue byte budget exceeded")
)

const initialResponseQueueSize = 16

// Tiny JSON chunks must also reserve space for queue entries. Normal pooled
// chunks are charged at retained capacity, as before. This minimum reservation
// bounds descriptor growth; it is not an exact measurement of heap usage.
func responseChunkReservation(chunk []byte) int64 {
	return max(int64(cap(chunk)), 64)
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

func (p *pendingRequest) bodyStream() (<-chan struct{}, <-chan struct{}) {
	if p == nil {
		return nil, nil
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	if p.bodyReady == nil {
		p.bodyReady = make(chan struct{}, 1)
	}
	return p.bodyReady, p.doneCh
}

// sendBody takes ownership only on success. Admission never waits for a public
// consumer: one delayed visitor must not block the shared tunnel reader.
func (p *pendingRequest) sendBody(payload []byte) error {
	if p == nil {
		return errResponseClosed
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	select {
	case <-p.doneCh:
		return errResponseClosed
	default:
	}
	if len(payload) == 0 {
		tunnelproto.ReleaseBodyChunk(payload)
		return nil
	}
	n := responseChunkReservation(payload)
	if !p.sessionBudget.acquire(n) {
		return errResponseQueueBudgetExceeded
	}
	if !p.globalBudget.acquire(n) {
		p.sessionBudget.release(n)
		return errResponseQueueBudgetExceeded
	}
	if p.bodyLen == len(p.bodyQueue) {
		queue := make([][]byte, max(initialResponseQueueSize, 2*len(p.bodyQueue)))
		first := min(p.bodyLen, len(p.bodyQueue)-p.bodyHead)
		copy(queue, p.bodyQueue[p.bodyHead:p.bodyHead+first])
		copy(queue[first:], p.bodyQueue[:p.bodyLen-first])
		p.bodyQueue, p.bodyHead = queue, 0
	}
	p.bodyQueue[(p.bodyHead+p.bodyLen)%len(p.bodyQueue)] = payload
	p.bodyLen++
	select {
	case p.bodyReady <- struct{}{}:
	default:
	}
	return nil
}

// nextBodyChunk transfers ownership to the public writer, but leaves its byte
// reservation charged until the write completes. Empty/terminal checks share
// the enqueue lock so a clean end cannot overtake an accepted body chunk.
func (p *pendingRequest) nextBodyChunk() (chunk []byte, done bool) {
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	if p.bodyLen > 0 {
		return p.popBodyLocked(), false
	}
	select {
	case <-p.doneCh:
		return nil, true
	default:
		return nil, false
	}
}

func (p *pendingRequest) popBodyLocked() []byte {
	chunk := p.bodyQueue[p.bodyHead]
	p.bodyQueue[p.bodyHead] = nil
	p.bodyHead = (p.bodyHead + 1) % len(p.bodyQueue)
	p.bodyLen--
	if p.bodyLen == 0 {
		p.bodyHead = 0
		if len(p.bodyQueue) > initialResponseQueueSize {
			p.bodyQueue = nil
		}
	}
	return chunk
}

func (p *pendingRequest) releaseBodyChunk(chunk []byte) {
	n := responseChunkReservation(chunk)
	p.sessionBudget.release(n)
	p.globalBudget.release(n)
	tunnelproto.ReleaseBodyChunk(chunk)
}

func (p *pendingRequest) discardBody() {
	if p == nil {
		return
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	for p.bodyLen > 0 {
		p.releaseBodyChunk(p.popBodyLocked())
	}
	p.bodyQueue = nil
}

func (p *pendingRequest) finish() {
	if p == nil {
		return
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	p.doneOnce.Do(func() { close(p.doneCh) })
}

func (p *pendingRequest) abort() {
	if p == nil {
		return
	}
	p.bodyMu.Lock()
	defer p.bodyMu.Unlock()
	p.aborted.Store(true)
	p.doneOnce.Do(func() { close(p.doneCh) })
}

// wasAborted reports whether the stream ended via abort rather than a clean
// finish, meaning any streamed body already written is truncated.
func (p *pendingRequest) wasAborted() bool {
	return p != nil && p.aborted.Load()
}

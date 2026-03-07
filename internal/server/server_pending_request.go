package server

import (
	"context"
	"sync"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

type pendingRequest struct {
	headerCh chan *tunnelproto.HTTPResponse
	bodyCh   chan []byte
	doneCh   chan struct{}

	bodyMu sync.Mutex
}

var pendingRequestPool = sync.Pool{
	New: func() any {
		return &pendingRequest{
			headerCh: make(chan *tunnelproto.HTTPResponse, 1),
			doneCh:   make(chan struct{}),
		}
	},
}

func acquirePendingRequest() *pendingRequest {
	req := pendingRequestPool.Get().(*pendingRequest)
	req.reset()
	return req
}

func releasePendingRequest(req *pendingRequest) {
	if req == nil {
		return
	}
	req.reset()
	pendingRequestPool.Put(req)
}

func (p *pendingRequest) reset() {
	if p == nil {
		return
	}
	drainPendingHeaders(p.headerCh)
	p.bodyMu.Lock()
	if p.bodyCh != nil {
		drainPendingBodies(p.bodyCh)
	}
	p.doneCh = make(chan struct{})
	p.bodyMu.Unlock()
}

func (p *pendingRequest) waitHeader(ctx context.Context) (*tunnelproto.HTTPResponse, bool) {
	if p == nil {
		return nil, false
	}
	select {
	case resp := <-p.headerCh:
		return resp, resp != nil
	case <-p.doneCh:
		return nil, false
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

func (p *pendingRequest) finish() {
	if p == nil {
		return
	}
	select {
	case <-p.doneCh:
	default:
		close(p.doneCh)
	}
}

func (p *pendingRequest) abort() {
	p.finish()
}

func drainPendingHeaders(ch chan *tunnelproto.HTTPResponse) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func drainPendingBodies(ch chan []byte) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

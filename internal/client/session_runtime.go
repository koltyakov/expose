package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

const streamedReqBodyDispatchWait = 100 * time.Millisecond

type streamedRequestState struct {
	ch     chan []byte
	mu     sync.Mutex
	closed bool
}

func newStreamedRequestState(bufSize int) *streamedRequestState {
	return &streamedRequestState{ch: make(chan []byte, bufSize)}
}

func (s *streamedRequestState) send(data []byte, wait time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}

	if wait <= 0 {
		select {
		case s.ch <- data:
			return true
		default:
			return false
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case s.ch <- data:
		return true
	case <-timer.C:
		return false
	}
}

func (s *streamedRequestState) close() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return false
	}
	s.closed = true
	close(s.ch)
	return true
}

type clientSessionRuntime struct {
	client    *Client
	localBase *url.URL
	conn      *websocket.Conn

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once

	requestWG  sync.WaitGroup
	requestSem chan struct{}
	requestMu  sync.Mutex
	reqCancel  map[string]context.CancelFunc

	writer *tunnelproto.WSWritePump

	pingSentMu sync.Mutex
	pingSentAt time.Time

	msgCh        chan tunnelproto.Message
	readErr      chan error
	keepaliveErr chan error

	wsMu    sync.RWMutex
	wsConns map[string]*websocket.Conn

	streamedMu       sync.Mutex
	streamedReqState map[string]*streamedRequestState
}

func newClientSessionRuntime(c *Client, parentCtx context.Context, localBase *url.URL, reg registerResponse) (*clientSessionRuntime, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: wsHandshakeTimeout,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
	}
	conn, _, err := dialer.DialContext(parentCtx, reg.WSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ws connect: %w", err)
	}
	conn.SetReadLimit(clientWSReadLimit)

	sessionCtx, cancel := context.WithCancel(parentCtx)
	rt := &clientSessionRuntime{
		client:           c,
		localBase:        localBase,
		conn:             conn,
		writer:           tunnelproto.NewWSWritePump(conn, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
		ctx:              sessionCtx,
		cancel:           cancel,
		requestSem:       make(chan struct{}, maxConcurrentForwardsFor(c.cfg)),
		reqCancel:        make(map[string]context.CancelFunc),
		msgCh:            make(chan tunnelproto.Message, wsMessageBufferSize),
		readErr:          make(chan error, 1),
		keepaliveErr:     make(chan error, 1),
		wsConns:          make(map[string]*websocket.Conn),
		streamedReqState: make(map[string]*streamedRequestState),
	}

	go func() {
		<-rt.ctx.Done()
		_ = rt.conn.Close()
	}()

	if err := rt.sendInitialPing(); err != nil {
		rt.close()
		return nil, err
	}
	rt.startKeepaliveLoop()
	rt.startReadLoop()
	return rt, nil
}

func (rt *clientSessionRuntime) close() {
	rt.closeOnce.Do(func() {
		rt.cancel()
		_ = rt.conn.Close()
		if rt.writer != nil {
			rt.writer.Close()
		}

		rt.wsMu.Lock()
		for id, streamConn := range rt.wsConns {
			delete(rt.wsConns, id)
			_ = streamConn.Close()
		}
		rt.wsMu.Unlock()

		rt.streamedMu.Lock()
		states := make([]*streamedRequestState, 0, len(rt.streamedReqState))
		for id, state := range rt.streamedReqState {
			delete(rt.streamedReqState, id)
			states = append(states, state)
		}
		rt.streamedMu.Unlock()
		for _, state := range states {
			state.close()
		}

		rt.requestMu.Lock()
		cancels := make([]context.CancelFunc, 0, len(rt.reqCancel))
		for id, cancel := range rt.reqCancel {
			delete(rt.reqCancel, id)
			cancels = append(cancels, cancel)
		}
		rt.requestMu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}

		rt.requestWG.Wait()
	})
}

func (rt *clientSessionRuntime) run() error {
	for {
		select {
		case <-rt.ctx.Done():
			return rt.ctx.Err()
		case err := <-rt.keepaliveErr:
			if rt.ctx.Err() != nil {
				return rt.ctx.Err()
			}
			return err
		case err := <-rt.readErr:
			if rt.ctx.Err() != nil {
				return rt.ctx.Err()
			}
			return err
		case msg := <-rt.msgCh:
			if err := rt.handleMessage(msg); err != nil {
				return err
			}
		}
	}
}

func (rt *clientSessionRuntime) handleMessage(msg tunnelproto.Message) error {
	switch msg.Kind {
	case tunnelproto.KindRequest:
		rt.handleRequest(msg.Request)
	case tunnelproto.KindReqBody:
		return rt.handleReqBody(msg.BodyChunk)
	case tunnelproto.KindReqBodyEnd:
		rt.handleReqBodyEnd(msg.BodyChunk)
	case tunnelproto.KindReqCancel:
		rt.handleRequestCancel(msg.ReqCancel)
	case tunnelproto.KindWSOpen:
		rt.handleWSOpen(msg.WSOpen)
	case tunnelproto.KindWSData:
		rt.handleWSData(msg.WSData)
	case tunnelproto.KindWSClose:
		rt.handleWSClose(msg.WSClose)
	case tunnelproto.KindPong, tunnelproto.KindPing:
		return rt.handlePingPong(msg)
	case tunnelproto.KindClose:
		return errors.New("server closed tunnel")
	}
	return nil
}

func (rt *clientSessionRuntime) sendInitialPing() error {
	rt.pingSentMu.Lock()
	rt.pingSentAt = time.Now()
	rt.pingSentMu.Unlock()
	return rt.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPing})
}

func (rt *clientSessionRuntime) startKeepaliveLoop() {
	if rt.client.cfg.PingInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(rt.client.cfg.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-rt.ctx.Done():
				return
			case <-ticker.C:
				rt.pingSentMu.Lock()
				rt.pingSentAt = time.Now()
				rt.pingSentMu.Unlock()
				if err := rt.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
					select {
					case rt.keepaliveErr <- err:
					default:
					}
					return
				}
			}
		}
	}()
}

func (rt *clientSessionRuntime) startReadLoop() {
	go func() {
		for {
			var msg tunnelproto.Message
			if err := tunnelproto.ReadWSMessage(rt.conn, &msg); err != nil {
				select {
				case rt.readErr <- err:
				default:
				}
				return
			}
			select {
			case rt.msgCh <- msg:
			case <-rt.ctx.Done():
				return
			}
		}
	}()
}

func (rt *clientSessionRuntime) writeJSON(msg tunnelproto.Message) error {
	if rt.writer == nil {
		return tunnelproto.ErrWSWritePumpClosed
	}
	return rt.writer.WriteJSON(msg)
}

func (rt *clientSessionRuntime) writeBinary(frameKind byte, id string, wsMessageType int, payload []byte) error {
	if rt.writer == nil {
		return tunnelproto.ErrWSWritePumpClosed
	}
	return rt.writer.WriteBinaryFrame(frameKind, id, wsMessageType, payload)
}

func (rt *clientSessionRuntime) handleRequest(req *tunnelproto.HTTPRequest) {
	if req == nil {
		return
	}

	select {
	case rt.requestSem <- struct{}{}:
	case <-rt.ctx.Done():
		return
	}

	rt.requestWG.Add(1)
	reqCopy := *req
	var bodyCh <-chan []byte
	if reqCopy.Streamed {
		bodyCh = rt.openStreamedRequest(reqCopy.ID)
	}
	reqCtx, cancel := requestContext(rt.ctx, &reqCopy)
	rt.storeRequestCancel(reqCopy.ID, cancel)

	go func(forwardReq tunnelproto.HTTPRequest, streamedBody <-chan []byte) {
		defer rt.requestWG.Done()
		defer func() { <-rt.requestSem }()
		defer rt.deleteRequestCancel(forwardReq.ID)
		defer rt.closeAndRemoveStreamedRequest(forwardReq.ID)
		defer cancel()

		rt.client.forwardAndSend(reqCtx, rt.localBase, &forwardReq, streamedBody, rt.writeJSON, func(id string, payload []byte) error {
			return rt.writeBinary(tunnelproto.BinaryFrameRespBody, id, 0, payload)
		})
	}(reqCopy, bodyCh)
}

func (rt *clientSessionRuntime) handleReqBody(chunk *tunnelproto.BodyChunk) error {
	if chunk == nil {
		return nil
	}

	state, ok := rt.getStreamedRequestState(chunk.ID)
	if !ok {
		return nil
	}

	data, err := chunk.Payload()
	if err != nil {
		return nil
	}

	if ok := state.send(data, streamedReqBodyDispatchWait); ok {
		return nil
	}

	rt.closeAndRemoveStreamedRequest(chunk.ID)
	if rt.client.log != nil {
		rt.client.log.Warn("dropping stalled streamed request body", "request_id", chunk.ID)
	}
	return nil
}

func (rt *clientSessionRuntime) handleReqBodyEnd(chunk *tunnelproto.BodyChunk) {
	if chunk == nil {
		return
	}
	rt.closeAndRemoveStreamedRequest(chunk.ID)
}

func (rt *clientSessionRuntime) openStreamedRequest(id string) <-chan []byte {
	if strings.TrimSpace(id) == "" {
		return nil
	}

	state := newStreamedRequestState(streamingReqBodyBufSize)

	rt.streamedMu.Lock()
	if prev, exists := rt.streamedReqState[id]; exists {
		delete(rt.streamedReqState, id)
		prev.close()
	}
	rt.streamedReqState[id] = state
	rt.streamedMu.Unlock()
	return state.ch
}

func (rt *clientSessionRuntime) getStreamedRequestState(id string) (*streamedRequestState, bool) {
	rt.streamedMu.Lock()
	state, ok := rt.streamedReqState[id]
	rt.streamedMu.Unlock()
	return state, ok
}

func (rt *clientSessionRuntime) closeAndRemoveStreamedRequest(id string) {
	if strings.TrimSpace(id) == "" {
		return
	}
	rt.streamedMu.Lock()
	state, ok := rt.streamedReqState[id]
	if ok {
		delete(rt.streamedReqState, id)
	}
	rt.streamedMu.Unlock()
	if ok {
		state.close()
	}
}

func (rt *clientSessionRuntime) handleRequestCancel(cancelMsg *tunnelproto.RequestCancel) {
	if cancelMsg == nil {
		return
	}
	rt.cancelRequest(cancelMsg.ID)
}

func (rt *clientSessionRuntime) storeRequestCancel(id string, cancel context.CancelFunc) {
	id = strings.TrimSpace(id)
	if id == "" || cancel == nil {
		return
	}

	rt.requestMu.Lock()
	if prev, exists := rt.reqCancel[id]; exists {
		delete(rt.reqCancel, id)
		prev()
	}
	rt.reqCancel[id] = cancel
	rt.requestMu.Unlock()
}

func (rt *clientSessionRuntime) deleteRequestCancel(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}

	rt.requestMu.Lock()
	delete(rt.reqCancel, id)
	rt.requestMu.Unlock()
}

func (rt *clientSessionRuntime) cancelRequest(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}

	rt.requestMu.Lock()
	cancel, ok := rt.reqCancel[id]
	if ok {
		delete(rt.reqCancel, id)
	}
	rt.requestMu.Unlock()

	rt.closeAndRemoveStreamedRequest(id)
	if ok {
		cancel()
	}
}

func requestContext(parent context.Context, req *tunnelproto.HTTPRequest) (context.Context, context.CancelFunc) {
	if req != nil && req.TimeoutMs > 0 {
		return context.WithTimeout(parent, time.Duration(req.TimeoutMs)*time.Millisecond)
	}
	return context.WithCancel(parent)
}

func (rt *clientSessionRuntime) handlePingPong(msg tunnelproto.Message) error {
	if msg.Kind == tunnelproto.KindPing {
		if err := rt.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && rt.ctx.Err() == nil {
			return err
		}
	}

	if msg.Kind == tunnelproto.KindPong {
		rt.pingSentMu.Lock()
		sentAt := rt.pingSentAt
		rt.pingSentMu.Unlock()
		if !sentAt.IsZero() {
			rtt := time.Since(sentAt)
			if rt.client.display != nil {
				rt.client.display.ShowLatency(rtt)
			} else if rt.client.log != nil {
				rt.client.log.Info("latency", "duration", rtt.String())
			}
		}
		if msg.Stats != nil {
			if rt.client.display != nil {
				rt.client.display.ShowWAFStats(msg.Stats.WAFBlocked)
			} else if rt.client.log != nil {
				rt.client.log.Info("waf stats", "blocked", msg.Stats.WAFBlocked)
			}
		}
	}

	return nil
}

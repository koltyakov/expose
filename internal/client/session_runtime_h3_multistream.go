package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/timerpool"
	"github.com/koltyakov/expose/internal/traffic"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

const (
	h3SessionHeader          = "X-Expose-H3-Session"
	h3WorkerConnectTimeout   = 15 * time.Second
	h3WorkerOpenCountFloor   = 4
	h3WorkerOpenCountCeiling = 64
	// h3RequestBodyDrainTimeout bounds how long a worker whose response is
	// complete keeps reading request body frames the server already sent.
	h3RequestBodyDrainTimeout = 5 * time.Second
)

var errH3RequestBodyStillActive = errors.New("http3 request body still active after forwarding completed")

func newSessionRuntime(c *Client, parentCtx context.Context, localBase *url.URL, reg domain.RegisterResponse) (sessionRuntime, error) {
	return newSessionRuntimeWithin(c, parentCtx, parentCtx, localBase, reg)
}

// newSessionRuntimeWithin connects and initializes a session. readyCtx bounds
// only the work before the session is ready: the transport connect, any
// connect-token refresh for a fallback transport, and the initial ping. The
// established session lives on sessionCtx, so readyCtx may end afterwards
// without affecting it. A session that completes after readyCtx ended is
// closed and reported as readyCtx's error.
func newSessionRuntimeWithin(c *Client, sessionCtx, readyCtx context.Context, localBase *url.URL, reg domain.RegisterResponse) (sessionRuntime, error) {
	conn, err := c.connectSessionTransport(readyCtx, reg)
	if err != nil {
		return nil, err
	}
	var rt sessionRuntime
	if isH3MultiStreamProtocol(conn.protocol) {
		h3rt, h3Err := newClientH3MultiStreamRuntimeWithin(c, sessionCtx, readyCtx, localBase, conn)
		if h3Err != nil {
			return nil, h3Err
		}
		rt = h3rt
	} else {
		wsrt, wsErr := newClientSessionRuntime(c, sessionCtx, readyCtx, localBase, conn)
		if wsErr != nil {
			return nil, wsErr
		}
		rt = wsrt
	}
	if err := readyCtx.Err(); err != nil {
		rt.close()
		return nil, err
	}
	return rt, nil
}

// sendBeforeReady runs send, aborting it through abort once readyCtx ends.
// abort must make send return, typically by closing the transport. An abort
// that started is waited for before returning.
func sendBeforeReady(readyCtx context.Context, abort func(), send func() error) error {
	aborted := make(chan struct{})
	stop := context.AfterFunc(readyCtx, func() {
		defer close(aborted)
		abort()
	})
	err := send()
	if !stop() {
		<-aborted
		return readyCtx.Err()
	}
	return err
}

func isH3MultiStreamProtocol(protocol string) bool {
	switch strings.TrimSpace(protocol) {
	case tunnelCapabilityH3Multistream, tunnelCapabilityH3MultistreamV2:
		return true
	default:
		return false
	}
}

type clientH3MultiStreamRuntime struct {
	client         *Client
	localBase      *url.URL
	transport      tunneltransport.Transport
	writer         *tunneltransport.WritePump
	h3ClientConn   *http3.ClientConn
	h3WorkerURL    string
	h3SessionToken string
	kind           string

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
	workerWG  sync.WaitGroup

	msgCh        chan tunnelproto.Message
	readErr      chan error
	keepaliveErr chan error

	pingSentMu sync.Mutex
	pingSentAt time.Time

	h3Workers   *h3WorkerManager
	useStreamV2 bool
}

// newClientH3MultiStreamRuntimeWithin bounds the initial ping by readyCtx and
// runs the session on parentCtx.
func newClientH3MultiStreamRuntimeWithin(
	c *Client,
	parentCtx context.Context,
	readyCtx context.Context,
	localBase *url.URL,
	conn sessionTransportConn,
) (*clientH3MultiStreamRuntime, error) {
	if conn.transport == nil || conn.writer == nil || conn.h3ClientConn == nil {
		closeSessionTransportConn(conn)
		return nil, errors.New("invalid http3 transport state")
	}
	if strings.TrimSpace(conn.h3WorkerURL) == "" || strings.TrimSpace(conn.h3SessionToken) == "" {
		closeSessionTransportConn(conn)
		return nil, errors.New("missing http3 worker metadata")
	}

	sessionCtx, cancel := context.WithCancel(parentCtx)
	rt := &clientH3MultiStreamRuntime{
		client:         c,
		localBase:      localBase,
		transport:      conn.transport,
		writer:         conn.writer,
		h3ClientConn:   conn.h3ClientConn,
		h3WorkerURL:    conn.h3WorkerURL,
		h3SessionToken: conn.h3SessionToken,
		kind:           conn.name,
		ctx:            sessionCtx,
		cancel:         cancel,
		msgCh:          make(chan tunnelproto.Message, wsMessageBufferSize),
		readErr:        make(chan error, 1),
		keepaliveErr:   make(chan error, 1),
		useStreamV2:    conn.protocol == tunnelCapabilityH3MultistreamV2,
	}
	rt.h3Workers = newH3WorkerManager(rt.maxWorkers(), rt.openWorker)
	rt.transport.SetReadLimit(clientWSReadLimit)
	go func() {
		<-rt.ctx.Done()
		_ = rt.transport.Close()
	}()

	if err := sendBeforeReady(readyCtx, func() { _ = rt.transport.Close() }, rt.sendInitialPing); err != nil {
		rt.close()
		return nil, err
	}
	rt.startKeepaliveLoop()
	rt.startControlReadLoop()
	rt.h3Workers.request(rt.initialWorkerCount())
	return rt, nil
}

func (rt *clientH3MultiStreamRuntime) transportKind() string {
	if rt == nil {
		return ""
	}
	return rt.kind
}

func (rt *clientH3MultiStreamRuntime) run() error {
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
			if err := rt.handleControlMessage(msg); err != nil {
				return err
			}
		}
	}
}

func (rt *clientH3MultiStreamRuntime) close() {
	rt.closeOnce.Do(func() {
		rt.cancel()
		if rt.transport != nil {
			_ = rt.transport.Close()
		}
		if rt.writer != nil {
			rt.writer.Close()
		}
		rt.workerWG.Wait()
	})
}

func (rt *clientH3MultiStreamRuntime) sendInitialPing() error {
	rt.pingSentMu.Lock()
	rt.pingSentAt = time.Now()
	rt.pingSentMu.Unlock()
	return rt.writeControlJSON(tunnelproto.Message{Kind: tunnelproto.KindPing})
}

func (rt *clientH3MultiStreamRuntime) startKeepaliveLoop() {
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
				if err := rt.writeControlJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
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

func (rt *clientH3MultiStreamRuntime) startControlReadLoop() {
	go func() {
		for {
			var msg tunnelproto.Message
			if err := rt.transport.ReadMessage(&msg); err != nil {
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

func (rt *clientH3MultiStreamRuntime) handleControlMessage(msg tunnelproto.Message) error {
	switch msg.Kind {
	case tunnelproto.KindPong, tunnelproto.KindPing:
		return rt.handlePingPong(msg)
	case tunnelproto.KindWorkerCtrl:
		if msg.WorkerCtrl != nil {
			rt.h3Workers.request(msg.WorkerCtrl.Desired)
		}
		return nil
	case tunnelproto.KindClose:
		return errors.New("server closed tunnel")
	default:
		// Request and websocket streams are delivered over dedicated h3 worker streams.
		return nil
	}
}

func (rt *clientH3MultiStreamRuntime) handlePingPong(msg tunnelproto.Message) error {
	if msg.Kind == tunnelproto.KindPing {
		if rt.writer == nil {
			return tunneltransport.ErrWritePumpClosed
		}
		if err := rt.writer.WriteJSONAsync(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && !errors.Is(err, tunneltransport.ErrWritePumpBackpressure) && rt.ctx.Err() == nil {
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

func (rt *clientH3MultiStreamRuntime) writeControlJSON(msg tunnelproto.Message) error {
	if rt.writer == nil {
		return tunneltransport.ErrWritePumpClosed
	}
	return rt.writer.WriteJSON(msg)
}

func (rt *clientH3MultiStreamRuntime) maxWorkers() int {
	workers := max(min(maxConcurrentForwardsFor(rt.client.cfg), h3WorkerOpenCountCeiling), 1)
	return workers
}

func (rt *clientH3MultiStreamRuntime) initialWorkerCount() int {
	workers := rt.maxWorkers()
	if workers < h3WorkerOpenCountFloor {
		return workers
	}
	return h3WorkerOpenCountFloor
}

func (rt *clientH3MultiStreamRuntime) openWorker() {
	rt.workerWG.Go(func() {
		rt.h3Workers.opened()
		pooled := true
		// A worker that carries a websocket never returns to the pool. It stops
		// counting against the worker limit and is replaced at once, so the
		// next request does not wait a round trip for a new worker.
		leavePool := func() {
			if !pooled {
				return
			}
			pooled = false
			rt.h3Workers.closed()
			rt.h3Workers.request(1)
		}
		defer func() {
			if pooled {
				rt.h3Workers.closed()
			}
		}()

		backoff := 100 * time.Millisecond
		for {
			if rt.ctx.Err() != nil {
				return
			}
			err := rt.runWorkerStream(leavePool)
			if rt.ctx.Err() != nil {
				return
			}
			if err == nil || !pooled {
				return
			}
			if rt.client.log != nil {
				rt.client.log.Warn("http3 worker stream ended; retrying", "err", shortenError(err), "retry_in", backoff.String())
			}
			timer := timerpool.Acquire(backoff)
			select {
			case <-rt.ctx.Done():
				timerpool.Release(timer)
				return
			case <-timer.C:
			}
			timerpool.Release(timer)
			backoff = min(backoff*2, 2*time.Second)
		}
	})
}

func (rt *clientH3MultiStreamRuntime) runWorkerStream(leavePool func()) error {
	openCtx, cancel := context.WithTimeout(rt.ctx, h3WorkerConnectTimeout)
	defer cancel()

	stream, err := rt.h3ClientConn.OpenRequestStream(openCtx)
	if err != nil {
		return err
	}
	graceful := false
	defer func() {
		if graceful {
			// Preserve a rejected WebSocket acknowledgment. Resetting
			// the write side can discard it before the server receives it.
			stream.CancelRead(0)
			_ = stream.Close()
		} else {
			closeH3RequestStream(stream)
		}
	}()

	req, err := http.NewRequestWithContext(rt.ctx, http.MethodPost, rt.h3WorkerURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set(h3SessionHeader, rt.h3SessionToken)
	_ = stream.SetWriteDeadline(time.Now().Add(h3WorkerConnectTimeout))
	if err := stream.SendRequestHeader(req); err != nil {
		_ = stream.SetWriteDeadline(time.Time{})
		return err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	_ = stream.SetReadDeadline(time.Now().Add(h3WorkerConnectTimeout))
	resp, err := stream.ReadResponse()
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := resp.Status
		if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096)); readErr == nil && strings.TrimSpace(string(body)) != "" {
			msg = strings.TrimSpace(string(body))
		}
		_ = resp.Body.Close()
		return fmt.Errorf("http3 worker rejected: %s", msg)
	}

	for {
		// Idle workers block here with no deadline. The server keeps ready
		// workers in its pool, so they must stay open, and a deadline firing
		// mid-frame would discard the bytes io.ReadFull already consumed and
		// desynchronize the stream. Session teardown closes the connection,
		// which ends this read.
		msg, err := readH3RequestStreamMessage(stream, rt.useStreamV2)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch msg.Kind {
		case tunnelproto.KindPing:
			if err := writeH3RequestStreamJSON(stream, tunnelproto.Message{Kind: tunnelproto.KindPong}, rt.useStreamV2); err != nil {
				return err
			}
		case tunnelproto.KindRequest:
			if err := rt.handleWorkerHTTPRequest(stream, msg.Request); err != nil {
				return err
			}
		case tunnelproto.KindWSOpen:
			leavePool()
			var err error
			graceful, err = rt.handleWorkerWS(stream, msg.WSOpen)
			return err
		}
	}
}

func (rt *clientH3MultiStreamRuntime) handleWorkerHTTPRequest(stream *http3.RequestStream, req *tunnelproto.HTTPRequest) error {
	if req == nil {
		return nil
	}
	reqCopy := *req
	reqCtx, cancel := requestContext(rt.ctx, &reqCopy)
	defer cancel()
	// A worker reset includes STOP_SENDING, which cancels the stream's send
	// context. Inline requests have no body reader to observe that reset.
	stopCancel := context.AfterFunc(stream.Context(), cancel)
	defer stopCancel()

	var bodyCh <-chan []byte
	var bodyDone chan struct{}
	var bodyClean bool
	if reqCopy.Streamed {
		ch := make(chan []byte, streamingReqBodyBufSize)
		bodyCh = ch
		bodyDone = make(chan struct{})
		go func() {
			defer close(bodyDone)
			bodyClean = pumpStreamedRequestBodyMessages(reqCtx, reqCopy.ID, cancel, func() (tunnelproto.Message, error) {
				return readH3RequestStreamMessage(stream, rt.useStreamV2)
			}, ch, nil)
		}()
	}

	rt.client.forwardAndSend(reqCtx, rt.localBase, &reqCopy, bodyCh, func(msg tunnelproto.Message) error {
		return writeH3RequestStreamJSON(stream, msg, rt.useStreamV2)
	}, func(id string, payload []byte) error {
		return writeH3RequestStreamBinary(stream, tunnelproto.BinaryFrameRespBody, id, 0, payload, rt.useStreamV2)
	})
	forwardErr := reqCtx.Err()
	if bodyDone == nil {
		return forwardErr
	}
	// The origin may answer before reading the whole body. Stop delivering
	// it, but keep reading to the server's end marker: a server that sent the
	// whole body reuses this worker, so its frames must not be left unread. A
	// server that stopped mid-upload resets the stream, which ends the read.
	// The pump is always joined, so nothing reads the stream after return.
	cancel()
	drain := timerpool.Acquire(h3RequestBodyDrainTimeout)
	select {
	case <-bodyDone:
		timerpool.Release(drain)
	case <-drain.C:
		timerpool.Release(drain)
		stream.CancelRead(0) // safe alongside Read; ends the pump's read
		<-bodyDone
		return errH3RequestBodyStillActive
	}
	if forwardErr != nil {
		return forwardErr
	}
	if !bodyClean {
		return errH3RequestBodyStillActive
	}
	return nil
}

// pumpStreamedRequestBodyMessages delivers request body frames to out until
// the request's end marker. Once ctx ends it stops delivering but keeps
// reading and discarding, so the stream stays aligned on frame boundaries.
// clean reports that the body ended with a successful end marker.
func pumpStreamedRequestBodyMessages(
	ctx context.Context,
	reqID string,
	cancel context.CancelFunc,
	readNext func() (tunnelproto.Message, error),
	out chan<- []byte,
	done chan<- struct{},
) (clean bool) {
	defer close(out)
	if done != nil {
		defer close(done)
	}
	delivering := true
	for {
		msg, err := readNext()
		if err != nil {
			if ctx.Err() == nil && cancel != nil {
				cancel()
			}
			return false
		}
		if msg.Kind == tunnelproto.KindReqBodyEnd && msg.BodyChunk != nil && msg.BodyChunk.ID == reqID {
			if msg.BodyChunk.Error != "" {
				if cancel != nil {
					cancel()
				}
				return false
			}
			return true
		}
		if msg.Kind == tunnelproto.KindReqCancel && msg.ReqCancel != nil && msg.ReqCancel.ID == reqID {
			if cancel != nil {
				cancel()
			}
			return false
		}
		if msg.Kind != tunnelproto.KindReqBody || msg.BodyChunk == nil || msg.BodyChunk.ID != reqID {
			continue
		}
		payload, err := msg.BodyChunk.Payload()
		if err != nil {
			tunnelproto.ReleaseBodyChunk(msg.BodyChunk.Data)
			continue
		}
		if !delivering {
			tunnelproto.ReleaseBodyChunk(payload)
			continue
		}
		select {
		case out <- payload:
		case <-ctx.Done():
			tunnelproto.ReleaseBodyChunk(payload)
			delivering = false
		}
	}
}

func (rt *clientH3MultiStreamRuntime) handleWorkerWS(stream *http3.RequestStream, open *tunnelproto.WSOpen) (flushAck bool, err error) {
	if open == nil {
		return false, nil
	}
	streamID := strings.TrimSpace(open.ID)
	if streamID == "" {
		return false, nil
	}

	upstreamConn, status, subprotocol, err := rt.client.openLocalWebSocket(rt.ctx, rt.localBase, open)
	if err != nil {
		err := writeH3RequestStreamJSON(stream, tunnelproto.Message{
			Kind: tunnelproto.KindWSOpenAck,
			WSOpenAck: &tunnelproto.WSOpenAck{
				ID:     streamID,
				OK:     false,
				Status: status,
				Error:  err.Error(),
			},
		}, rt.useStreamV2)
		return err == nil, err
	}
	defer func() { _ = upstreamConn.Close() }()
	rt.client.trackWSOpen(streamID, open)
	defer rt.client.trackWSClose(streamID)

	if err := writeH3RequestStreamJSON(stream, tunnelproto.Message{
		Kind: tunnelproto.KindWSOpenAck,
		WSOpenAck: &tunnelproto.WSOpenAck{
			ID:          streamID,
			OK:          true,
			Status:      http.StatusSwitchingProtocols,
			Subprotocol: subprotocol,
		},
	}, rt.useStreamV2); err != nil {
		return false, err
	}

	var writeMu sync.Mutex
	writeStreamJSON := func(msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeH3RequestStreamJSON(stream, msg, rt.useStreamV2)
	}
	writeStreamWSData := func(messageType int, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeH3RequestStreamBinary(stream, tunnelproto.BinaryFrameWSData, streamID, messageType, payload, rt.useStreamV2)
	}

	localErr := make(chan struct{})
	// The caller closes the stream after this returns. http3.Stream.Close and
	// Write share unsynchronized frame state, so the local reader goroutine
	// must have stopped writing first. Closing the upstream connection ends
	// its ReadMessage; a blocked stream write is bounded by its deadline, and
	// cancelling the write side on shutdown releases it at once.
	defer func() {
		_ = upstreamConn.Close()
		if rt.ctx.Err() != nil {
			stream.CancelWrite(0)
		}
		<-localErr
	}()
	go func() {
		defer close(localErr)
		for {
			msgType, payload, err := upstreamConn.ReadMessage()
			if err != nil {
				code := websocket.CloseNormalClosure
				text := ""
				if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
					code = ce.Code
					text = ce.Text
				}
				_ = writeStreamJSON(tunnelproto.Message{
					Kind:    tunnelproto.KindWSClose,
					WSClose: &tunnelproto.WSClose{ID: streamID, Code: code, Text: text},
				})
				return
			}
			if err := writeStreamWSData(msgType, payload); err != nil {
				return
			}
			rt.client.recordTraffic(traffic.DirectionOutbound, int64(len(payload)))
		}
	}()

	for {
		select {
		case <-rt.ctx.Done():
			return false, rt.ctx.Err()
		case <-localErr:
			return false, nil
		default:
		}

		msg, err := readH3RequestStreamMessage(stream, rt.useStreamV2)
		if err != nil {
			return false, nil
		}
		switch msg.Kind {
		case tunnelproto.KindWSData:
			if msg.WSData == nil {
				continue
			}
			payload, err := msg.WSData.Payload()
			if err != nil {
				continue
			}
			_ = upstreamConn.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout))
			if err := upstreamConn.WriteMessage(msg.WSData.MessageType, payload); err != nil {
				return false, nil
			}
			rt.client.recordTraffic(traffic.DirectionInbound, int64(len(payload)))
		case tunnelproto.KindWSClose:
			if msg.WSClose == nil {
				return false, nil
			}
			_ = upstreamConn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text),
				time.Now().Add(5*time.Second),
			)
			return false, nil
		}
	}
}

// readH3RequestStreamMessage reads one frame without a deadline: frames are
// decoded with io.ReadFull, so a deadline that fires partway through a frame
// would lose the consumed bytes.
func readH3RequestStreamMessage(stream *http3.RequestStream, useV2 bool) (tunnelproto.Message, error) {
	if stream == nil {
		return tunnelproto.Message{}, io.EOF
	}
	return readStreamMessage(stream, useV2)
}

func readStreamMessage(r io.Reader, useV2 bool) (tunnelproto.Message, error) {
	var msg tunnelproto.Message
	var err error
	if useV2 {
		err = tunnelproto.ReadStreamMessageV2(r, clientWSReadLimit, &msg)
	} else {
		err = tunnelproto.ReadStreamMessage(r, clientWSReadLimit, &msg)
	}
	if err != nil {
		return tunnelproto.Message{}, err
	}
	return msg, nil
}

func writeH3RequestStreamJSON(stream *http3.RequestStream, msg tunnelproto.Message, useV2 bool) error {
	if stream == nil {
		return io.EOF
	}
	_ = stream.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if useV2 {
		return tunnelproto.WriteStreamJSONV2(stream, msg)
	}
	return tunnelproto.WriteStreamJSON(stream, msg)
}

func writeH3RequestStreamBinary(stream *http3.RequestStream, frameKind byte, id string, wsMessageType int, payload []byte, useV2 bool) error {
	if stream == nil {
		return io.EOF
	}
	_ = stream.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if useV2 {
		return tunnelproto.WriteStreamBinaryFrameV2(stream, frameKind, id, wsMessageType, payload)
	}
	return tunnelproto.WriteStreamBinaryFrame(stream, frameKind, id, wsMessageType, payload)
}

func closeH3RequestStream(stream *http3.RequestStream) {
	if stream == nil {
		return
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	_ = stream.Close()
}

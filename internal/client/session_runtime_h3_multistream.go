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

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

const (
	h3SessionHeader          = "X-Expose-H3-Session"
	h3WorkerConnectTimeout   = 15 * time.Second
	h3WorkerIdleTTL          = 30 * time.Second
	h3WorkerOpenCountFloor   = 2
	h3WorkerOpenCountCeiling = 64
)

func newSessionRuntime(c *Client, parentCtx context.Context, localBase *url.URL, reg registerResponse) (sessionRuntime, error) {
	conn, err := c.connectSessionTransport(parentCtx, reg)
	if err != nil {
		return nil, err
	}
	if conn.protocol == tunnelCapabilityH3Multistream {
		return newClientH3MultiStreamRuntime(c, parentCtx, localBase, conn)
	}
	return newClientSessionRuntimeFromConn(c, parentCtx, localBase, conn)
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

func newClientH3MultiStreamRuntime(
	c *Client,
	parentCtx context.Context,
	localBase *url.URL,
	conn sessionTransportConn,
) (*clientH3MultiStreamRuntime, error) {
	if conn.transport == nil || conn.writer == nil || conn.h3ClientConn == nil {
		return nil, errors.New("invalid http3 transport state")
	}
	if strings.TrimSpace(conn.h3WorkerURL) == "" || strings.TrimSpace(conn.h3SessionToken) == "" {
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

	if err := rt.sendInitialPing(); err != nil {
		rt.close()
		return nil, err
	}
	rt.startKeepaliveLoop()
	rt.startControlReadLoop()
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
		if err := rt.writeControlJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && rt.ctx.Err() == nil {
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
	workers := maxConcurrentForwardsFor(rt.client.cfg)
	if workers > h3WorkerOpenCountCeiling {
		workers = h3WorkerOpenCountCeiling
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

func (rt *clientH3MultiStreamRuntime) openWorker() {
	rt.workerWG.Add(1)
	go func() {
		defer rt.workerWG.Done()
		backoff := 100 * time.Millisecond
		for {
			if rt.ctx.Err() != nil {
				return
			}
			err := rt.runWorkerStream()
			if rt.ctx.Err() != nil {
				return
			}
			if err == nil {
				return
			}
			if rt.client.log != nil {
				rt.client.log.Warn("http3 worker stream ended; retrying", "err", shortenError(err), "retry_in", backoff.String())
			}
			timer := time.NewTimer(backoff)
			select {
			case <-rt.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			backoff = min(backoff*2, 2*time.Second)
		}
	}()
}

func (rt *clientH3MultiStreamRuntime) runWorkerStream() error {
	rt.h3Workers.opened()
	defer rt.h3Workers.closed()

	openCtx, cancel := context.WithTimeout(rt.ctx, h3WorkerConnectTimeout)
	defer cancel()

	stream, err := rt.h3ClientConn.OpenRequestStream(openCtx)
	if err != nil {
		return err
	}
	defer closeH3RequestStream(stream)

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
		msg, err := readH3RequestStreamMessage(stream, h3WorkerIdleTTL, rt.useStreamV2)
		if err != nil {
			if isTimeoutError(err) {
				return nil
			}
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
			return rt.handleWorkerWS(stream, msg.WSOpen)
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

	var bodyCh <-chan []byte
	if reqCopy.Streamed {
		ch := make(chan []byte, streamingReqBodyBufSize)
		bodyCh = ch
		go func() {
			defer close(ch)
			for {
				msg, err := readH3RequestStreamMessage(stream, 0, rt.useStreamV2)
				if err != nil {
					return
				}
				if msg.Kind == tunnelproto.KindReqBodyEnd && msg.BodyChunk != nil && msg.BodyChunk.ID == reqCopy.ID {
					return
				}
				if msg.Kind == tunnelproto.KindReqCancel && msg.ReqCancel != nil && msg.ReqCancel.ID == reqCopy.ID {
					cancel()
					return
				}
				if msg.Kind != tunnelproto.KindReqBody || msg.BodyChunk == nil {
					continue
				}
				payload, err := msg.BodyChunk.Payload()
				if err != nil {
					continue
				}
				select {
				case ch <- payload:
				case <-reqCtx.Done():
					return
				}
			}
		}()
	}

	rt.client.forwardAndSend(reqCtx, rt.localBase, &reqCopy, bodyCh, func(msg tunnelproto.Message) error {
		return writeH3RequestStreamJSON(stream, msg, rt.useStreamV2)
	}, func(id string, payload []byte) error {
		return writeH3RequestStreamBinary(stream, tunnelproto.BinaryFrameRespBody, id, 0, payload, rt.useStreamV2)
	})
	return nil
}

func (rt *clientH3MultiStreamRuntime) handleWorkerWS(stream *http3.RequestStream, open *tunnelproto.WSOpen) error {
	if open == nil {
		return nil
	}
	streamID := strings.TrimSpace(open.ID)
	if streamID == "" {
		return nil
	}

	upstreamConn, status, subprotocol, err := rt.client.openLocalWebSocket(rt.ctx, rt.localBase, open)
	if err != nil {
		_ = writeH3RequestStreamJSON(stream, tunnelproto.Message{
			Kind: tunnelproto.KindWSOpenAck,
			WSOpenAck: &tunnelproto.WSOpenAck{
				ID:     streamID,
				OK:     false,
				Status: status,
				Error:  err.Error(),
			},
		}, rt.useStreamV2)
		return nil
	}
	defer func() { _ = upstreamConn.Close() }()

	if err := writeH3RequestStreamJSON(stream, tunnelproto.Message{
		Kind: tunnelproto.KindWSOpenAck,
		WSOpenAck: &tunnelproto.WSOpenAck{
			ID:          streamID,
			OK:          true,
			Status:      http.StatusSwitchingProtocols,
			Subprotocol: subprotocol,
		},
	}, rt.useStreamV2); err != nil {
		return err
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
	go func() {
		defer close(localErr)
		for {
			msgType, payload, err := upstreamConn.ReadMessage()
			if err != nil {
				code := websocket.CloseNormalClosure
				text := ""
				var ce *websocket.CloseError
				if errors.As(err, &ce) {
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
		}
	}()

	for {
		select {
		case <-rt.ctx.Done():
			return rt.ctx.Err()
		case <-localErr:
			return nil
		default:
		}

		msg, err := readH3RequestStreamMessage(stream, 0, rt.useStreamV2)
		if err != nil {
			return nil
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
			if err := upstreamConn.WriteMessage(msg.WSData.MessageType, payload); err != nil {
				return nil
			}
		case tunnelproto.KindWSClose:
			if msg.WSClose == nil {
				return nil
			}
			_ = upstreamConn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text),
				time.Now().Add(5*time.Second),
			)
			return nil
		}
	}
}

func readH3RequestStreamMessage(stream *http3.RequestStream, timeout time.Duration, useV2 bool) (tunnelproto.Message, error) {
	var msg tunnelproto.Message
	if stream == nil {
		return msg, io.EOF
	}
	if timeout > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = stream.SetReadDeadline(time.Time{}) }()
	}
	var err error
	if useV2 {
		err = tunnelproto.ReadStreamMessageV2(stream, clientWSReadLimit, &msg)
	} else {
		err = tunnelproto.ReadStreamMessage(stream, clientWSReadLimit, &msg)
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

func isTimeoutError(err error) bool {
	type timeout interface {
		Timeout() bool
	}
	if err == nil {
		return false
	}
	if te, ok := err.(timeout); ok {
		return te.Timeout()
	}
	return false
}

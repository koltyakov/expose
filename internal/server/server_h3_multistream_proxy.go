package server

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func (s *Server) proxyPublicHTTPH3MultiStream(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	if s.cfg.MaxBodyBytes > 0 && r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	}

	reqID := s.nextRequestID()
	if !sess.tryAcquirePending(maxPendingPerSessionFor(s.cfg)) {
		http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		return
	}
	defer sess.releasePending()

	stream, err := sess.acquireH3Worker(r.Context(), s.cfg.RequestTimeout)
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	requeue := true
	defer func() {
		if requeue {
			if !sess.addH3Worker(stream) {
				closeH3Stream(stream)
			}
			return
		}
		closeH3Stream(stream)
	}()

	requestHeaders := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	stripPublicAccessCookie(requestHeaders)
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, r.RemoteAddr)

	if _, err := s.sendRequestBodyToH3Stream(stream, reqID, r, requestHeaders, sess.usesH3StreamV2()); err != nil {
		requeue = false
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		} else if errors.Is(err, tunneltransport.ErrWritePumpBackpressure) {
			http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "tunnel write failed", http.StatusBadGateway)
		}
		return
	}

	msg, err := readH3StreamMessage(stream, s.cfg.RequestTimeout, sess.usesH3StreamV2())
	if err != nil || msg.Kind != tunnelproto.KindResponse || msg.Response == nil {
		requeue = false
		http.Error(w, "tunnel closed", http.StatusBadGateway)
		return
	}
	resp := msg.Response
	if shouldServeFallbackFavicon(r, resp.Status) {
		if resp.Streamed {
			// Streamed 404 responses may still have unread body frames.
			// Close this worker stream instead of reusing it.
			requeue = false
		}
		writeFallbackFavicon(w, r)
		s.queueDomainTouch(route.Domain.ID)
		return
	}
	respHeaders := resp.Headers
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
	for k, vals := range respHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.Status)

	if resp.Streamed {
		if !writeH3StreamedResponseBody(w, r, stream, s.cfg.RequestTimeout, sess.usesH3StreamV2()) {
			requeue = false
			return
		}
	} else {
		b, err := resp.Payload()
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
	}
	s.queueDomainTouch(route.Domain.ID)
}

func (s *Server) handlePublicWebSocketH3MultiStream(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	streamID := s.nextWSStreamID()
	stream, err := sess.acquireH3Worker(r.Context(), s.cfg.RequestTimeout)
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	defer closeH3Stream(stream)

	headers := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	stripPublicAccessCookie(headers)
	injectForwardedProxyHeaders(headers, r)
	injectForwardedFor(headers, r.RemoteAddr)
	openMsg := tunnelproto.Message{
		Kind: tunnelproto.KindWSOpen,
		WSOpen: &tunnelproto.WSOpen{
			ID:      streamID,
			Method:  r.Method,
			Path:    r.URL.Path,
			RawPath: r.URL.RawPath,
			Query:   r.URL.RawQuery,
			Headers: headers,
		},
	}
	if err := writeH3StreamJSON(stream, openMsg, sess.usesH3StreamV2()); err != nil {
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	msg, err := readH3StreamMessage(stream, s.cfg.RequestTimeout, sess.usesH3StreamV2())
	if err != nil || msg.Kind != tunnelproto.KindWSOpenAck || msg.WSOpenAck == nil {
		http.Error(w, "tunnel closed", http.StatusBadGateway)
		return
	}
	ack := msg.WSOpenAck
	if !ack.OK {
		status, message := publicWSOpenFailure(ack)
		http.Error(w, message, status)
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	if p := ack.Subprotocol; p != "" {
		upgrader.Subprotocols = []string{p}
	}
	publicConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = writeH3StreamJSON(stream, tunnelproto.Message{
			Kind:    tunnelproto.KindWSClose,
			WSClose: &tunnelproto.WSClose{ID: streamID, Code: websocket.CloseGoingAway, Text: "public upgrade failed"},
		}, sess.usesH3StreamV2())
		return
	}
	defer func() { _ = publicConn.Close() }()
	s.queueDomainTouch(route.Domain.ID)

	var writeMu sync.Mutex
	writeStreamJSON := func(msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeH3StreamJSON(stream, msg, sess.usesH3StreamV2())
	}
	writeWSData := func(payload []byte, msgType int) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeH3StreamWSData(stream, streamID, msgType, payload, sess.usesH3StreamV2())
	}

	readDone := make(chan struct{})
	writeDone := make(chan struct{})

	go func() {
		defer close(readDone)
		for {
			msgType, payload, err := publicConn.ReadMessage()
			if err != nil {
				code, text := websocket.CloseNormalClosure, ""
				if ce, ok := errors.AsType[*websocket.CloseError](err); ok {
					code, text = ce.Code, ce.Text
				}
				_ = writeStreamJSON(tunnelproto.Message{
					Kind:    tunnelproto.KindWSClose,
					WSClose: &tunnelproto.WSClose{ID: streamID, Code: code, Text: text},
				})
				return
			}
			if err := writeWSData(payload, msgType); err != nil {
				return
			}
		}
	}()

	go func() {
		defer close(writeDone)
		for {
			msg, err := readH3StreamMessage(stream, 0, sess.usesH3StreamV2())
			if err != nil {
				return
			}
			switch msg.Kind {
			case tunnelproto.KindWSData:
				if msg.WSData == nil {
					continue
				}
				b, err := msg.WSData.Payload()
				if err != nil {
					continue
				}
				if err := publicConn.WriteMessage(msg.WSData.MessageType, b); err != nil {
					return
				}
			case tunnelproto.KindWSClose:
				if msg.WSClose == nil {
					return
				}
				_ = publicConn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text),
					time.Now().Add(5*time.Second),
				)
				return
			}
		}
	}()

	select {
	case <-r.Context().Done():
	case <-readDone:
	case <-writeDone:
	}
}

func readH3StreamMessage(stream *http3.Stream, timeout time.Duration, useV2 bool) (tunnelproto.Message, error) {
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
		err = tunnelproto.ReadStreamMessageV2(stream, minWSReadLimit*2, &msg)
	} else {
		err = tunnelproto.ReadStreamMessage(stream, minWSReadLimit*2, &msg)
	}
	if err != nil {
		return tunnelproto.Message{}, err
	}
	return msg, nil
}

func writeH3StreamJSON(stream *http3.Stream, msg tunnelproto.Message, useV2 bool) error {
	if stream == nil {
		return io.EOF
	}
	_ = stream.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if useV2 {
		return tunnelproto.WriteStreamJSONV2(stream, msg)
	}
	return tunnelproto.WriteStreamJSON(stream, msg)
}

func writeH3StreamWSData(stream *http3.Stream, streamID string, messageType int, payload []byte, useV2 bool) error {
	if stream == nil {
		return io.EOF
	}
	_ = stream.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if useV2 {
		return tunnelproto.WriteStreamBinaryFrameV2(stream, tunnelproto.BinaryFrameWSData, streamID, messageType, payload)
	}
	return tunnelproto.WriteStreamBinaryFrame(stream, tunnelproto.BinaryFrameWSData, streamID, messageType, payload)
}

func writeH3StreamReqBody(stream *http3.Stream, reqID string, payload []byte, useV2 bool) error {
	if stream == nil {
		return io.EOF
	}
	_ = stream.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if useV2 {
		return tunnelproto.WriteStreamBinaryFrameV2(stream, tunnelproto.BinaryFrameReqBody, reqID, 0, payload)
	}
	return tunnelproto.WriteStreamBinaryFrame(stream, tunnelproto.BinaryFrameReqBody, reqID, 0, payload)
}

func (s *Server) sendRequestBodyToH3Stream(
	stream *http3.Stream,
	reqID string,
	r *http.Request,
	headers map[string][]string,
	useV2 bool,
) (bool, error) {
	requestTimeoutMs := s.requestTimeoutMillis()
	if r.Body == nil || r.Body == http.NoBody {
		return false, writeH3StreamJSON(stream, tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:        reqID,
				Method:    r.Method,
				Path:      r.URL.Path,
				RawPath:   r.URL.RawPath,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				TimeoutMs: requestTimeoutMs,
			},
		}, useV2)
	}
	defer func() { _ = r.Body.Close() }()

	firstBufRef := requestFirstChunkPool.Get().(*[]byte)
	firstBuf := *firstBufRef
	if cap(firstBuf) < streamingThreshold+1 {
		firstBuf = make([]byte, streamingThreshold+1)
	} else {
		firstBuf = firstBuf[:streamingThreshold+1]
	}
	*firstBufRef = firstBuf
	defer requestFirstChunkPool.Put(firstBufRef)
	n, readErr := io.ReadFull(r.Body, firstBuf)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		return false, writeH3StreamJSON(stream, tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:        reqID,
				Method:    r.Method,
				Path:      r.URL.Path,
				RawPath:   r.URL.RawPath,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				Body:      firstBuf[:n],
				TimeoutMs: requestTimeoutMs,
			},
		}, useV2)
	}
	if readErr != nil {
		return false, readErr
	}

	if err := writeH3StreamJSON(stream, tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:        reqID,
			Method:    r.Method,
			Path:      r.URL.Path,
			RawPath:   r.URL.RawPath,
			Query:     r.URL.RawQuery,
			Headers:   headers,
			Streamed:  true,
			TimeoutMs: requestTimeoutMs,
		},
	}, useV2); err != nil {
		return true, err
	}
	if err := writeH3StreamReqBody(stream, reqID, firstBuf[:n], useV2); err != nil {
		return true, err
	}

	chunkBufRef := requestStreamChunkPool.Get().(*[]byte)
	chunkBuf := *chunkBufRef
	if cap(chunkBuf) < streamingChunkSize {
		chunkBuf = make([]byte, streamingChunkSize)
	} else {
		chunkBuf = chunkBuf[:streamingChunkSize]
	}
	*chunkBufRef = chunkBuf
	defer requestStreamChunkPool.Put(chunkBufRef)
	for {
		cn, err := r.Body.Read(chunkBuf)
		if cn > 0 {
			if wErr := writeH3StreamReqBody(stream, reqID, chunkBuf[:cn], useV2); wErr != nil {
				return true, wErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return true, err
		}
	}
	return true, writeH3StreamJSON(stream, tunnelproto.Message{
		Kind:      tunnelproto.KindReqBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: reqID},
	}, useV2)
}

func writeH3StreamedResponseBody(
	w http.ResponseWriter,
	r *http.Request,
	stream *http3.Stream,
	chunkTimeout time.Duration,
	useV2 bool,
) bool {
	flusher, canFlush := w.(http.Flusher)
	for {
		msg, err := readH3StreamMessage(stream, chunkTimeout, useV2)
		if err != nil {
			return false
		}
		switch msg.Kind {
		case tunnelproto.KindRespBody:
			if msg.BodyChunk == nil {
				continue
			}
			b, err := msg.BodyChunk.Payload()
			if err == nil && len(b) > 0 {
				if _, wErr := w.Write(b); wErr != nil {
					return false
				}
				if canFlush {
					flusher.Flush()
				}
			}
		case tunnelproto.KindRespBodyEnd:
			return true
		}
		select {
		case <-r.Context().Done():
			return false
		default:
		}
	}
}

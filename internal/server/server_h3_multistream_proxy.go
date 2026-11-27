package server

import (
	"bufio"
	"context"
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
)

func (s *Server) proxyPublicHTTPH3MultiStream(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	reqID := s.nextRequestID()
	if !sess.tryAcquirePending(maxPendingPerSessionFor(s.cfg)) {
		s.writePublicRejection(w, r, http.StatusServiceUnavailable, "tunnel overloaded", rejectionConcurrency)
		return
	}
	defer sess.releasePending()

	stream, err := sess.acquireH3Worker(r.Context(), s.cfg.RequestTimeout)
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	requeue := true
	var upload *requestUpload
	// Reset only this worker when the public caller leaves. Besides unblocking
	// local stream I/O, STOP_SENDING cancels the client's upstream request.
	// Only cancel here: Close shares unsynchronized frame state with Write, so
	// it runs below once no goroutine can still write the stream.
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(r.Context(), func() {
		cancelH3StreamIO(stream)
		close(cancelDone)
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone // Do not return a worker while its reset is in flight.
		}
		upload.finish(false)
		if requeue && upload.completed() && r.Context().Err() == nil {
			if !sess.addH3Worker(stream) {
				closeH3Stream(stream)
			}
			return
		}
		closeH3Stream(stream)
	}()

	requestHeaders := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	preparePublicAccessHeaders(requestHeaders, r, route)
	injectForwardedProxyHeaders(requestHeaders, r)
	injectForwardedFor(requestHeaders, s.clientIP(r))

	useV2 := sess.usesH3StreamV2()
	writeMsg := func(msg tunnelproto.Message) error { return writeH3StreamJSON(stream, msg, useV2) }
	streamed, err := s.sendRequestHead(reqID, r, requestHeaders, writeMsg)
	if err != nil {
		requeue = false
		s.writeUploadFailure(w, r, err)
		return
	}

	headerWait := &h3HeaderWait{stream: stream, timeout: s.cfg.RequestTimeout, armed: !streamed}
	if streamed {
		// Upload in the background, so a response sent before the origin
		// reads the whole body reaches the visitor at once. The response
		// header timeout starts when the upload ends.
		upload = s.startRequestUpload(w, r, reqID, writeMsg, func(payload []byte) error {
			return writeH3StreamReqBody(stream, reqID, payload, useV2)
		}, func() {
			// Abandon a blocked write. The worker is not reused after an
			// interrupted upload.
			stream.CancelWrite(0)
		}, func(err error) {
			switch {
			case err == nil:
				headerWait.arm()
			case errors.Is(err, errUploadStopped):
			case isUploadTunnelError(err):
				// A partly written frame cannot be continued. The peer may
				// still have answered, as an older client does when the
				// origin responds early and it resets the worker.
				stream.CancelWrite(0)
				headerWait.arm()
			default:
				// The visitor's body failed: abandon the request.
				cancelH3StreamIO(stream)
			}
		})
	}

	msg, err := headerWait.read(useV2)
	if err != nil || msg.Kind != tunnelproto.KindResponse || msg.Response == nil || msg.Response.ID != reqID {
		requeue = false
		if uploadErr := upload.failure(); uploadErr != nil {
			s.writeUploadFailure(w, r, uploadErr)
			return
		}
		http.Error(w, "tunnel closed", http.StatusBadGateway)
		return
	}
	resp := msg.Response
	if s.handleDelegatedAccessResponse(w, r, route, resp.Status, resp.Headers) {
		if resp.Streamed {
			requeue = false // Unread probe/challenge body frames must not be reused.
		}
		return
	}
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
	stripUpstreamAltSvc(respHeaders)
	for k, vals := range respHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	setInlineContentLength(w, r, resp, upload)
	w.WriteHeader(normalizeUpstreamStatus(resp.Status))

	if resp.Streamed {
		flushResponse(w)
		ok, reusable := writeH3StreamedResponseBody(w, r, stream, s.cfg.RequestTimeout, useV2)
		if !reusable {
			requeue = false
		}
		if !ok {
			if r.Context().Err() == nil {
				// The status and partial body already went out. Match the WS
				// path: do not finish an unknown-length body as a clean EOF.
				panic(http.ErrAbortHandler)
			}
			return
		}
	} else {
		b, err := resp.Payload()
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
	}
	finishUploadAfterResponse(w, r, normalizeUpstreamStatus(resp.Status), upload)
	s.queueDomainTouch(route.Domain.ID)
}

// h3HeaderWait reads the response header from a worker stream. While the
// request body still uploads the read has no deadline; arm starts the
// RequestTimeout once the upload ends. The upload goroutine may call arm while
// the handler reads, so both sides use mu to keep a deadline from outliving
// the read.
type h3HeaderWait struct {
	stream  *http3.Stream
	timeout time.Duration

	mu      sync.Mutex
	armed   bool
	reading bool
}

func (h *h3HeaderWait) arm() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.armed = true
	if h.reading && h.timeout > 0 {
		_ = h.stream.SetReadDeadline(time.Now().Add(h.timeout))
	}
}

func (h *h3HeaderWait) read(useV2 bool) (tunnelproto.Message, error) {
	h.mu.Lock()
	h.reading = true
	if h.armed && h.timeout > 0 {
		_ = h.stream.SetReadDeadline(time.Now().Add(h.timeout))
	}
	h.mu.Unlock()
	msg, err := readH3StreamMessageFrom(h.stream, h.stream, 0, useV2)
	h.mu.Lock()
	h.reading = false
	_ = h.stream.SetReadDeadline(time.Time{})
	h.mu.Unlock()
	return msg, err
}

func (s *Server) handlePublicWebSocketH3MultiStream(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	if publicAccessProtected(route) && !publicWebSocketOriginAllowed(r) {
		http.Error(w, "websocket origin not allowed", http.StatusForbidden)
		return
	}
	if !sess.tryAcquireWebSocket(maxPendingPerSessionFor(s.cfg)) {
		s.writePublicRejection(w, r, http.StatusServiceUnavailable, "tunnel overloaded", rejectionConcurrency)
		return
	}
	defer sess.releaseWebSocket()

	streamID := s.nextWSStreamID()
	stream, err := sess.acquireH3Worker(r.Context(), s.cfg.RequestTimeout)
	if err != nil {
		http.Error(w, "tunnel unavailable", http.StatusServiceUnavailable)
		return
	}
	// The relay goroutines below are joined before this runs: Close must not
	// race a Write. A clean close keeps the final close notice instead of
	// resetting it away.
	resetWrite := true
	defer func() {
		stream.CancelRead(0)
		if resetWrite {
			stream.CancelWrite(0)
		}
		_ = stream.Close()
	}()

	headers := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	preparePublicAccessHeaders(headers, r, route)
	injectForwardedProxyHeaders(headers, r)
	injectForwardedFor(headers, s.clientIP(r))
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
		if s.handleDelegatedAccessResponse(w, r, route, status, nil) {
			return
		}
		http.Error(w, message, status)
		return
	}

	checkOrigin := func(*http.Request) bool { return true }
	if publicAccessProtected(route) {
		checkOrigin = publicWebSocketOriginAllowed
	}
	upgrader := websocket.Upgrader{CheckOrigin: checkOrigin}
	if p := ack.Subprotocol; p != "" {
		upgrader.Subprotocols = []string{p}
	}
	publicConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		if writeH3StreamJSON(stream, tunnelproto.Message{
			Kind:    tunnelproto.KindWSClose,
			WSClose: &tunnelproto.WSClose{ID: streamID, Code: websocket.CloseGoingAway, Text: "public upgrade failed"},
		}, sess.usesH3StreamV2()) == nil {
			resetWrite = false
		}
		return
	}
	publicConn.SetReadLimit(webSocketReadLimitFor(s.cfg))
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

	s.hub.wg.Go(func() {
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
	})

	s.hub.wg.Go(func() {
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
				_ = publicConn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
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
	})

	select {
	case <-r.Context().Done():
	case <-readDone:
		// The visitor side ended and its close notice was written; no
		// goroutine writes the stream any more.
		resetWrite = false
	case <-writeDone:
	}
	// Stop both relays and wait for them before the deferred Close.
	// CancelWrite and CancelRead are safe alongside Read and Write, and
	// closing the public connection ends its blocked read or write.
	if resetWrite {
		stream.CancelWrite(0)
	}
	stream.CancelRead(0)
	_ = publicConn.Close()
	<-readDone
	<-writeDone
}

func readH3StreamMessage(stream *http3.Stream, timeout time.Duration, useV2 bool) (tunnelproto.Message, error) {
	if stream == nil {
		return tunnelproto.Message{}, io.EOF
	}
	return readH3StreamMessageFrom(stream, stream, timeout, useV2)
}

// readH3StreamMessageFrom decodes one frame from src, which reads from
// stream (possibly through a buffer); the deadline applies to stream.
func readH3StreamMessageFrom(stream readDeadliner, src io.Reader, timeout time.Duration, useV2 bool) (tunnelproto.Message, error) {
	var msg tunnelproto.Message
	if timeout > 0 {
		_ = stream.SetReadDeadline(time.Now().Add(timeout))
		defer func() { _ = stream.SetReadDeadline(time.Time{}) }()
	}
	var err error
	if useV2 {
		err = tunnelproto.ReadStreamMessageV2(src, minWSReadLimit*2, &msg)
	} else {
		err = tunnelproto.ReadStreamMessage(src, minWSReadLimit*2, &msg)
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

// writeH3StreamedResponseBody copies body frames from a worker stream to
// the public response. Like the WS path, it flushes when no further frame
// bytes are waiting (or every maxUnflushedStreamBytes), so chunks that arrive
// together leave in one flush. reusable reports whether the worker stream
// ended exactly at the end frame and may serve another request.
func writeH3StreamedResponseBody(
	w http.ResponseWriter,
	r *http.Request,
	stream h3FrameReader,
	chunkTimeout time.Duration,
	useV2 bool,
) (ok, reusable bool) {
	flusher, canFlush := w.(http.Flusher)
	src := bufio.NewReaderSize(stream, h3ResponseReadBuffer)
	unflushed := 0
	for {
		msg, err := readH3StreamMessageFrom(stream, src, chunkTimeout, useV2)
		if err != nil {
			return false, false
		}
		switch msg.Kind {
		case tunnelproto.KindRespBody:
			if msg.BodyChunk == nil {
				continue
			}
			b, err := msg.BodyChunk.Payload()
			if err == nil && len(b) > 0 {
				n, wErr := w.Write(b)
				tunnelproto.ReleaseBodyChunk(b)
				if wErr != nil {
					return false, false
				}
				unflushed += n
				if canFlush && (unflushed >= maxUnflushedStreamBytes || src.Buffered() == 0) {
					flusher.Flush()
					unflushed = 0
				}
			} else {
				tunnelproto.ReleaseBodyChunk(b)
			}
		case tunnelproto.KindRespBodyEnd:
			if canFlush && unflushed > 0 {
				flusher.Flush()
			}
			if msg.BodyChunk != nil && msg.BodyChunk.Error != "" {
				return false, false
			}
			// Bytes read past the end frame belong to nobody; such a stream
			// must not be reused.
			return true, src.Buffered() == 0
		}
		select {
		case <-r.Context().Done():
			return false, false
		default:
		}
	}
}

type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// h3FrameReader is the part of a worker stream the response copy uses.
type h3FrameReader interface {
	io.Reader
	readDeadliner
}

// h3ResponseReadBuffer sizes the read-ahead that shows whether further body
// frames are already waiting on a worker stream.
const h3ResponseReadBuffer = 32 << 10

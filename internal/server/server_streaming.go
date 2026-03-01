package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	requestFirstChunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, streamingThreshold+1)
			return &b
		},
	}
	requestStreamChunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, streamingChunkSize)
			return &b
		},
	}
)

// sendRequestBody reads the public HTTP request body and sends it to the
// tunnel client. For small bodies (<= streamingThreshold) the body is inlined
// in the KindRequest message. For large bodies it sends a KindRequest with
// Streamed=true followed by KindReqBody chunks and a KindReqBodyEnd.
// Returns whether the request was streamed and any write error.
func (s *Server) sendRequestBody(sess *session, reqID string, r *http.Request, headers map[string][]string) (bool, error) {
	requestTimeoutMs := s.requestTimeoutMillis()
	if r.Body == nil || r.Body == http.NoBody {
		return false, sess.writeJSON(tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:        reqID,
				Method:    r.Method,
				Path:      r.URL.Path,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				TimeoutMs: requestTimeoutMs,
			},
		})
	}
	defer func() { _ = r.Body.Close() }()

	// Read the first chunk plus one byte to decide inline vs streamed.
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
		// The entire body fits within the threshold - send inline.
		return false, sess.writeJSON(tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:        reqID,
				Method:    r.Method,
				Path:      r.URL.Path,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				BodyB64:   tunnelproto.EncodeBody(firstBuf[:n]),
				TimeoutMs: requestTimeoutMs,
			},
		})
	}
	if readErr != nil {
		return false, readErr
	}

	// Body exceeds threshold - stream it.
	if err := sess.writeJSON(tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:        reqID,
			Method:    r.Method,
			Path:      r.URL.Path,
			Query:     r.URL.RawQuery,
			Headers:   headers,
			Streamed:  true,
			TimeoutMs: requestTimeoutMs,
		},
	}); err != nil {
		return true, err
	}

	// Send the already-read data as the first body chunk.
	if err := sess.writeBinaryFrame(tunnelproto.BinaryFrameReqBody, reqID, 0, firstBuf[:n]); err != nil {
		return true, err
	}

	// Read remaining body in chunks.
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
			if wErr := sess.writeBinaryFrame(tunnelproto.BinaryFrameReqBody, reqID, 0, chunkBuf[:cn]); wErr != nil {
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

	// Signal end of request body.
	return true, sess.writeJSON(tunnelproto.Message{
		Kind:      tunnelproto.KindReqBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: reqID},
	})
}

func (s *Server) requestTimeoutMillis() int {
	timeout := s.cfg.RequestTimeout
	if timeout <= 0 {
		return 0
	}
	return int(timeout / time.Millisecond)
}

// writeStreamedResponseBody reads body chunks from the pending channel and
// writes them to the HTTP response writer, flushing after each chunk.
// It returns true when the upstream stream completed normally.
func (s *Server) writeStreamedResponseBody(w http.ResponseWriter, r *http.Request, respCh <-chan tunnelproto.Message, chunkTimeout time.Duration) bool {
	flusher, canFlush := w.(http.Flusher)
	timer := time.NewTimer(chunkTimeout)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	for {
		select {
		case msg, ok := <-respCh:
			if !ok {
				return false // tunnel closed
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(chunkTimeout)

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
		case <-timer.C:
			return false // chunk timeout
		case <-r.Context().Done():
			return false // client disconnected
		}
	}
}

// streamSend attempts to write msg to ch without blocking the read loop for
// too long. Mirrors wsPendingSend but for HTTP body streaming channels.
func (s *session) streamSend(ch chan tunnelproto.Message, msg tunnelproto.Message, wait time.Duration) bool {
	select {
	case ch <- msg:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ch <- msg:
		return true
	case <-timer.C:
		return false
	}
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) (*bytes.Buffer, func(), error) {
	reader := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = reader.Close() }()
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, err := buf.ReadFrom(reader)
	if err != nil {
		bufferPool.Put(buf)
		return nil, nil, err
	}
	return buf, func() { bufferPool.Put(buf) }, nil
}

func isBodyTooLargeError(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}

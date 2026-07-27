package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/timerpool"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	// requestSmallChunkPool serves the common case: bodies that fit well
	// under streamingThreshold. Handing every request with a body a
	// streamingThreshold-sized buffer meant a form post of a few hundred
	// bytes checked out 256 KiB, so peak memory scaled with in-flight
	// requests rather than with actual body sizes.
	requestSmallChunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, smallBodyBufferSize)
			return &b
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

// smallBodyBufferSize is the first read size for request bodies. Bodies at or
// below it never touch the larger pools.
const smallBodyBufferSize = 16 * 1024

// maxPooledBufferBytes caps the capacity of a bytes.Buffer returned to
// bufferPool, so one large request cannot pin an oversized buffer forever.
const maxPooledBufferBytes = 1 << 20

func getPooledBuf(pool *sync.Pool, size int) (*[]byte, []byte) {
	ref := pool.Get().(*[]byte)
	buf := *ref
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}
	*ref = buf
	return ref, buf
}

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
				RawPath:   r.URL.RawPath,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				TimeoutMs: requestTimeoutMs,
			},
		})
	}
	defer func() { _ = r.Body.Close() }()

	// Probe with a small buffer first; only bodies that outgrow it need a
	// streamingThreshold-sized one. When Content-Length already says the body
	// exceeds the threshold, skip the probe and stream directly.
	var (
		firstBuf []byte
		n        int
		readErr  error
	)
	knownLarge := r.ContentLength > int64(streamingThreshold)

	if !knownLarge {
		smallRef, smallBuf := getPooledBuf(&requestSmallChunkPool, smallBodyBufferSize)
		defer requestSmallChunkPool.Put(smallRef)

		n, readErr = io.ReadFull(r.Body, smallBuf)
		firstBuf = smallBuf
	}

	// The small buffer filled without hitting EOF, so the body may still be
	// inlineable but needs the larger buffer to find out.
	if knownLarge || readErr == nil {
		bigRef, bigBuf := getPooledBuf(&requestFirstChunkPool, streamingThreshold+1)
		defer requestFirstChunkPool.Put(bigRef)

		copied := copy(bigBuf, firstBuf[:n])
		var more int
		more, readErr = io.ReadFull(r.Body, bigBuf[copied:])
		n = copied + more
		firstBuf = bigBuf
	}

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		// The entire body fits within the threshold - send inline. Passing the
		// pooled buffer without a copy is safe: writeJSON blocks until the
		// write pump has fully written (or failed) the message.
		return false, sess.writeJSON(tunnelproto.Message{
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
			RawPath:   r.URL.RawPath,
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
	chunkBufRef, chunkBuf := getPooledBuf(&requestStreamChunkPool, streamingChunkSize)
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
// It returns true when the upstream stream completed normally; an
// abort-terminated stream (client reported an upstream failure) returns
// false so the caller can tear the public connection down rather than end
// the truncated response as if it were complete.
func (s *Server) writeStreamedResponseBody(w http.ResponseWriter, r *http.Request, pending *pendingRequest, chunkTimeout time.Duration) bool {
	bodyCh, doneCh := pending.bodyStream()
	flusher, canFlush := w.(http.Flusher)
	timer := timerpool.Acquire(chunkTimeout)
	defer timerpool.Release(timer)

	for {
		select {
		case chunk := <-bodyCh:
			if chunk == nil {
				continue
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(chunkTimeout)
			if len(chunk) > 0 {
				_, wErr := w.Write(chunk)
				tunnelproto.ReleaseBodyChunk(chunk)
				if wErr != nil {
					return false
				}
				if canFlush {
					flusher.Flush()
				}
			}
		case <-doneCh:
			for {
				select {
				case chunk := <-bodyCh:
					if len(chunk) == 0 {
						continue
					}
					_, wErr := w.Write(chunk)
					tunnelproto.ReleaseBodyChunk(chunk)
					if wErr != nil {
						return false
					}
					if canFlush {
						flusher.Flush()
					}
				default:
					return !pending.wasAborted()
				}
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
func (s *session) streamSend(ch chan []byte, payload []byte, wait time.Duration) bool {
	// Fast path: non-blocking attempt.
	select {
	case ch <- payload:
		return true
	default:
	}
	if wait <= 0 {
		return false
	}
	timer := timerpool.Acquire(wait)
	defer timerpool.Release(timer)
	select {
	case ch <- payload:
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
		releasePooledBuffer(buf)
		return nil, nil, err
	}
	return buf, func() { releasePooledBuffer(buf) }, nil
}

// releasePooledBuffer returns buf to the pool unless it grew past
// maxPooledBufferBytes, in which case it is dropped so a single large request
// does not keep an oversized buffer alive for the process lifetime.
func releasePooledBuffer(buf *bytes.Buffer) {
	if buf == nil || buf.Cap() > maxPooledBufferBytes {
		return
	}
	bufferPool.Put(buf)
}

func isBodyTooLargeError(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}

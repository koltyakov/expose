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

// smallBodyBufferSize sizes the pool for known-small request bodies. Bodies at
// or below it never touch the larger upload pools.
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

// sendRequestHead writes the request envelope. Known-small bodies travel
// inline and are fully consumed. streamed reports that the envelope announced
// a streamed body: the caller then owns sending it with streamRequestBody,
// which closes r.Body. The body is also closed when sending the envelope fails.
func (s *Server) sendRequestHead(reqID string, r *http.Request, headers map[string][]string, writeMsg func(tunnelproto.Message) error) (streamed bool, err error) {
	requestTimeoutMs := s.requestTimeoutMillis()
	if !hasRequestBody(r) {
		return false, writeMsg(tunnelproto.Message{
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
	if r.ContentLength > 0 && r.ContentLength <= streamingThreshold {
		defer func() { _ = r.Body.Close() }()
		pool, size := &requestSmallChunkPool, smallBodyBufferSize
		if r.ContentLength > int64(size) {
			pool, size = &requestFirstChunkPool, streamingThreshold+1
		}
		ref, buf := getPooledBuf(pool, size)
		defer pool.Put(ref)
		n, err := io.ReadFull(r.Body, buf[:int(r.ContentLength)])
		if err != nil {
			return false, err
		}
		return false, writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:        reqID,
				Method:    r.Method,
				Path:      r.URL.Path,
				RawPath:   r.URL.RawPath,
				Query:     r.URL.RawQuery,
				Headers:   headers,
				Body:      buf[:n],
				TimeoutMs: requestTimeoutMs,
			},
		})
	}
	if err := writeMsg(tunnelproto.Message{
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
		_ = r.Body.Close()
		return true, err
	}
	return true, nil
}

// streamRequestBody copies r.Body after a streamed envelope and ends it with
// KindReqBodyEnd. Tunnel write failures are wrapped in uploadTunnelError.
// Once stopped reports true, read bytes are discarded and the copy ends with
// errUploadStopped. An HTTP/1 body is then closed, which lets net/http drain
// a bounded remainder so the visitor's connection can be reused. A
// multiplexed body is left for the server to reset after the handler: closing
// an HTTP/3 body early sends STOP_SENDING ahead of the response's end.
func streamRequestBody(reqID string, r *http.Request, writeMsg func(tunnelproto.Message) error, writeChunk func([]byte) error, stopped func() bool) (err error) {
	defer func() {
		if !errors.Is(err, errUploadStopped) || r.ProtoMajor == 1 {
			_ = r.Body.Close()
		}
	}()
	chunkBufRef, chunkBuf := getPooledBuf(&requestStreamChunkPool, streamingChunkSize)
	defer requestStreamChunkPool.Put(chunkBufRef)
	var sent int64
	for {
		cn, readErr := r.Body.Read(chunkBuf)
		if stopped() {
			return errUploadStopped
		}
		if cn > 0 {
			sent += int64(cn)
			if wErr := writeChunk(chunkBuf[:cn]); wErr != nil {
				return &uploadTunnelError{err: wErr}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if r.ContentLength > 0 && sent != r.ContentLength {
					return io.ErrUnexpectedEOF
				}
				break
			}
			return readErr
		}
	}

	// Signal end of request body.
	if err := writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindReqBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: reqID},
	}); err != nil {
		return &uploadTunnelError{err: err}
	}
	return nil
}

func (s *Server) requestTimeoutMillis() int {
	timeout := s.cfg.RequestTimeout
	if timeout <= 0 {
		return 0
	}
	return int(timeout / time.Millisecond)
}

// maxUnflushedStreamBytes bounds how much already-queued response data is
// written before a flush. Chunks that are queued together are flushed together
// (one TLS record and syscall instead of one per chunk), while a producer that
// stays ahead of the public client still reaches it in bounded batches.
const maxUnflushedStreamBytes = 64 << 10

// writeStreamedResponseBody reads body chunks from the pending queue and
// writes them to the HTTP response writer, flushing whenever the queue drains.
// It returns true when the upstream stream completed normally; an
// abort-terminated stream (client reported an upstream failure) returns
// false so the caller can tear the public connection down rather than end
// the truncated response as if it were complete.
func (s *Server) writeStreamedResponseBody(w http.ResponseWriter, r *http.Request, pending *pendingRequest, chunkTimeout time.Duration) bool {
	bodyReady, doneCh := pending.bodyStream()
	flusher, canFlush := w.(http.Flusher)
	timer := timerpool.Acquire(chunkTimeout)
	defer timerpool.Release(timer)
	unflushed := 0

	for {
		select {
		case <-r.Context().Done():
			return false // client disconnected
		default:
		}
		chunk, done := pending.nextBodyChunk()
		if chunk != nil {
			n, wErr := w.Write(chunk)
			pending.releaseBodyChunk(chunk)
			if wErr != nil {
				return false
			}
			unflushed += n
			if canFlush && (unflushed >= maxUnflushedStreamBytes || !pending.hasQueuedBody()) {
				flusher.Flush()
				unflushed = 0
			}
			continue
		}
		if done {
			return !pending.wasAborted()
		}
		// Time out only while waiting for another upstream chunk. A slow
		// public Write/Flush must not expire an already buffered clean end.
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(chunkTimeout)
		select {
		case <-bodyReady:
		case <-doneCh:
		case <-timer.C:
			return false // chunk timeout
		case <-r.Context().Done():
			return false // client disconnected
		}
	}
}

// flushResponse sends buffered headers and body bytes to the public client.
func flushResponse(w http.ResponseWriter) {
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
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

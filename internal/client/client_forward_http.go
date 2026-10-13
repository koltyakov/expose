package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/timerpool"
	"github.com/koltyakov/expose/internal/traffic"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	responseFirstChunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, streamingThreshold+1)
			return &b
		},
	}
	responseStreamChunkPool = sync.Pool{
		New: func() any {
			b := make([]byte, streamingChunkSize)
			return &b
		},
	}
)

func joinForwardTarget(base *url.URL, path, rawPath, rawQuery string) url.URL {
	target := *base
	basePath := strings.TrimSuffix(base.Path, "/")
	target.Path = basePath + path
	target.RawQuery = rawQuery

	baseRawPath := strings.TrimSuffix(base.EscapedPath(), "/")
	if rawPath == "" {
		rawPath = escapePathPreservingSlashes(path)
	}
	target.RawPath = baseRawPath + rawPath
	return target
}

func escapePathPreservingSlashes(path string) string {
	if path == "" {
		return ""
	}
	segments := strings.Split(path, "/")
	for i := range segments {
		segments[i] = url.PathEscape(segments[i])
	}
	return strings.Join(segments, "/")
}

func (c *Client) forwardLocal(ctx context.Context, base *url.URL, req *tunnelproto.HTTPRequest) *tunnelproto.HTTPResponse {
	target := joinForwardTarget(base, req.Path, req.RawPath, req.Query)

	body, err := req.Payload()
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), newTrafficCountingReader(bytes.NewReader(body), func(n int) {
		c.recordTraffic(traffic.DirectionInbound, int64(n))
	}))
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	headers := tunnelproto.ShallowCloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	localReq.Header = headers
	localReq.Header.Del("Host")
	setForwardedContentLength(localReq, headers, int64(len(body)))
	if forwardedHost != "" {
		localReq.Host = forwardedHost
	} else {
		localReq.Host = base.Host
	}

	resp, err := c.fwdClient.Do(localReq)
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:    []byte("local upstream unavailable"),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	respHeaders := tunnelproto.ShallowCloneHeaders(resp.Header)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  resp.StatusCode,
			Headers: respHeaders,
		}
	}
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	_, err = buf.ReadFrom(io.LimitReader(newTrafficCountingReader(resp.Body, func(n int) {
		c.recordTraffic(traffic.DirectionOutbound, int64(n))
	}), localForwardResponseMaxB64+1))
	if err != nil {
		bufferPool.Put(buf)
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:    []byte("failed to read local upstream response"),
		}
	}
	if buf.Len() > localForwardResponseMaxB64 {
		bufferPool.Put(buf)
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:    []byte("local upstream response too large"),
		}
	}
	// Take ownership of the buffer contents without copying. The buffer is
	// not returned to the pool when the response body is used — this trades a
	// small pool miss for avoiding a full body copy (up to 10MB).
	bodyBytes := buf.Bytes()
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
	return &tunnelproto.HTTPResponse{
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: respHeaders,
		Body:    bodyBytes,
	}
}

// forwardAndSend handles a tunnelled HTTP request, optionally with a streamed
// request body (bodyCh != nil), forwards it to the local upstream, and sends
// the response back through writeMsg. Large response bodies (exceeding
// streamingThreshold) are streamed as multiple messages instead of being
// buffered entirely in memory.
func (c *Client) forwardAndSend(
	ctx context.Context,
	base *url.URL,
	req *tunnelproto.HTTPRequest,
	bodyCh <-chan []byte,
	writeMsg func(tunnelproto.Message) error,
	writeRespBodyChunk func(id string, payload []byte) error,
) {
	started := time.Now()
	target := joinForwardTarget(base, req.Path, req.RawPath, req.Query)

	// Build request body reader.
	var body io.Reader
	var pipeReader *io.PipeReader
	contentLength := int64(-1)
	if bodyCh != nil {
		pr, pw := io.Pipe()
		pipeReader = pr
		go func() {
			defer func() { _ = pw.Close() }()
			defer func() {
				for chunk := range bodyCh {
					tunnelproto.ReleaseBodyChunk(chunk)
				}
			}()
			for {
				select {
				case chunk, ok := <-bodyCh:
					if !ok {
						return
					}
					data := chunk
					for len(data) > 0 {
						written, err := pw.Write(data)
						if written > 0 {
							c.recordTraffic(traffic.DirectionInbound, int64(written))
							data = data[written:]
						}
						if err != nil {
							tunnelproto.ReleaseBodyChunk(chunk)
							return
						}
					}
					// The pipe reader has copied every byte once Write returns,
					// so the chunk's pooled buffer can be recycled.
					tunnelproto.ReleaseBodyChunk(chunk)
				case <-ctx.Done():
					pw.CloseWithError(ctx.Err())
					return
				}
			}
		}()
		body = pr
	} else {
		data, err := req.Payload()
		if err != nil {
			_ = writeMsg(tunnelproto.Message{
				Kind:     tunnelproto.KindResponse,
				Response: &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway},
			})
			c.logForwardResult(req, http.StatusBadGateway, started)
			return
		}
		body = newTrafficCountingReader(bytes.NewReader(data), func(n int) {
			c.recordTraffic(traffic.DirectionInbound, int64(n))
		})
		contentLength = int64(len(data))
	}
	if pipeReader != nil {
		// Ensure the body pump goroutine unblocks if forwarding fails before the
		// local upstream reads the streamed request body.
		defer func() { _ = pipeReader.Close() }()
	}

	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
	if err != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind:     tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}

	headers := tunnelproto.ShallowCloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	localReq.Header = headers
	localReq.Header.Del("Host")
	setForwardedContentLength(localReq, headers, contentLength)
	if forwardedHost != "" {
		localReq.Host = forwardedHost
	} else {
		localReq.Host = base.Host
	}

	resp, err := c.fwdClient.Do(localReq)
	if err != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  http.StatusBadGateway,
				Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
				Body:    []byte("local upstream unavailable"),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	respHeaders := tunnelproto.ShallowCloneHeaders(resp.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)

	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  resp.StatusCode,
				Headers: respHeaders,
			},
		})
		return
	}

	// Send bodies that complete promptly inline with their headers. Anything
	// still arriving after inlineResponseWindow, or larger than
	// streamingThreshold, is streamed as it arrives, so slow producers such as
	// server-sent events and long polls are not held back.
	pump := startResponseBodyPump(resp.Body, func(n int) {
		c.recordTraffic(traffic.DirectionOutbound, int64(n))
	})
	defer pump.close()

	window := timerpool.Acquire(inlineResponseWindow)
	defer timerpool.Release(window)

	var (
		head     bodyRead // the first read owns the buffer that small bodies accumulate in
		buffered []byte
		overflow bodyRead
		complete bool
		readErr  error
	)
	defer func() { head.release() }()
collect:
	for len(buffered) <= streamingThreshold {
		select {
		case read := <-pump.reads:
			switch {
			case read.n == 0:
			case head.ref == nil:
				head, buffered = read, read.data()
			case len(buffered)+read.n <= cap(buffered):
				buffered = append(buffered, read.data()...)
				read.release()
			default:
				overflow = read
			}
			if read.err != nil {
				if errors.Is(read.err, io.EOF) || errors.Is(read.err, io.ErrUnexpectedEOF) {
					complete = true
				} else {
					readErr = read.err
				}
				break collect
			}
			if overflow.ref != nil {
				break collect
			}
		case <-window.C:
			break collect
		}
	}
	defer func() { overflow.release() }()

	if readErr != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  http.StatusBadGateway,
				Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
				Body:    []byte("failed to read local upstream response"),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}

	if complete && overflow.ref == nil && len(buffered) <= streamingThreshold {
		// Passing the pooled buffer without a copy is safe: writeMsg blocks
		// until the message has been fully written (or failed).
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  resp.StatusCode,
				Headers: respHeaders,
				Body:    buffered,
			},
		})
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	if err := writeMsg(tunnelproto.Message{
		Kind: tunnelproto.KindResponse,
		Response: &tunnelproto.HTTPResponse{
			ID:       req.ID,
			Status:   resp.StatusCode,
			Headers:  respHeaders,
			Streamed: true,
		},
	}); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	sendChunk := func(data []byte) error {
		if len(data) == 0 {
			return nil
		}
		if writeRespBodyChunk != nil {
			return writeRespBodyChunk(req.ID, data)
		}
		return writeMsg(tunnelproto.Message{
			Kind:      tunnelproto.KindRespBody,
			BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, Data: append([]byte(nil), data...)},
		})
	}
	if err := sendChunk(buffered); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}
	if err := sendChunk(overflow.data()); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	for !complete {
		read := <-pump.reads
		err := sendChunk(read.data())
		read.release()
		if err != nil {
			c.logForwardResult(req, resp.StatusCode, started)
			return
		}
		if read.err == nil {
			continue
		}
		if !errors.Is(read.err, io.EOF) {
			// Tell the server the stream failed so it aborts the public
			// request immediately instead of waiting out the chunk timeout.
			_ = writeMsg(tunnelproto.Message{
				Kind:      tunnelproto.KindRespBodyEnd,
				BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, Error: "local upstream read failed"},
			})
			c.logForwardResult(req, http.StatusBadGateway, started)
			return
		}
		complete = true
	}

	// Signal end of response buffered.
	_ = writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindRespBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: req.ID},
	})
	c.logForwardResult(req, resp.StatusCode, started)
}

// bodyRead is one read from a local response body. Its pooled buffer belongs
// to whoever holds the bodyRead, which returns it with release.
type bodyRead struct {
	ref  *[]byte
	pool *sync.Pool
	n    int
	err  error
}

func (r bodyRead) data() []byte {
	if r.ref == nil {
		return nil
	}
	return (*r.ref)[:r.n]
}

func (r bodyRead) release() {
	if r.ref != nil {
		r.pool.Put(r.ref)
	}
}

// responseBodyPump reads a local response body in the background, so the
// forwarder can choose inline or streamed delivery without blocking on a slow
// producer. The first read uses a buffer that can hold a whole inline body.
type responseBodyPump struct {
	reads chan bodyRead
	stop  chan struct{}
}

func startResponseBodyPump(body io.Reader, onRead func(int)) *responseBodyPump {
	p := &responseBodyPump{reads: make(chan bodyRead), stop: make(chan struct{})}
	go p.run(body, onRead)
	return p
}

func (p *responseBodyPump) run(body io.Reader, onRead func(int)) {
	pool, size := &responseFirstChunkPool, streamingThreshold+1
	for {
		ref := pool.Get().(*[]byte)
		if cap(*ref) < size {
			*ref = make([]byte, size)
		}
		*ref = (*ref)[:size]
		n, err := body.Read(*ref)
		if n > 0 && onRead != nil {
			onRead(n)
		}
		if n == 0 && err == nil {
			pool.Put(ref)
			continue
		}
		read := bodyRead{ref: ref, pool: pool, n: n, err: err}
		if n == 0 {
			pool.Put(ref)
			read.ref = nil
		}
		select {
		case p.reads <- read:
		case <-p.stop:
			read.release()
			return
		}
		if err != nil {
			return
		}
		if n > 0 {
			pool, size = &responseStreamChunkPool, streamingChunkSize
		}
	}
}

// close stops delivery. A read still blocked on the body ends once the
// caller closes the body.
func (p *responseBodyPump) close() {
	close(p.stop)
}

func setForwardedContentLength(req *http.Request, headers map[string][]string, fallback int64) {
	contentLength := fallback
	if value := strings.TrimSpace(firstHeaderValueCI(headers, "Content-Length")); value != "" {
		if parsed, err := strconv.ParseInt(value, 10, 64); err == nil && parsed >= 0 {
			contentLength = parsed
		}
	}
	if contentLength < 0 {
		return
	}
	req.ContentLength = contentLength
	if contentLength == 0 {
		req.Body = http.NoBody
	}
}

type trafficCountingReader struct {
	reader io.Reader
	onRead func(int)
}

func newTrafficCountingReader(reader io.Reader, onRead func(int)) io.Reader {
	if reader == nil || onRead == nil {
		return reader
	}
	return &trafficCountingReader{reader: reader, onRead: onRead}
}

func (r *trafficCountingReader) Read(p []byte) (int, error) {
	if r == nil || r.reader == nil {
		return 0, io.EOF
	}
	n, err := r.reader.Read(p)
	if n > 0 && r.onRead != nil {
		r.onRead(n)
	}
	return n, err
}

// logForwardResult logs the forwarded request result via display or logger.
func (c *Client) logForwardResult(req *tunnelproto.HTTPRequest, status int, started time.Time) {
	method := config.SanitizeTerminalString(req.Method)
	path := config.SanitizeTerminalString(req.Path)
	query := strings.TrimSpace(req.Query)
	if query != "" {
		path = path + "?" + config.SanitizeTerminalString(query)
	}
	elapsed := time.Since(started)
	if c.display != nil {
		c.display.LogRequest(method, path, status, elapsed, req.Headers)
	} else if c.log != nil {
		logPath := config.SanitizeTerminalString(req.Path)
		if query != "" {
			logPath = logPath + "?" + config.RedactQueryValues(query)
		}
		fp := visitorFingerprint(req.Headers)
		if fp != "" {
			c.log.Info("forwarded request", "method", method, "path", logPath, "status", status, "duration", elapsed.String(), "client_fingerprint", fp)
		} else {
			c.log.Info("forwarded request", "method", method, "path", logPath, "status", status, "duration", elapsed.String())
		}
	}
}

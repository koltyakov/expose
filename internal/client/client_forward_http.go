package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/netutil"
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

func (c *Client) forwardLocal(ctx context.Context, base *url.URL, req *tunnelproto.HTTPRequest) *tunnelproto.HTTPResponse {
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + req.Path
	target.RawQuery = req.Query

	body, err := tunnelproto.DecodeBody(req.BodyB64)
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	headers := tunnelproto.CloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	localReq.Header = headers
	localReq.Header.Del("Host")
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
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream unavailable")),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	respHeaders := tunnelproto.CloneHeaders(resp.Header)
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
	defer bufferPool.Put(buf)
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, localForwardResponseMaxB64+1))
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("failed to read local upstream response")),
		}
	}
	if buf.Len() > localForwardResponseMaxB64 {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream response too large")),
		}
	}
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
	return &tunnelproto.HTTPResponse{
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: respHeaders,
		BodyB64: tunnelproto.EncodeBody(buf.Bytes()),
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
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + req.Path
	target.RawQuery = req.Query

	// Build request body reader.
	var body io.Reader
	var pipeReader *io.PipeReader
	if bodyCh != nil {
		pr, pw := io.Pipe()
		pipeReader = pr
		go func() {
			defer func() { _ = pw.Close() }()
			for {
				select {
				case chunk, ok := <-bodyCh:
					if !ok {
						return
					}
					if _, err := pw.Write(chunk); err != nil {
						return
					}
				case <-ctx.Done():
					pw.CloseWithError(ctx.Err())
					return
				}
			}
		}()
		body = pr
	} else {
		data, err := tunnelproto.DecodeBody(req.BodyB64)
		if err != nil {
			_ = writeMsg(tunnelproto.Message{
				Kind:     tunnelproto.KindResponse,
				Response: &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway},
			})
			c.logForwardResult(req, http.StatusBadGateway, started)
			return
		}
		body = bytes.NewReader(data)
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

	headers := tunnelproto.CloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	localReq.Header = headers
	localReq.Header.Del("Host")
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
				BodyB64: tunnelproto.EncodeBody([]byte("local upstream unavailable")),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	respHeaders := tunnelproto.CloneHeaders(resp.Header)
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

	// Try to read the first chunk to decide inline vs streamed response.
	firstBufRef := responseFirstChunkPool.Get().(*[]byte)
	firstBuf := *firstBufRef
	if cap(firstBuf) < streamingThreshold+1 {
		firstBuf = make([]byte, streamingThreshold+1)
	} else {
		firstBuf = firstBuf[:streamingThreshold+1]
	}
	*firstBufRef = firstBuf
	defer responseFirstChunkPool.Put(firstBufRef)
	n, readErr := io.ReadFull(resp.Body, firstBuf)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		// Small response - send inline.
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  resp.StatusCode,
				Headers: respHeaders,
				BodyB64: tunnelproto.EncodeBody(firstBuf[:n]),
			},
		})
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	if readErr != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  http.StatusBadGateway,
				Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
				BodyB64: tunnelproto.EncodeBody([]byte("failed to read local upstream response")),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}

	// Large response - stream it.
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

	// Send the already-read data as the first body chunk.
	if writeRespBodyChunk != nil {
		if err := writeRespBodyChunk(req.ID, firstBuf[:n]); err != nil {
			c.logForwardResult(req, resp.StatusCode, started)
			return
		}
	} else if err := writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindRespBody,
		BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, DataB64: tunnelproto.EncodeBody(firstBuf[:n])},
	}); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	// Read remaining body in chunks.
	chunkBufRef := responseStreamChunkPool.Get().(*[]byte)
	chunkBuf := *chunkBufRef
	if cap(chunkBuf) < streamingChunkSize {
		chunkBuf = make([]byte, streamingChunkSize)
	} else {
		chunkBuf = chunkBuf[:streamingChunkSize]
	}
	*chunkBufRef = chunkBuf
	defer responseStreamChunkPool.Put(chunkBufRef)
	for {
		cn, err := resp.Body.Read(chunkBuf)
		if cn > 0 {
			if writeRespBodyChunk != nil {
				if wErr := writeRespBodyChunk(req.ID, chunkBuf[:cn]); wErr != nil {
					c.logForwardResult(req, resp.StatusCode, started)
					return
				}
			} else if wErr := writeMsg(tunnelproto.Message{
				Kind:      tunnelproto.KindRespBody,
				BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, DataB64: tunnelproto.EncodeBody(chunkBuf[:cn])},
			}); wErr != nil {
				c.logForwardResult(req, resp.StatusCode, started)
				return
			}
		}
		if err != nil {
			break
		}
	}

	// Signal end of response body.
	_ = writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindRespBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: req.ID},
	})
	c.logForwardResult(req, resp.StatusCode, started)
}

// logForwardResult logs the forwarded request result via display or logger.
func (c *Client) logForwardResult(req *tunnelproto.HTTPRequest, status int, started time.Time) {
	path := req.Path
	if strings.TrimSpace(req.Query) != "" {
		path = path + "?" + req.Query
	}
	elapsed := time.Since(started)
	if c.display != nil {
		c.display.LogRequest(req.Method, path, status, elapsed, req.Headers)
	} else if c.log != nil {
		fp := visitorFingerprint(req.Headers)
		if fp != "" {
			c.log.Info("forwarded request", "method", req.Method, "path", path, "status", status, "duration", elapsed.String(), "client_fingerprint", fp)
		} else {
			c.log.Info("forwarded request", "method", req.Method, "path", path, "status", status, "duration", elapsed.String())
		}
	}
}

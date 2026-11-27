package server

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

// A streamed request body is copied to the tunnel by a background goroutine,
// so the handler can relay the origin's response while the visitor is still
// sending. That covers an early final response (413, 401, a redirect) and a
// full-duplex 200 that streams while it reads. Response headers never cut the
// upload short. Only after the final response has been relayed in full does
// the handler stop forwarding, allow a bounded drain, and interrupt the read.
// The goroutine is always joined before the handler returns, so neither the
// request body nor a tunnel stream is used after the handler ends.

const (
	// uploadDrainTimeout bounds how long an HTTP/1 visitor may keep sending
	// after the response is complete. While draining, net/http discards up
	// to its own post-handler limit so the connection can serve another
	// request. HTTP/2 and HTTP/3 end the stream cleanly with no drain.
	uploadDrainTimeout = 500 * time.Millisecond
	// uploadInterruptRetry re-applies the read interrupt. Each body Read can
	// install its own idle deadline and overwrite the previous one.
	uploadInterruptRetry = 20 * time.Millisecond
)

var errUploadStopped = errors.New("request upload stopped after the response completed")

// uploadTunnelError marks an upload that failed writing to the tunnel rather
// than reading from the visitor.
type uploadTunnelError struct{ err error }

func (e *uploadTunnelError) Error() string { return e.err.Error() }
func (e *uploadTunnelError) Unwrap() error { return e.err }

func isUploadTunnelError(err error) bool {
	var tunnelErr *uploadTunnelError
	return errors.As(err, &tunnelErr)
}

type requestUpload struct {
	r       *http.Request
	rc      *http.ResponseController
	stopped atomic.Bool
	done    chan struct{}

	// interruptTunnel, when set, unblocks a pending tunnel write. It must be
	// safe to call concurrently with that write.
	interruptTunnel func()

	mu  sync.Mutex
	err error
}

// startRequestUpload streams the rest of r.Body after the streamed request
// envelope has been sent. onEnd runs on the upload goroutine once copying
// stops: err is nil after a complete upload, errUploadStopped after stop, or
// the failure. The failure is readable through failure before onEnd runs.
func (s *Server) startRequestUpload(
	w http.ResponseWriter,
	r *http.Request,
	reqID string,
	writeMsg func(tunnelproto.Message) error,
	writeChunk func([]byte) error,
	interruptTunnel func(),
	onEnd func(error),
) *requestUpload {
	rc := http.NewResponseController(w)
	// HTTP/1 net/http otherwise consumes the unread request body before the
	// first response write, which would race the upload goroutine.
	_ = rc.EnableFullDuplex()
	u := &requestUpload{r: r, rc: rc, done: make(chan struct{}), interruptTunnel: interruptTunnel}
	go func() {
		defer close(u.done)
		err := streamRequestBody(reqID, r, writeMsg, writeChunk, u.stopped.Load)
		u.mu.Lock()
		u.err = err
		u.mu.Unlock()
		if onEnd != nil {
			onEnd(err)
		}
	}()
	return u
}

// failure reports why the upload failed before it was stopped. It returns nil
// while the upload runs, after it completes, or after stop.
func (u *requestUpload) failure() error {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if errors.Is(u.err, errUploadStopped) {
		return nil
	}
	return u.err
}

// completed reports whether the entire body and its end marker were sent.
func (u *requestUpload) completed() bool {
	if u == nil {
		return true
	}
	select {
	case <-u.done:
	default:
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err == nil
}

func (u *requestUpload) doneCh() <-chan struct{} {
	if u == nil {
		return nil
	}
	return u.done
}

// finish stops forwarding and joins the upload goroutine. Call it only once
// the final response is complete (or abandoned); a finished upload returns at
// once. drain lets an HTTP/1 visitor finish sending within the bound.
func (u *requestUpload) finish(drain bool) {
	if u == nil {
		return
	}
	select {
	case <-u.done:
		return
	default:
	}
	u.stopped.Store(true)
	if drain {
		timer := time.NewTimer(uploadDrainTimeout)
		select {
		case <-u.done:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	if u.interruptTunnel != nil {
		u.interruptTunnel()
	}
	ticker := time.NewTicker(uploadInterruptRetry)
	defer ticker.Stop()
	for {
		if err := u.rc.SetReadDeadline(time.Now()); err != nil {
			// Writers without deadline support (tests, wrappers) fall back to
			// closing the body, which unblocks HTTP/2, HTTP/3 and pipe readers.
			_ = u.r.Body.Close()
		}
		select {
		case <-u.done:
			return
		case <-ticker.C:
		}
	}
}

// drainUploadOnFinish reports whether finish should let the visitor finish
// sending. Only HTTP/1 benefits: draining keeps the connection reusable, and
// multiplexed protocols end the stream cleanly without it. The drain runs only
// once the visitor can already tell the response is complete. A chunked
// HTTP/1 body ends when the handler returns, so it must not wait on a drain;
// net/http still half-closes and lingers before closing that connection.
func drainUploadOnFinish(w http.ResponseWriter, r *http.Request, status int) bool {
	if r == nil || r.ProtoMajor != 1 {
		return false
	}
	if r.Method == http.MethodHead || status == http.StatusNoContent || status == http.StatusNotModified {
		return true
	}
	return w.Header().Get("Content-Length") != ""
}

// writeUploadFailure answers a request whose upload failed before any
// response header was written.
func (s *Server) writeUploadFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case isBodyTooLargeError(err):
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, tunneltransport.ErrWritePumpBackpressure):
		s.writePublicRejection(w, r, http.StatusServiceUnavailable, "tunnel overloaded", rejectionBackpressure)
	default:
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
	}
}

// setInlineContentLength declares the length of an inline response while the
// upload still runs. The handler returns only after the upload is stopped, so
// without it an HTTP/1 visitor would wait out the drain for the body's end.
func setInlineContentLength(w http.ResponseWriter, r *http.Request, resp *tunnelproto.HTTPResponse, upload *requestUpload) {
	if upload == nil || resp == nil || resp.Streamed || r.Method == http.MethodHead {
		return
	}
	select {
	case <-upload.done:
		return
	default:
	}
	status := normalizeUpstreamStatus(resp.Status)
	if status == http.StatusNoContent || status == http.StatusNotModified {
		return
	}
	header := w.Header()
	if header.Get("Content-Length") != "" || header.Get("Transfer-Encoding") != "" {
		return
	}
	body, err := resp.Payload()
	if err != nil {
		return
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
}

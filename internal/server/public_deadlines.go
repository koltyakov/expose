package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/serviceapi"
)

// Public traffic uses per-I/O deadlines. http.Server's absolute write timeout
// otherwise cuts off active SSE responses and long downloads. Service paths
// keep their ordinary deadlines and the HTTP/3 stream-takeover interfaces.
func publicDeadlineMiddleware(next http.Handler, readTimeout, writeTimeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serviceapi.IsServicePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		controller := http.NewResponseController(w)
		_ = controller.SetWriteDeadline(time.Time{})
		// net/http flushes small buffered responses after the handler returns.
		defer func() { _ = controller.SetWriteDeadline(time.Now().Add(writeTimeout)) }()
		if hasRequestBody(r) && readTimeout > 0 {
			r.Body = &publicDeadlineBody{ReadCloser: r.Body, controller: controller, timeout: readTimeout}
		}
		writer := &publicDeadlineWriter{ResponseWriter: w, controller: controller, timeout: writeTimeout, multiplexed: r.ProtoMajor >= 2}
		if r.ProtoMajor == 1 && hasRequestBody(r) {
			writer.drainTimeout = readTimeout
		}
		next.ServeHTTP(writer, r)
	})
}

// Incoming requests use zero for a known-empty body and -1 for an unknown
// length. HTTP/2 still supplies a non-nil requestBody for an empty stream.
func hasRequestBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && (r.ContentLength != 0 || len(r.TransferEncoding) != 0)
}

type publicDeadlineBody struct {
	io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
}

func (b *publicDeadlineBody) Read(p []byte) (int, error) {
	_ = b.controller.SetReadDeadline(time.Now().Add(b.timeout))
	defer func() { _ = b.controller.SetReadDeadline(time.Time{}) }()
	return b.ReadCloser.Read(p)
}

func (b *publicDeadlineBody) Close() error {
	// HTTP/1.1 may drain unread bytes in Close without calling our Read method.
	_ = b.controller.SetReadDeadline(time.Now().Add(b.timeout))
	defer func() { _ = b.controller.SetReadDeadline(time.Time{}) }()
	return b.ReadCloser.Close()
}

type publicDeadlineWriter struct {
	http.ResponseWriter
	controller   *http.ResponseController
	timeout      time.Duration
	drainTimeout time.Duration
	multiplexed  bool
	writeMu      sync.Mutex
	writeTimer   *time.Timer
	writeUntil   time.Time
	writing      bool
}

func (w *publicDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *publicDeadlineWriter) beginWrite() {
	if w.multiplexed && w.timeout > 0 {
		// HTTP/2 deadline updates synchronously cross into its connection loop.
		// Fast writes need only arm this reusable watchdog; touch the stream's
		// deadline when an actual write stalls.
		w.writeMu.Lock()
		w.writing = true
		w.writeUntil = time.Now().Add(w.timeout)
		if w.writeTimer == nil {
			w.writeTimer = time.AfterFunc(w.timeout, w.expireWrite)
		} else {
			w.writeTimer.Reset(w.timeout)
		}
		w.writeMu.Unlock()
		return
	}
	_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	// net/http can read the original HTTP/1.1 body before writing headers.
	// That implicit drain bypasses publicDeadlineBody.Read entirely.
	if w.drainTimeout > 0 {
		_ = w.controller.SetReadDeadline(time.Now().Add(w.drainTimeout))
	}
}

func (w *publicDeadlineWriter) endWrite() {
	if w.multiplexed && w.timeout > 0 {
		w.writeMu.Lock()
		w.writing = false
		w.writeTimer.Stop()
		w.writeMu.Unlock()
		return
	}
	_ = w.controller.SetWriteDeadline(time.Time{})
	if w.drainTimeout > 0 {
		_ = w.controller.SetReadDeadline(time.Time{})
	}
}

func (w *publicDeadlineWriter) expireWrite() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if !w.writing {
		return
	}
	if remaining := time.Until(w.writeUntil); remaining > 0 {
		w.writeTimer.Reset(remaining)
		return
	}
	// endWrite waits for this call before allowing ServeHTTP to return. A
	// stopped callback therefore cannot access a recycled response writer.
	_ = w.controller.SetWriteDeadline(time.Now())
}

func (w *publicDeadlineWriter) WriteHeader(status int) {
	w.beginWrite()
	defer w.endWrite()
	w.ResponseWriter.WriteHeader(status)
}

func (w *publicDeadlineWriter) Write(p []byte) (int, error) {
	w.beginWrite()
	defer w.endWrite()
	return w.ResponseWriter.Write(p)
}

func (w *publicDeadlineWriter) FlushError() error {
	w.beginWrite()
	defer w.endWrite()
	return w.controller.Flush()
}

func (w *publicDeadlineWriter) Flush() { _ = w.FlushError() }

func (w *publicDeadlineWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.controller.Hijack()
}

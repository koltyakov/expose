package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
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
		if r.Body != nil && r.Body != http.NoBody && readTimeout > 0 {
			r.Body = &publicDeadlineBody{ReadCloser: r.Body, controller: controller, timeout: readTimeout}
		}
		writer := &publicDeadlineWriter{ResponseWriter: w, controller: controller, timeout: writeTimeout}
		if r.ProtoMajor == 1 && r.Body != nil && r.Body != http.NoBody {
			writer.drainTimeout = readTimeout
		}
		next.ServeHTTP(writer, r)
	})
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
}

func (w *publicDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *publicDeadlineWriter) beginWrite() {
	_ = w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	// net/http can read the original HTTP/1.1 body before writing headers.
	// That implicit drain bypasses publicDeadlineBody.Read entirely.
	if w.drainTimeout > 0 {
		_ = w.controller.SetReadDeadline(time.Now().Add(w.drainTimeout))
	}
}

func (w *publicDeadlineWriter) endWrite() {
	_ = w.controller.SetWriteDeadline(time.Time{})
	if w.drainTimeout > 0 {
		_ = w.controller.SetReadDeadline(time.Time{})
	}
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

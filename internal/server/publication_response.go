package server

import "net/http"

// publicationResponseWriter releases the directory-lifetime lock once a
// handler has assembled its response, before any potentially blocking write.
// The caller also defers release for paths that return without a response.
type publicationResponseWriter struct {
	http.ResponseWriter
	release func()
}

func (w *publicationResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *publicationResponseWriter) WriteHeader(status int) {
	w.release()
	w.ResponseWriter.WriteHeader(status)
}

func (w *publicationResponseWriter) Write(p []byte) (int, error) {
	w.release()
	return w.ResponseWriter.Write(p)
}

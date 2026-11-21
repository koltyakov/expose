package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type readerFromRecorder struct {
	*httptest.ResponseRecorder
	readFromCalls int
}

func (r *readerFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.readFromCalls++
	return io.Copy(struct{ io.Writer }{r.ResponseRecorder}, src)
}

func TestSiteStatsWriterReadFromKeepsFastPathAndCounts(t *testing.T) {
	t.Parallel()

	fast := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	w := &siteStatsWriter{ResponseWriter: fast}
	if n, err := w.ReadFrom(strings.NewReader("hello world")); err != nil || n != 11 {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}
	if fast.readFromCalls != 1 {
		t.Fatalf("underlying ReadFrom calls = %d, want 1", fast.readFromCalls)
	}
	if w.status != http.StatusOK || w.bytes != 11 || fast.Body.String() != "hello world" {
		t.Fatalf("status=%d bytes=%d body=%q", w.status, w.bytes, fast.Body.String())
	}

	plain := httptest.NewRecorder()
	w = &siteStatsWriter{ResponseWriter: plain}
	w.WriteHeader(http.StatusPartialContent)
	if n, err := w.ReadFrom(strings.NewReader("abc")); err != nil || n != 3 {
		t.Fatalf("fallback ReadFrom = %d, %v", n, err)
	}
	if w.status != http.StatusPartialContent || w.bytes != 3 || plain.Body.String() != "abc" {
		t.Fatalf("fallback status=%d bytes=%d body=%q", w.status, w.bytes, plain.Body.String())
	}
}

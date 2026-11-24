package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

type bufferedFrameStream struct{ *bytes.Reader }

func (bufferedFrameStream) SetReadDeadline(time.Time) error { return nil }

type countingFlushRecorder struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *countingFlushRecorder) Flush() { w.flushes++ }

func encodeH3BodyFrames(t *testing.T, chunks []string, trailing []byte) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	for _, chunk := range chunks {
		if err := tunnelproto.WriteStreamBinaryFrame(&buf, tunnelproto.BinaryFrameRespBody, "req", 0, []byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tunnelproto.WriteStreamJSON(&buf, tunnelproto.Message{Kind: tunnelproto.KindRespBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: "req"}}); err != nil {
		t.Fatal(err)
	}
	buf.Write(trailing)
	return bytes.NewReader(buf.Bytes())
}

func TestH3StreamedBodyBatchesQueuedChunks(t *testing.T) {
	chunks := []string{"a", "b", "c", "d", "e"}
	w := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, reusable := writeH3StreamedResponseBody(w, r, bufferedFrameStream{encodeH3BodyFrames(t, chunks, nil)}, time.Second, false)
	if !ok || !reusable {
		t.Fatalf("ok=%v reusable=%v", ok, reusable)
	}
	if got := w.Body.String(); got != strings.Join(chunks, "") {
		t.Fatalf("body = %q", got)
	}
	// Every frame was already received, so the chunks leave in one flush
	// instead of one per chunk.
	if w.flushes != 1 {
		t.Fatalf("flushes = %d, want 1 for %d queued chunks", w.flushes, len(chunks))
	}
}

func TestH3StreamedBodyNotReusableWithTrailingBytes(t *testing.T) {
	w := &countingFlushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ok, reusable := writeH3StreamedResponseBody(w, r, bufferedFrameStream{encodeH3BodyFrames(t, []string{"a"}, []byte("junk"))}, time.Second, false)
	if !ok || reusable {
		t.Fatalf("ok=%v reusable=%v; a stream with unread bytes must not be reused", ok, reusable)
	}
}

func TestRequestH3WorkersDoesNotWaitForTunnelWriter(t *testing.T) {
	stream := &blockingWriteStream{started: make(chan struct{}), release: make(chan struct{})}
	writer := tunneltransport.NewStreamWritePump(stream, time.Second, 1, 1, func() { _ = stream.Close() })
	defer writer.Close()
	defer func() { _ = stream.Close() }()
	go func() { _ = writer.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}) }()
	<-stream.started // the writer is now stuck on the tunnel
	sess := &session{writer: writer}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 3 {
			sess.requestH3Workers(1)
		}
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("requesting workers blocked the public request path")
	}
}

type blockingWriteStream struct {
	started, release chan struct{}
	startOnce        sync.Once
	closeOnce        sync.Once
}

func (s *blockingWriteStream) Read([]byte) (int, error) { <-s.release; return 0, io.EOF }
func (s *blockingWriteStream) Write(p []byte) (int, error) {
	s.startOnce.Do(func() { close(s.started) })
	<-s.release
	return len(p), nil
}
func (s *blockingWriteStream) Close() error {
	s.closeOnce.Do(func() { close(s.release) })
	return nil
}

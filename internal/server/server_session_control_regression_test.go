package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type blockedRegressionSessionWriter struct {
	release chan struct{}
	async   chan tunnelproto.Message
}

func (w *blockedRegressionSessionWriter) WriteJSON(tunnelproto.Message) error {
	<-w.release
	return nil
}
func (w *blockedRegressionSessionWriter) WriteJSONAsync(msg tunnelproto.Message) error {
	w.async <- msg
	return nil
}
func (*blockedRegressionSessionWriter) WriteBinaryFrame(byte, string, int, []byte) error { return nil }
func (*blockedRegressionSessionWriter) Close()                                           {}

type regressionMessageTransport struct {
	msgs   chan tunnelproto.Message
	closed chan struct{}
	once   sync.Once
}

func (s *regressionMessageTransport) ReadMessage(dst *tunnelproto.Message) error {
	select {
	case *dst = <-s.msgs:
		return nil
	case <-s.closed:
		return io.EOF
	}
}
func (*regressionMessageTransport) SetReadLimit(int64) {}
func (s *regressionMessageTransport) Close() error     { s.once.Do(func() { close(s.closed) }); return nil }

func TestSessionOverflowCloseDoesNotBlockResponseDispatch(t *testing.T) {
	writer := &blockedRegressionSessionWriter{release: make(chan struct{}), async: make(chan tunnelproto.Message, 2)}
	transport := &regressionMessageTransport{msgs: make(chan tunnelproto.Message, 2), closed: make(chan struct{})}
	pending := newPendingRequest()
	ws := newWSStream(1)
	ws.ch <- tunnelproto.Message{Kind: tunnelproto.KindWSData}
	sess := &session{tunnelID: "control-regression", writer: writer, transport: transport, pending: map[string]*pendingRequest{"http": pending}, wsPending: map[string]*wsStream{"stalled": ws}}
	sess.pendingCount.Store(1)
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.hub.sessions[sess.tunnelID] = sess
	done := make(chan struct{})
	go func() { defer close(done); srv.readLoop(sess) }()
	defer func() {
		close(writer.release)
		_ = transport.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}()
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindWSData, WSData: &tunnelproto.WSData{ID: "stalled", Data: []byte("overflow")}}
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: "http", Status: 200}}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, ok := pending.waitHeader(ctx); !ok {
		t.Fatal("HTTP response dispatch blocked behind overflow close")
	}
	select {
	case msg := <-writer.async:
		if msg.Kind != tunnelproto.KindWSClose {
			t.Fatalf("unexpected async control %q", msg.Kind)
		}
	default:
		t.Fatal("overflow close was not queued asynchronously")
	}
}

func TestResponseBudgetOverflowDoesNotBlockOtherRequests(t *testing.T) {
	writer := &blockedRegressionSessionWriter{release: make(chan struct{}), async: make(chan tunnelproto.Message, 2)}
	transport := &regressionMessageTransport{msgs: make(chan tunnelproto.Message, 2), closed: make(chan struct{})}
	global := &byteBudget{limit: 128}
	slow, fast := newPendingRequest(), newPendingRequest()
	slow.globalBudget = global
	sess := &session{tunnelID: "budget-regression", writer: writer, transport: transport, pending: map[string]*pendingRequest{"slow": slow, "fast": fast}, wsPending: make(map[string]*wsStream)}
	sess.pendingCount.Store(2)
	if err := slow.sendBody(make([]byte, 128)); err != nil {
		t.Fatal("initial chunk should fit the budget")
	}
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.hub.sessions[sess.tunnelID] = sess
	done := make(chan struct{})
	go func() { defer close(done); srv.readLoop(sess) }()
	defer func() { close(writer.release); _ = transport.Close(); <-done }()
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: "slow", Data: []byte("overflow")}}
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: "fast", Status: 200}}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, ok := fast.waitHeader(ctx); !ok {
		t.Fatal("budget overflow blocked an unrelated response")
	}
	if !slow.wasAborted() || global.used.Load() != 0 || srv.responseQueueRejects.Load() != 1 {
		t.Fatal("overflow did not abort and release the stalled response")
	}
	select {
	case msg := <-writer.async:
		if msg.Kind != tunnelproto.KindReqCancel {
			t.Fatalf("unexpected control message: %s", msg.Kind)
		}
	default:
		t.Fatal("overflow did not asynchronously cancel the upstream request")
	}
}

func TestClosedResponseDoesNotCountAsQueueRejection(t *testing.T) {
	writer := &blockedRegressionSessionWriter{release: make(chan struct{}), async: make(chan tunnelproto.Message, 1)}
	transport := &regressionMessageTransport{msgs: make(chan tunnelproto.Message, 2), closed: make(chan struct{})}
	closed, fast := newPendingRequest(), newPendingRequest()
	closed.finish()
	sess := &session{
		tunnelID: "closed-response", writer: writer, transport: transport,
		pending:   map[string]*pendingRequest{"closed": closed, "fast": fast},
		wsPending: make(map[string]*wsStream),
	}
	sess.pendingCount.Store(2)
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	srv.hub.sessions[sess.tunnelID] = sess
	done := make(chan struct{})
	go func() { defer close(done); srv.readLoop(sess) }()
	defer func() { close(writer.release); _ = transport.Close(); <-done }()
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: "closed", Data: []byte("late")}}
	transport.msgs <- tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: "fast", Status: http.StatusOK}}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, ok := fast.waitHeader(ctx); !ok {
		t.Fatal("late frame blocked an unrelated response")
	}
	if srv.responseQueueRejects.Load() != 0 || closed.wasAborted() {
		t.Fatal("late frame was treated as queue overflow")
	}
	select {
	case msg := <-writer.async:
		t.Fatalf("late frame triggered cancellation: %s", msg.Kind)
	default:
	}
}

// Delay all public consumers until the shared reader has dispatched more than
// sixteen chunks per response. The unrelated response must still get through.
func TestConcurrentStreamBurstsCompleteWithoutQueueRejections(t *testing.T) {
	const streams, chunks = 16, 64
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	writer := &blockedRegressionSessionWriter{
		release: make(chan struct{}), async: make(chan tunnelproto.Message, streams),
	}
	transport := &regressionMessageTransport{msgs: make(chan tunnelproto.Message), closed: make(chan struct{})}
	srv := New(config.ServerConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	sess := &session{
		tunnelID: "stream-bursts", writer: writer, transport: transport,
		pending: make(map[string]*pendingRequest), wsPending: make(map[string]*wsStream),
		queuedResponses: byteBudget{limit: config.DefaultMaxQueuedResponseBytesPerTunnel},
	}
	srv.hub.sessions[sess.tunnelID] = sess
	ready := make(chan struct{}, streams)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	type result struct {
		id       string
		complete bool
		body     string
	}
	results := make(chan result, streams)
	want := make(map[string]string)
	var readers sync.WaitGroup
	for i := range streams {
		id := fmt.Sprintf("stream-%02d", i)
		pending := newPendingRequest()
		pending.sessionBudget, pending.globalBudget = &sess.queuedResponses, &srv.queuedResponses
		sess.pendingStore(id, pending)
		var body strings.Builder
		for chunk := range chunks {
			fmt.Fprintf(&body, "%s chunk=%02d\n", id, chunk)
		}
		want[id] = body.String()
		readers.Go(func() {
			if _, ok := pending.waitHeader(ctx); !ok {
				results <- result{id: id}
				return
			}
			ready <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
			complete := srv.writeStreamedResponseBody(w, req, pending, time.Second)
			pending.discardBody()
			results <- result{id: id, complete: complete, body: w.Body.String()}
		})
	}
	fast := newPendingRequest()
	sess.pendingStore("fast", fast)
	sess.pendingCount.Store(streams + 1)
	done := make(chan struct{})
	go func() { defer close(done); srv.readLoop(sess) }()
	t.Cleanup(func() {
		unblock()
		cancel()
		close(writer.release)
		_ = transport.Close()
		<-done
		readers.Wait()
	})
	dispatch := func(msg tunnelproto.Message) {
		t.Helper()
		select {
		case transport.msgs <- msg:
		case <-ctx.Done():
			t.Fatal("shared reader blocked while dispatching concurrent responses")
		}
	}
	for i := range streams {
		dispatch(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{
			ID: fmt.Sprintf("stream-%02d", i), Status: http.StatusOK, Streamed: true,
		}})
	}
	for range streams {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("streamed headers were not dispatched")
		}
	}
	for chunk := range chunks {
		for i := range streams {
			id := fmt.Sprintf("stream-%02d", i)
			data := fmt.Appendf(make([]byte, 0, 4096), "%s chunk=%02d\n", id, chunk)
			dispatch(tunnelproto.Message{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: id, Data: data}})
		}
	}
	for i := range streams {
		dispatch(tunnelproto.Message{Kind: tunnelproto.KindRespBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: fmt.Sprintf("stream-%02d", i)}})
	}
	dispatch(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: "fast", Status: http.StatusOK}})
	if _, ok := fast.waitHeader(ctx); !ok {
		t.Fatal("unrelated response blocked behind delayed stream consumers")
	}
	if rejects := srv.responseQueueRejects.Load(); rejects != 0 {
		t.Errorf("response queue rejected %d in-budget chunks", rejects)
	}
	unblock()
	for range streams {
		select {
		case got := <-results:
			if !got.complete || got.body != want[got.id] {
				t.Errorf("%s: complete=%v bytes=%d, want %d ordered bytes", got.id, got.complete, len(got.body), len(want[got.id]))
			}
		case <-ctx.Done():
			t.Fatal("responses did not complete after consumers resumed")
		}
	}
	if sess.queuedResponses.used.Load() != 0 || srv.queuedResponses.used.Load() != 0 {
		t.Fatal("completed responses retained queue budget reservations")
	}
	select {
	case msg := <-writer.async:
		t.Fatalf("unexpected cancellation of an in-budget response: %s", msg.Kind)
	default:
	}
}

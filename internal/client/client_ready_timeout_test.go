package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestRunReadyTimeoutStopsRetryingBeforeFirstTunnel(t *testing.T) {
	t.Parallel()
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := New(config.ClientConfig{
		ServerURL:    srv.URL,
		APIKey:       "test-key",
		LocalPort:    1,
		ReadyTimeout: 300 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	started := time.Now()
	err := c.Run(ctx)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "not ready within 300ms") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed < 250*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("Run returned after %s, want about the 300ms deadline", elapsed)
	}
	if attempts < 1 {
		t.Fatalf("register attempts = %d, want at least one", attempts)
	}
}

func TestRunReadyTimeoutBoundsHungRegister(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	c := New(config.ClientConfig{
		ServerURL:    srv.URL,
		APIKey:       "test-key",
		LocalPort:    1,
		ReadyTimeout: 300 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	started := time.Now()
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready within") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("hung register held Run for %s past a 300ms ready timeout", elapsed)
	}
}

// readyTestWSServer serves register and a websocket connect endpoint. The
// connect handler runs beforeUpgrade first, then upgrades and reads until the
// connection ends, reporting the read error on closed.
type readyTestWSServer struct {
	srv      *httptest.Server
	upgrades atomic.Int32
	closed   chan error
}

func newReadyTestWSServer(t *testing.T, beforeUpgrade func(*http.Request) bool) *readyTestWSServer {
	t.Helper()
	s := &readyTestWSServer{closed: make(chan error, 4)}
	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/_expose/v1/tunnels/register", func(w http.ResponseWriter, _ *http.Request) {
		wsURL := "ws" + strings.TrimPrefix(s.srv.URL, "http") + "/_expose/v1/tunnels/connect?token=tok"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.RegisterResponse{
			TunnelID:  "tun_ready",
			PublicURL: "https://ready.example.com",
			WSURL:     wsURL,
		})
	})
	mux.HandleFunc("/_expose/v1/tunnels/connect", func(w http.ResponseWriter, r *http.Request) {
		if beforeUpgrade != nil && !beforeUpgrade(r) {
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		s.upgrades.Add(1)
		defer func() { _ = conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				s.closed <- err
				return
			}
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func newReadyTestClient(serverURL, transport string, readyTimeout time.Duration) *Client {
	return New(config.ClientConfig{
		ServerURL:    serverURL,
		APIKey:       "test-key",
		LocalPort:    1,
		Transport:    transport,
		ReadyTimeout: readyTimeout,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestRunReadyTimeoutBoundsLateWebSocketHandshake covers a handshake that
// succeeds after the deadline: readiness must not be announced late.
func TestRunReadyTimeoutBoundsLateWebSocketHandshake(t *testing.T) {
	t.Parallel()
	srv := newReadyTestWSServer(t, func(r *http.Request) bool {
		select {
		case <-time.After(300 * time.Millisecond):
			return true
		case <-r.Context().Done():
			return false
		}
	})
	c := newReadyTestClient(srv.srv.URL, "ws", 100*time.Millisecond)
	var readyEvents atomic.Int32
	c.SetLifecycleHooks(LifecycleHooks{OnTunnelReady: func(TunnelReadyEvent) { readyEvents.Add(1) }})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	err := c.Run(ctx)
	elapsed := time.Since(started)
	if err == nil || !strings.Contains(err.Error(), "not ready within 100ms") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed > 280*time.Millisecond {
		t.Fatalf("Run returned after %s, want it bounded by the 100ms deadline, not the 300ms handshake", elapsed)
	}
	if n := readyEvents.Load(); n != 0 {
		t.Fatalf("tunnel ready announced %d times after the deadline", n)
	}
}

// TestRunReadyTimeoutBoundsHungWebSocketHandshake covers an upgrade response
// that never arrives; the 10s handshake timeout must not apply instead.
func TestRunReadyTimeoutBoundsHungWebSocketHandshake(t *testing.T) {
	t.Parallel()
	srv := newReadyTestWSServer(t, func(r *http.Request) bool {
		<-r.Context().Done()
		return false
	})
	c := newReadyTestClient(srv.srv.URL, "ws", 150*time.Millisecond)
	started := time.Now()
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready within") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("hung websocket handshake held Run for %s", elapsed)
	}
}

// TestRunCancelInterruptsWebSocketHandshake covers cancellation without a
// ready deadline: the dialer honours only ctx deadlines on its own.
func TestRunCancelInterruptsWebSocketHandshake(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{}, 1)
	srv := newReadyTestWSServer(t, func(r *http.Request) bool {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
		return false
	})
	c := newReadyTestClient(srv.srv.URL, "ws", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("websocket handshake never reached the server")
	}
	cancelled := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run error = %v, want nil after cancellation", err)
		}
		if elapsed := time.Since(cancelled); elapsed > 2*time.Second {
			t.Fatalf("Run took %s to stop after cancellation", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt the websocket handshake")
	}
}

// TestRunReadyTimeoutDoesNotBoundEstablishedWebSocketSession checks a
// session that became ready in time keeps running past the deadline.
func TestRunReadyTimeoutDoesNotBoundEstablishedWebSocketSession(t *testing.T) {
	t.Parallel()
	srv := newReadyTestWSServer(t, nil)
	const readyTimeout = 300 * time.Millisecond
	c := newReadyTestClient(srv.srv.URL, "ws", readyTimeout)
	readyCh := make(chan TunnelReadyEvent, 4)
	dropCh := make(chan SessionDisconnectEvent, 4)
	c.SetLifecycleHooks(LifecycleHooks{
		OnTunnelReady: func(ev TunnelReadyEvent) { readyCh <- ev },
		OnSessionDrop: func(ev SessionDisconnectEvent) { dropCh <- ev },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx) }()

	waitTunnelReadyEvent(t, readyCh, 5*time.Second, "websocket tunnel ready")
	time.Sleep(time.Until(started.Add(readyTimeout + 300*time.Millisecond)))

	select {
	case ev := <-dropCh:
		t.Fatalf("session dropped after the ready deadline: %v", ev.Err)
	case err := <-srv.closed:
		t.Fatalf("server saw the session close after the ready deadline: %v", err)
	case err := <-errCh:
		t.Fatalf("Run returned after the ready deadline: %v", err)
	default:
	}
	if n := srv.upgrades.Load(); n != 1 {
		t.Fatalf("websocket upgrades = %d, want the one session", n)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run error = %v, want nil after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

// readyTestH3Server serves register over plain HTTP and the HTTP/3
// multistream control and worker endpoints. control decides whether a control
// connect is accepted; accepted control streams stay open until the test ends.
type readyTestH3Server struct {
	registerSrv *httptest.Server
	h3Addr      string
	registers   atomic.Int32
	controlEOF  chan error
}

func newReadyTestH3Server(
	t *testing.T,
	caps []string,
	register func(n int32, r *http.Request) bool,
	control func(r *http.Request, w http.ResponseWriter) bool,
) *readyTestH3Server {
	t.Helper()
	s := &readyTestH3Server{controlEOF: make(chan error, 4)}
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/_expose/v1/tunnels/connect-h3", func(w http.ResponseWriter, r *http.Request) {
		if control != nil && !control(r, w) {
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set(h3SessionHeader, "session-token")
		w.WriteHeader(http.StatusOK)
		stream, err := takeOverHTTP3Stream(w, streamer)
		if err != nil {
			return
		}
		go func() {
			_, err := io.Copy(io.Discard, stream)
			if err == nil {
				err = io.EOF
			}
			select {
			case <-done:
			default:
				s.controlEOF <- err
			}
		}()
		<-done
		closeHTTP3TestStream(stream)
	})
	mux.HandleFunc("/_expose/v1/tunnels/connect-h3/stream", func(w http.ResponseWriter, _ *http.Request) {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
		stream, err := takeOverHTTP3Stream(w, streamer)
		if err != nil {
			return
		}
		<-done
		closeHTTP3TestStream(stream)
	})
	addr, cleanupH3 := startHTTP3TestServer(t, mux)
	s.h3Addr = addr
	s.registerSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_expose/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		// Consume the body so the server notices a client that gives up and
		// cancels r.Context() for a hung handler.
		_, _ = io.Copy(io.Discard, r.Body)
		n := s.registers.Add(1)
		if register != nil && !register(n, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.RegisterResponse{
			TunnelID:     "tun_ready_h3",
			PublicURL:    "https://ready.example.com",
			WSURL:        "wss://unused.example.com/_expose/v1/tunnels/connect?token=unused",
			H3URL:        "https://" + addr + "/_expose/v1/tunnels/connect-h3?token=abc",
			Capabilities: caps,
		})
	}))
	t.Cleanup(func() {
		close(done)
		s.registerSrv.Close()
		cleanupH3()
	})
	return s
}

func newReadyTestQUICClient(s *readyTestH3Server, readyTimeout time.Duration) *Client {
	c := newReadyTestClient(s.registerSrv.URL, "quic", readyTimeout)
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	return c
}

// TestRunReadyTimeoutBoundsHungQUICControlHandshake covers an HTTP/3 server
// that accepts the connection but never answers the control request.
func TestRunReadyTimeoutBoundsHungQUICControlHandshake(t *testing.T) {
	t.Parallel()
	s := newReadyTestH3Server(t, []string{tunnelCapabilityH3MultistreamV2}, nil, func(r *http.Request, _ http.ResponseWriter) bool {
		<-r.Context().Done()
		return false
	})
	c := newReadyTestQUICClient(s, 300*time.Millisecond)
	var readyEvents atomic.Int32
	c.SetLifecycleHooks(LifecycleHooks{OnTunnelReady: func(TunnelReadyEvent) { readyEvents.Add(1) }})

	started := time.Now()
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready within") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("hung HTTP/3 control handshake held Run for %s", elapsed)
	}
	if n := readyEvents.Load(); n != 0 {
		t.Fatalf("tunnel ready announced %d times after the deadline", n)
	}
}

// TestRunReadyTimeoutBoundsQUICFallbackTokenRefresh covers the register call
// that refreshes the connect token before the HTTP/3 compat fallback.
func TestRunReadyTimeoutBoundsQUICFallbackTokenRefresh(t *testing.T) {
	t.Parallel()
	s := newReadyTestH3Server(t,
		[]string{tunnelCapabilityH3MultistreamV2, tunnelCapabilityH3CompatV1},
		func(n int32, r *http.Request) bool {
			if n == 1 {
				return true
			}
			<-r.Context().Done() // the refresh hangs
			return false
		},
		func(r *http.Request, w http.ResponseWriter) bool {
			if r.Header.Get("X-Expose-H3-Mode") != "" {
				http.Error(w, "multistream disabled", http.StatusForbidden)
				return false
			}
			return true
		},
	)
	c := newReadyTestQUICClient(s, time.Second)
	started := time.Now()
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not ready within") {
		t.Fatalf("Run error = %v, want ready timeout", err)
	}
	if !strings.Contains(err.Error(), "refresh HTTP/3 connect token") {
		t.Fatalf("Run error = %v, want it to come from the token refresh", err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("hung token refresh held Run for %s", elapsed)
	}
	if n := s.registers.Load(); n != 2 {
		t.Fatalf("register calls = %d, want the register and one refresh", n)
	}
}

// TestRunReadyTimeoutDoesNotBoundEstablishedQUICSession checks an HTTP/3
// multistream session that became ready in time outlives the deadline.
func TestRunReadyTimeoutDoesNotBoundEstablishedQUICSession(t *testing.T) {
	t.Parallel()
	s := newReadyTestH3Server(t, []string{tunnelCapabilityH3MultistreamV2}, nil, nil)
	const readyTimeout = 2 * time.Second
	c := newReadyTestQUICClient(s, readyTimeout)
	readyCh := make(chan TunnelReadyEvent, 4)
	dropCh := make(chan SessionDisconnectEvent, 4)
	c.SetLifecycleHooks(LifecycleHooks{
		OnTunnelReady: func(ev TunnelReadyEvent) { readyCh <- ev },
		OnSessionDrop: func(ev SessionDisconnectEvent) { dropCh <- ev },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := time.Now()
	errCh := make(chan error, 1)
	go func() { errCh <- c.Run(ctx) }()

	ev := waitTunnelReadyEvent(t, readyCh, 5*time.Second, "quic tunnel ready")
	if ev.Transport != "quic" {
		t.Fatalf("transport = %q, want quic", ev.Transport)
	}
	time.Sleep(time.Until(started.Add(readyTimeout + 300*time.Millisecond)))

	select {
	case ev := <-dropCh:
		t.Fatalf("session dropped after the ready deadline: %v", ev.Err)
	case err := <-s.controlEOF:
		t.Fatalf("server saw the control stream end after the ready deadline: %v", err)
	case err := <-errCh:
		t.Fatalf("Run returned after the ready deadline: %v", err)
	default:
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run error = %v, want nil after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestSendBeforeReadyAbortsBlockedSend(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	aborted := make(chan struct{})
	err := sendBeforeReady(ctx, func() { close(aborted) }, func() error {
		<-aborted
		return errors.New("transport closed")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sendBeforeReady error = %v, want deadline exceeded", err)
	}

	err = sendBeforeReady(context.Background(), func() { t.Error("abort ran without ctx ending") }, func() error { return nil })
	if err != nil {
		t.Fatalf("sendBeforeReady error = %v, want nil", err)
	}
}

// TestH3ControlCloseDuringBlockedWrite closes the control transport while its
// WritePump is blocked inside Write on a peer that never reads. Run with
// -race: a graceful stream Close here races the writer's frame state.
func TestH3ControlCloseDuringBlockedWrite(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/_expose/v1/tunnels/connect-h3", func(w http.ResponseWriter, _ *http.Request) {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set(h3SessionHeader, "session-token")
		w.WriteHeader(http.StatusOK)
		stream, err := takeOverHTTP3Stream(w, streamer)
		if err != nil {
			return
		}
		select { // never read, so flow control stalls the client's writes
		case <-done:
		case <-stream.Context().Done():
		}
		closeHTTP3TestStream(stream)
	})
	addr, cleanupH3 := startHTTP3TestServer(t, mux)
	t.Cleanup(func() {
		close(done)
		cleanupH3()
	})

	c := newReadyTestClient("http://127.0.0.1:1", "quic", 0)
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.connectHTTP3MultiStreamTransport(ctx, domain.RegisterResponse{
		TunnelID:     "tun_close",
		H3URL:        "https://" + addr + "/_expose/v1/tunnels/connect-h3",
		Capabilities: []string{tunnelCapabilityH3MultistreamV2},
	})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	var written atomic.Int64
	writeErr := make(chan error, 1)
	payload := make([]byte, 256*1024)
	go func() {
		for {
			if err := conn.writer.WriteBinaryFrame(tunnelproto.BinaryFrameReqBody, "r1", 0, payload); err != nil {
				writeErr <- err
				return
			}
			written.Add(int64(len(payload)))
		}
	}()
	// Wait until writes stop making progress: the pump is parked in Write.
	last := int64(-1)
	waitForCondition(t, 5*time.Second, "blocked control write", func() (struct{}, bool) {
		time.Sleep(100 * time.Millisecond)
		n := written.Load()
		stalled := n == last && n > 0
		last = n
		return struct{}{}, stalled
	})

	closeErr := make(chan error, 2)
	for range 2 { // concurrent and repeated closes share one abort
		go func() { closeErr <- conn.transport.Close() }()
	}
	var results []error
	for range 2 {
		select {
		case err := <-closeErr:
			results = append(results, err)
		case <-time.After(5 * time.Second):
			t.Fatal("control transport Close did not return")
		}
	}
	if !errors.Is(results[0], results[1]) && !errors.Is(results[1], results[0]) {
		t.Fatalf("repeated closes returned %v and %v, want the one abort result", results[0], results[1])
	}
	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("blocked write returned nil after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked control write was not aborted by close")
	}
	conn.writer.Close()
}

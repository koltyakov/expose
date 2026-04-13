package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/traffic"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type testTrafficRecorder struct {
	inbound  atomic.Int64
	outbound atomic.Int64
}

func (r *testTrafficRecorder) RecordTraffic(direction traffic.Direction, bytes int64) {
	switch direction {
	case traffic.DirectionInbound:
		r.inbound.Add(bytes)
	case traffic.DirectionOutbound:
		r.outbound.Add(bytes)
	}
}

func TestReconnectScheduleNextDelay(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	var schedule reconnectSchedule

	if got := schedule.nextDelay(start); got != reconnectInitialDelay {
		t.Fatalf("expected initial delay %s, got %s", reconnectInitialDelay, got)
	}

	if got := schedule.nextDelay(start.Add(29 * time.Second)); got != reconnectInitialDelay {
		t.Fatalf("expected first-stage delay %s, got %s", reconnectInitialDelay, got)
	}

	if got := schedule.nextDelay(start.Add(reconnectInitialWindow)); got != reconnectSecondStageDelay {
		t.Fatalf("expected second-stage delay %s, got %s", reconnectSecondStageDelay, got)
	}

	if got := schedule.nextDelay(start.Add(reconnectInitialWindow + reconnectSecondStageWindow - time.Second)); got != reconnectSecondStageDelay {
		t.Fatalf("expected second-stage delay before final window %s, got %s", reconnectSecondStageDelay, got)
	}

	if got := schedule.nextDelay(start.Add(reconnectInitialWindow + reconnectSecondStageWindow)); got != reconnectThirdStageDelay {
		t.Fatalf("expected third-stage delay %s, got %s", reconnectThirdStageDelay, got)
	}

	schedule.reset()
	if got := schedule.nextDelay(start.Add(10 * time.Minute)); got != reconnectInitialDelay {
		t.Fatalf("expected reset to restore initial delay %s, got %s", reconnectInitialDelay, got)
	}
}

func TestShouldResetReconnectSchedule(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.March, 8, 12, 0, 0, 0, time.UTC)
	if shouldResetReconnectSchedule(start, start.Add(reconnectInitialWindow-time.Millisecond)) {
		t.Fatal("expected short-lived session to keep reconnect backoff state")
	}
	if !shouldResetReconnectSchedule(start, start.Add(reconnectInitialWindow)) {
		t.Fatal("expected stable session to reset reconnect backoff state")
	}
}

func TestNewUsesClonedForwardTransportWithSafeDefaults(t *testing.T) {
	t.Parallel()

	c := New(config.ClientConfig{Timeout: 3 * time.Second}, slog.Default())
	tr, ok := c.fwdClient.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("expected *http.Transport, got %T", c.fwdClient.Transport)
	}
	if tr == http.DefaultTransport {
		t.Fatal("expected cloned transport, got shared default transport")
	}
	if tr.Proxy == nil {
		t.Fatal("expected ProxyFromEnvironment to be preserved")
	}
	if tr.DialContext == nil {
		t.Fatal("expected DialContext to be preserved")
	}
	if tr.TLSHandshakeTimeout <= 0 {
		t.Fatalf("expected TLSHandshakeTimeout > 0, got %s", tr.TLSHandshakeTimeout)
	}
	if tr.MaxIdleConns != 100 {
		t.Fatalf("expected MaxIdleConns=100, got %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 100 {
		t.Fatalf("expected MaxIdleConnsPerHost=100, got %d", tr.MaxIdleConnsPerHost)
	}
	if tr.MaxConnsPerHost != defaultMaxConcurrentForwards {
		t.Fatalf("expected MaxConnsPerHost=%d, got %d", defaultMaxConcurrentForwards, tr.MaxConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != 2*time.Minute {
		t.Fatalf("expected ResponseHeaderTimeout=2m, got %s", tr.ResponseHeaderTimeout)
	}
}

func TestForwardLocalStripsHopByHopHeaders(t *testing.T) {
	t.Parallel()

	headerCh := make(chan struct {
		connection string
		hop        string
	}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerCh <- struct {
			connection string
			hop        string
		}{
			connection: r.Header.Get("Connection"),
			hop:        r.Header.Get("X-Hop"),
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("Proxy-Connection", "keep-alive")
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{Timeout: 5 * time.Second},
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:     "req_1",
		Method: http.MethodGet,
		Path:   "/hello",
		Headers: map[string][]string{
			"Connection": {"keep-alive, X-Hop"},
			"X-Hop":      {"drop"},
			"X-Keep":     {"keep"},
		},
	})

	if resp.Status != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, resp.Status)
	}
	gotHeaders := <-headerCh
	if gotHeaders.connection != "" {
		t.Fatalf("expected Connection header stripped before local forward, got %q", gotHeaders.connection)
	}
	if gotHeaders.hop != "" {
		t.Fatalf("expected Connection-declared hop header stripped, got %q", gotHeaders.hop)
	}
	if resp.Headers["Connection"] != nil {
		t.Fatalf("expected Connection header removed from response")
	}
	if resp.Headers["Proxy-Connection"] != nil {
		t.Fatalf("expected Proxy-Connection header removed from response")
	}
	if got := firstHeaderValue(resp.Headers, "X-Upstream"); got != "ok" {
		t.Fatalf("expected X-Upstream header to be preserved, got %q", got)
	}
}

func TestForwardLocalRecordsTraffic(t *testing.T) {
	t.Parallel()

	bodyCh := make(chan []byte, 1)
	recorder := &testTrafficRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		bodyCh <- gotBody
		_, _ = io.WriteString(w, "response-data")
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient:   &http.Client{Timeout: 5 * time.Second},
		trafficSink: recorder,
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:      "req_traffic",
		Method:  http.MethodPost,
		Path:    "/upload",
		Body:    []byte("request-data"),
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
	})

	if got := string(<-bodyCh); got != "request-data" {
		t.Fatalf("expected upstream request body, got %q", got)
	}
	body, err := resp.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "response-data" {
		t.Fatalf("expected response body to round-trip, got %q", string(body))
	}
	if got := recorder.inbound.Load(); got != int64(len("request-data")) {
		t.Fatalf("expected inbound bytes %d, got %d", len("request-data"), got)
	}
	if got := recorder.outbound.Load(); got != int64(len("response-data")) {
		t.Fatalf("expected outbound bytes %d, got %d", len("response-data"), got)
	}
}

func TestForwardLocalPreservesWebSocketUpgradeHeaders(t *testing.T) {
	t.Parallel()

	headerCh := make(chan struct {
		connection string
		upgrade    string
	}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerCh <- struct {
			connection string
			upgrade    string
		}{
			connection: r.Header.Get("Connection"),
			upgrade:    r.Header.Get("Upgrade"),
		}
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Sec-WebSocket-Accept", "abc123")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{Timeout: 5 * time.Second},
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:     "req_ws",
		Method: http.MethodGet,
		Path:   "/api/ws",
		Headers: map[string][]string{
			"Connection": {"keep-alive, upgrade, X-Hop"},
			"Upgrade":    {"websocket"},
			"X-Hop":      {"drop"},
		},
	})

	if resp.Status != http.StatusSwitchingProtocols {
		t.Fatalf("expected %d, got %d", http.StatusSwitchingProtocols, resp.Status)
	}
	gotHeaders := <-headerCh
	if !strings.EqualFold(gotHeaders.connection, "upgrade") {
		t.Fatalf("expected Connection header preserved for local forward, got %q", gotHeaders.connection)
	}
	if !strings.EqualFold(gotHeaders.upgrade, "websocket") {
		t.Fatalf("expected Upgrade header preserved for local forward, got %q", gotHeaders.upgrade)
	}
	if got := firstHeaderValue(resp.Headers, "Connection"); !strings.EqualFold(got, "upgrade") {
		t.Fatalf("expected Connection response header preserved, got %q", got)
	}
	if got := firstHeaderValue(resp.Headers, "Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Fatalf("expected Upgrade response header preserved, got %q", got)
	}
}

func TestForwardLocalUsesForwardedHostWhenProvided(t *testing.T) {
	t.Parallel()

	hostCh := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostCh <- r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{Timeout: 5 * time.Second},
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:     "req_host",
		Method: http.MethodGet,
		Path:   "/hello",
		Headers: map[string][]string{
			"Host": {"myapp.example.com"},
		},
	})

	if resp.Status != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.Status)
	}
	if gotHost := <-hostCh; gotHost != "myapp.example.com" {
		t.Fatalf("expected forwarded Host myapp.example.com, got %q", gotHost)
	}
}

func TestForwardLocalPreservesEscapedPath(t *testing.T) {
	t.Parallel()

	requestCh := make(chan struct {
		path        string
		rawPath     string
		escapedPath string
		requestURI  string
	}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCh <- struct {
			path        string
			rawPath     string
			escapedPath string
			requestURI  string
		}{
			path:        r.URL.Path,
			rawPath:     r.URL.RawPath,
			escapedPath: r.URL.EscapedPath(),
			requestURI:  r.RequestURI,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{Timeout: 5 * time.Second},
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:      "req_raw_path",
		Method:  http.MethodGet,
		Path:    "/files/a/b",
		RawPath: "/files/a%2Fb",
	})

	if resp.Status != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, resp.Status)
	}
	got := <-requestCh
	if got.path != "/files/a/b" {
		t.Fatalf("expected decoded upstream path, got %q", got.path)
	}
	if got.rawPath != "/files/a%2Fb" {
		t.Fatalf("expected raw upstream path to preserve escapes, got %q", got.rawPath)
	}
	if got.escapedPath != "/files/a%2Fb" {
		t.Fatalf("expected escaped upstream path to preserve escapes, got %q", got.escapedPath)
	}
	if got.requestURI != "/files/a%2Fb" {
		t.Fatalf("expected request URI to preserve escapes, got %q", got.requestURI)
	}
}

func TestOpenLocalWebSocketOriginCheckRejectsWithoutForwardedHost(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := &Client{}
	conn, status, _, err := c.openLocalWebSocket(ctx, base, &tunnelproto.WSOpen{
		ID:     "stream-1",
		Method: http.MethodGet,
		Path:   "/ws",
		Headers: map[string][]string{
			"Origin": {"https://myapp.example.com"},
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected websocket dial to fail due to origin/host mismatch")
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected %d, got %d (err=%v)", http.StatusForbidden, status, err)
	}
}

func TestOpenLocalWebSocketOriginCheckAcceptsWithForwardedHost(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := &Client{}
	conn, status, _, err := c.openLocalWebSocket(ctx, base, &tunnelproto.WSOpen{
		ID:     "stream-2",
		Method: http.MethodGet,
		Path:   "/ws",
		Headers: map[string][]string{
			"Origin": {"https://myapp.example.com"},
			"Host":   {"myapp.example.com"},
		},
	})
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		t.Fatalf("expected websocket dial to succeed, got err=%v", err)
	}
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("expected %d, got %d", http.StatusSwitchingProtocols, status)
	}
}

func TestOpenLocalWebSocketPreservesEscapedPath(t *testing.T) {
	t.Parallel()

	requestCh := make(chan struct {
		path        string
		rawPath     string
		escapedPath string
		requestURI  string
	}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCh <- struct {
			path        string
			rawPath     string
			escapedPath string
			requestURI  string
		}{
			path:        r.URL.Path,
			rawPath:     r.URL.RawPath,
			escapedPath: r.URL.EscapedPath(),
			requestURI:  r.RequestURI,
		}
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = conn.Close()
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c := &Client{}
	conn, status, _, err := c.openLocalWebSocket(ctx, base, &tunnelproto.WSOpen{
		ID:      "stream-raw-path",
		Method:  http.MethodGet,
		Path:    "/ws/a/b",
		RawPath: "/ws/a%2Fb",
	})
	if conn != nil {
		_ = conn.Close()
	}
	if err != nil {
		t.Fatalf("expected websocket dial to succeed, got err=%v", err)
	}
	if status != http.StatusSwitchingProtocols {
		t.Fatalf("expected %d, got %d", http.StatusSwitchingProtocols, status)
	}

	got := <-requestCh
	if got.path != "/ws/a/b" {
		t.Fatalf("expected decoded websocket path, got %q", got.path)
	}
	if got.rawPath != "/ws/a%2Fb" {
		t.Fatalf("expected raw websocket path to preserve escapes, got %q", got.rawPath)
	}
	if got.escapedPath != "/ws/a%2Fb" {
		t.Fatalf("expected escaped websocket path to preserve escapes, got %q", got.escapedPath)
	}
	if got.requestURI != "/ws/a%2Fb" {
		t.Fatalf("expected websocket request URI to preserve escapes, got %q", got.requestURI)
	}
}

func TestRunSessionStreamedRequestEarlyFailureDoesNotStallLoop(t *testing.T) {
	t.Parallel()

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "bad")
		}
	}))
	defer local.Close()

	localBase, err := url.Parse(local.URL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	gotReq2Response := make(chan int, 1)
	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		conn.SetReadLimit(64 * 1024 * 1024)

		send := func(msg tunnelproto.Message) error {
			if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
				return err
			}
			defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
			writer, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				return err
			}
			if err := tunnelproto.WriteMessage(writer, msg); err != nil {
				_ = writer.Close()
				return err
			}
			return writer.Close()
		}

		// Request 1: streamed body with an invalid method so the client fails fast
		// before consuming body chunks.
		if err := send(tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:       "req_1",
				Method:   "BAD\nMETHOD",
				Path:     "/fail",
				Streamed: true,
			},
		}); err != nil {
			return
		}

		chunkData := tunnelproto.EncodeBody([]byte("x"))
		for range streamingReqBodyBufSize + 32 {
			if err := send(tunnelproto.Message{
				Kind:      tunnelproto.KindReqBody,
				BodyChunk: &tunnelproto.BodyChunk{ID: "req_1", DataB64: chunkData},
			}); err != nil {
				return
			}
		}

		// Request 2 should still be processed even if req_1 stream consumer is
		// stalled or already closed.
		if err := send(tunnelproto.Message{
			Kind: tunnelproto.KindRequest,
			Request: &tunnelproto.HTTPRequest{
				ID:     "req_2",
				Method: http.MethodGet,
				Path:   "/ok",
			},
		}); err != nil {
			return
		}

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			var msg tunnelproto.Message
			if err := tunnelproto.ReadWSMessage(conn, &msg); err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					continue
				}
				return
			}

			switch msg.Kind {
			case tunnelproto.KindPing:
				_ = send(tunnelproto.Message{Kind: tunnelproto.KindPong})
			case tunnelproto.KindResponse:
				if msg.Response != nil && msg.Response.ID == "req_2" {
					gotReq2Response <- msg.Response.Status
					<-ctx.Done()
					return
				}
			}
		}
	}))
	defer wsSrv.Close()

	c := &Client{
		cfg: config.ClientConfig{
			PingInterval: 0,
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}

	reg := domain.RegisterResponse{
		WSURL: "ws" + strings.TrimPrefix(wsSrv.URL, "http"),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.runSession(ctx, localBase, reg)
	}()

	select {
	case status := <-gotReq2Response:
		if status != http.StatusOK {
			t.Fatalf("expected req_2 status %d, got %d", http.StatusOK, status)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for req_2 response")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("runSession returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runSession did not return after cancellation")
	}
}

func TestIsNonRetriableRegisterError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "hostname conflict code",
			err:  &registerError{StatusCode: http.StatusConflict, Code: "hostname_in_use", Message: "hostname already in use"},
			want: true,
		},
		{
			name: "unauthorized status",
			err:  &registerError{StatusCode: http.StatusUnauthorized, Message: "unauthorized"},
			want: true,
		},
		{
			name: "bad request status",
			err:  &registerError{StatusCode: http.StatusBadRequest, Message: "invalid mode"},
			want: true,
		},
		{
			name: "rate limit status",
			err:  &registerError{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"},
			want: false,
		},
		{
			name: "server error status",
			err:  &registerError{StatusCode: http.StatusBadGateway, Message: "upstream"},
			want: false,
		},
		{
			name: "plain unauthorized fallback",
			err:  io.ErrUnexpectedEOF,
			want: false,
		},
	}

	for _, tc := range cases {
		if got := isNonRetriableRegisterError(tc.err); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	if got := isNonRetriableRegisterError(errors.New("unauthorized")); !got {
		t.Fatal("expected plain unauthorized error to be non-retriable")
	}
}

func TestIsTLSProvisioningInProgressError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "verify certificate failure",
			err:  errors.New("Post \"https://example.com\": tls: failed to verify certificate: x509: certificate signed by unknown authority"),
			want: true,
		},
		{
			name: "standards compliant failure",
			err:  errors.New("x509: \"example.com\" certificate is not standards compliant"),
			want: true,
		},
		{
			name: "generic x509",
			err:  errors.New("x509: certificate has expired or is not yet valid"),
			want: true,
		},
		{
			name: "network error",
			err:  errors.New("dial tcp: connect: connection refused"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isTLSProvisioningInProgressError(tc.err); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func firstHeaderValue(h map[string][]string, key string) string {
	if len(h[key]) == 0 {
		return ""
	}
	return h[key][0]
}

func TestRegisterSendsOptionalPassword(t *testing.T) {
	t.Parallel()

	resultCh := make(chan struct {
		auth     string
		user     string
		mode     string
		password string
		resumeID string
	}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		result := struct {
			auth     string
			user     string
			mode     string
			password string
			resumeID string
		}{
			auth:     r.Header.Get("Authorization"),
			resumeID: r.Header.Get(domain.RegisterResumeTunnelHeader),
		}
		var req domain.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result.password = req.Password
		result.user = req.User
		result.mode = req.AccessMode
		resultCh <- result
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tunnel_id":"t_1","public_url":"https://demo.example.com","ws_url":"wss://example.com/v1/tunnels/connect?token=abc"}`)
	}))
	defer srv.Close()

	c := New(config.ClientConfig{
		ServerURL:   srv.URL,
		APIKey:      "key123",
		User:        "admin",
		Password:    "session-pass",
		ProtectMode: "form",
		LocalPort:   8080,
	}, nil)
	c.resumeID = "t_prev"

	_, err := c.register(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := <-resultCh
	if got.password != "session-pass" {
		t.Fatalf("expected password in register payload, got %q", got.password)
	}
	if got.user != "admin" {
		t.Fatalf("expected user in register payload, got %q", got.user)
	}
	if got.mode != "form" {
		t.Fatalf("expected access mode in register payload, got %q", got.mode)
	}
	if !strings.HasPrefix(got.auth, "Bearer ") {
		t.Fatalf("expected bearer auth header, got %q", got.auth)
	}
	if got.resumeID != "t_prev" {
		t.Fatalf("expected resume tunnel header t_prev, got %q", got.resumeID)
	}
}

func TestNormalizeWSURLPort(t *testing.T) {
	tests := []struct {
		name      string
		wsURL     string
		serverURL string
		want      string
	}{
		{
			name:      "inject non-default server port",
			wsURL:     "wss://myapp.example.com/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com:10443",
			want:      "wss://myapp.example.com:10443/v1/tunnels/connect?token=abc",
		},
		{
			name:      "keep explicit ws port",
			wsURL:     "wss://myapp.example.com:9443/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com:10443",
			want:      "wss://myapp.example.com:9443/v1/tunnels/connect?token=abc",
		},
		{
			name:      "ignore default server port",
			wsURL:     "wss://myapp.example.com/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com",
			want:      "wss://myapp.example.com/v1/tunnels/connect?token=abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeWSURLPort(tt.wsURL, tt.serverURL); got != tt.want {
				t.Fatalf("normalizeWSURLPort(): got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConnectSessionTransportQUICRequiresH3URL(t *testing.T) {
	t.Parallel()

	c := &Client{cfg: config.ClientConfig{Transport: "quic"}}
	_, err := c.connectSessionTransport(t.Context(), domain.RegisterResponse{
		WSURL: "wss://example.com/v1/tunnels/connect?token=abc",
	})
	if err == nil {
		t.Fatal("expected error when h3_url is missing")
	}
	if !isNonRetriableSessionError(err) {
		t.Fatalf("expected non-retriable session error, got %v", err)
	}
}

func TestHTTP3DialAuthority(t *testing.T) {
	t.Parallel()

	cases := []struct {
		raw  string
		want string
	}{
		{raw: "https://example.com/v1/tunnels/connect-h3?token=abc", want: "example.com:443"},
		{raw: "https://example.com:9443/v1/tunnels/connect-h3?token=abc", want: "example.com:9443"},
		{raw: "https://[2001:db8::1]:9443/v1/tunnels/connect-h3?token=abc", want: "[2001:db8::1]:9443"},
	}
	for _, tc := range cases {
		u, err := url.Parse(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := http3DialAuthority(u); got != tc.want {
			t.Fatalf("http3DialAuthority(%q): got %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCanUseH3Modes(t *testing.T) {
	t.Parallel()

	reg := domain.RegisterResponse{
		H3URL:        "https://example.com/v1/tunnels/connect-h3?token=abc",
		Capabilities: []string{"h3_compat", "h3_multistream_v2", "h3_multistream"},
	}
	if !canUseH3Compat(reg) {
		t.Fatal("expected h3 compatibility mode to be available")
	}
	if !canUseH3MultiStream(reg) {
		t.Fatal("expected h3 multistream mode to be available")
	}
	if got := h3MultiStreamProtocol(reg); got != tunnelCapabilityH3MultistreamV2 {
		t.Fatalf("expected multistream v2 preference, got %q", got)
	}

	reg.Capabilities = []string{"h3_compat"}
	if canUseH3MultiStream(reg) {
		t.Fatal("expected h3 multistream mode to be unavailable without capability")
	}

	reg.Capabilities = nil
	if !canUseH3Compat(reg) {
		t.Fatal("expected h3 compatibility mode to be available without capability list")
	}
	if canUseH3MultiStream(reg) {
		t.Fatal("expected h3 multistream mode to require explicit capability list")
	}
}

func TestH3WorkerURL(t *testing.T) {
	t.Parallel()

	target, err := url.Parse("https://example.com/v1/tunnels/connect-h3?token=abc")
	if err != nil {
		t.Fatal(err)
	}
	if got := h3WorkerURL(target); got != "https://example.com/v1/tunnels/connect-h3/stream" {
		t.Fatalf("unexpected worker url %q", got)
	}
}

func TestClientH3MultiStreamRuntimeInitialWorkerCount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		maxOpen int
		want    int
	}{
		{name: "below floor", maxOpen: 1, want: 1},
		{name: "at floor", maxOpen: 2, want: 2},
		{name: "above floor", maxOpen: 8, want: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rt := &clientH3MultiStreamRuntime{
				client: &Client{cfg: config.ClientConfig{MaxConcurrentForwards: tc.maxOpen}},
			}
			if got := rt.initialWorkerCount(); got != tc.want {
				t.Fatalf("initialWorkerCount() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIsH3MultiStreamProtocol(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		protocol string
		want     bool
	}{
		{name: "legacy multistream", protocol: tunnelCapabilityH3Multistream, want: true},
		{name: "v2 multistream", protocol: tunnelCapabilityH3MultistreamV2, want: true},
		{name: "compat", protocol: tunnelCapabilityH3CompatV1, want: false},
		{name: "ws", protocol: "ws_v1", want: false},
		{name: "blank", protocol: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isH3MultiStreamProtocol(tc.protocol); got != tc.want {
				t.Fatalf("isH3MultiStreamProtocol(%q) = %v, want %v", tc.protocol, got, tc.want)
			}
		})
	}
}

func TestIsNonReleaseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    bool
	}{
		{version: "", want: true},
		{version: "dev", want: true},
		{version: "  dev  ", want: true},
		{version: "1.2.3-dev", want: true},
		{version: "1.2.3", want: false},
		{version: "v1.2.3", want: false},
	}
	for _, tt := range tests {
		if got := isNonReleaseVersion(tt.version); got != tt.want {
			t.Fatalf("isNonReleaseVersion(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestForwardAndSendSmallResponseInline(t *testing.T) {
	t.Parallel()

	responseBody := "small response"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, responseBody)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}

	var msgs []tunnelproto.Message
	writeMsg := func(msg tunnelproto.Message) error {
		msgs = append(msgs, msg)
		return nil
	}

	req := &tunnelproto.HTTPRequest{
		ID:     "req_1",
		Method: http.MethodGet,
		Path:   "/hello",
	}
	c.forwardAndSend(context.Background(), base, req, nil, writeMsg, nil)

	if len(msgs) != 1 {
		t.Fatalf("expected 1 message for small inline response, got %d", len(msgs))
	}
	if msgs[0].Kind != tunnelproto.KindResponse {
		t.Fatalf("expected kind %q, got %q", tunnelproto.KindResponse, msgs[0].Kind)
	}
	if msgs[0].Response.Streamed {
		t.Fatal("expected non-streamed response for small body")
	}
	decoded, _ := msgs[0].Response.Payload()
	if string(decoded) != responseBody {
		t.Fatalf("expected body %q, got %q", responseBody, string(decoded))
	}
	if firstHeaderValue(msgs[0].Response.Headers, "X-Test") != "yes" {
		t.Fatal("expected X-Test header to be preserved")
	}
}

func TestForwardAndSendInlineBodyRecordsTraffic(t *testing.T) {
	t.Parallel()

	recorder := &testTrafficRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(append([]byte("reply:"), body...))
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
		trafficSink: recorder,
	}

	req := &tunnelproto.HTTPRequest{
		ID:     "req_inline_traffic",
		Method: http.MethodPost,
		Path:   "/echo",
		Body:   []byte("payload"),
	}
	c.forwardAndSend(context.Background(), base, req, nil, func(tunnelproto.Message) error { return nil }, nil)

	if got := recorder.inbound.Load(); got != int64(len("payload")) {
		t.Fatalf("expected inbound bytes %d, got %d", len("payload"), got)
	}
	if got := recorder.outbound.Load(); got != int64(len("reply:payload")) {
		t.Fatalf("expected outbound bytes %d, got %d", len("reply:payload"), got)
	}
}

func TestForwardAndSendLargeResponseStreamed(t *testing.T) {
	t.Parallel()

	largeBody := make([]byte, streamingThreshold+500)
	for i := range largeBody {
		largeBody[i] = byte(i % 256)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(largeBody)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}

	var msgs []tunnelproto.Message
	writeMsg := func(msg tunnelproto.Message) error {
		msgs = append(msgs, msg)
		return nil
	}

	req := &tunnelproto.HTTPRequest{
		ID:     "req_2",
		Method: http.MethodGet,
		Path:   "/download",
	}
	c.forwardAndSend(context.Background(), base, req, nil, writeMsg, nil)

	if len(msgs) < 3 {
		t.Fatalf("expected at least 3 messages (response header + body chunk(s) + end), got %d", len(msgs))
	}

	// First message: response headers with Streamed=true
	if msgs[0].Kind != tunnelproto.KindResponse {
		t.Fatalf("expected first kind %q, got %q", tunnelproto.KindResponse, msgs[0].Kind)
	}
	if !msgs[0].Response.Streamed {
		t.Fatal("expected response to be streamed")
	}
	if len(msgs[0].Response.Body) != 0 {
		t.Fatal("expected empty inline body in streamed response header")
	}
	if msgs[0].Response.Status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", msgs[0].Response.Status)
	}

	// Middle messages: body chunks
	var reassembled []byte
	for _, msg := range msgs[1 : len(msgs)-1] {
		if msg.Kind != tunnelproto.KindRespBody {
			t.Fatalf("expected body chunk kind %q, got %q", tunnelproto.KindRespBody, msg.Kind)
		}
		chunk, _ := msg.BodyChunk.Payload()
		reassembled = append(reassembled, chunk...)
	}

	// Last message: end signal
	last := msgs[len(msgs)-1]
	if last.Kind != tunnelproto.KindRespBodyEnd {
		t.Fatalf("expected last kind %q, got %q", tunnelproto.KindRespBodyEnd, last.Kind)
	}

	if len(reassembled) != len(largeBody) {
		t.Fatalf("reassembled body length %d != original %d", len(reassembled), len(largeBody))
	}
	for i := range reassembled {
		if reassembled[i] != largeBody[i] {
			t.Fatalf("body mismatch at byte %d", i)
		}
	}
}

func TestForwardAndSendStreamedRequestBody(t *testing.T) {
	t.Parallel()

	bodyResultCh := make(chan []byte, 1)
	recorder := &testTrafficRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		bodyResultCh <- gotBody
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "received")
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
		trafficSink: recorder,
	}

	var msgs []tunnelproto.Message
	writeMsg := func(msg tunnelproto.Message) error {
		msgs = append(msgs, msg)
		return nil
	}

	bodyCh := make(chan []byte, 4)
	bodyCh <- []byte("chunk1-")
	bodyCh <- []byte("chunk2-")
	bodyCh <- []byte("chunk3")
	close(bodyCh)

	req := &tunnelproto.HTTPRequest{
		ID:       "req_3",
		Method:   http.MethodPost,
		Path:     "/upload",
		Streamed: true,
	}
	c.forwardAndSend(context.Background(), base, req, bodyCh, writeMsg, nil)

	expected := "chunk1-chunk2-chunk3"
	if gotBody := string(<-bodyResultCh); gotBody != expected {
		t.Fatalf("expected local upstream to receive %q, got %q", expected, gotBody)
	}

	if len(msgs) < 1 {
		t.Fatal("expected at least 1 response message")
	}
	if msgs[0].Kind != tunnelproto.KindResponse {
		t.Fatalf("expected response kind, got %q", msgs[0].Kind)
	}
	if msgs[0].Response.Status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", msgs[0].Response.Status)
	}
	if got := recorder.inbound.Load(); got != int64(len(expected)) {
		t.Fatalf("expected inbound bytes %d, got %d", len(expected), got)
	}
	if got := recorder.outbound.Load(); got != int64(len("received")) {
		t.Fatalf("expected outbound bytes %d, got %d", len("received"), got)
	}
}

func TestForwardAndSendUpstreamUnavailable(t *testing.T) {
	t.Parallel()

	// Use a port that definitely isn't listening
	base, _ := url.Parse("http://127.0.0.1:1")

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 1 * time.Second,
			},
		},
	}

	var msgs []tunnelproto.Message
	writeMsg := func(msg tunnelproto.Message) error {
		msgs = append(msgs, msg)
		return nil
	}

	req := &tunnelproto.HTTPRequest{
		ID:     "req_err",
		Method: http.MethodGet,
		Path:   "/fail",
	}
	c.forwardAndSend(context.Background(), base, req, nil, writeMsg, nil)

	if len(msgs) != 1 {
		t.Fatalf("expected 1 error response, got %d", len(msgs))
	}
	if msgs[0].Response.Status != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", msgs[0].Response.Status)
	}
}

func TestForwardAndSendCancelsLocalRequest(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	canceled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.forwardAndSend(ctx, base, &tunnelproto.HTTPRequest{
			ID:     "req_cancel",
			Method: http.MethodGet,
			Path:   "/slow",
		}, nil, func(tunnelproto.Message) error { return nil }, nil)
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("local upstream request did not start")
	}

	cancel()

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("expected local upstream request context to be canceled")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwardAndSend did not return after cancellation")
	}
}

func TestPumpStreamedRequestBodyMessagesCancelsOnReadError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	steps := []struct {
		msg tunnelproto.Message
		err error
	}{
		{
			msg: tunnelproto.Message{
				Kind: tunnelproto.KindReqBody,
				BodyChunk: &tunnelproto.BodyChunk{
					ID:   "req_1",
					Data: []byte("chunk-1"),
				},
			},
		},
		{err: io.ErrUnexpectedEOF},
	}

	var idx int
	out := make(chan []byte, 2)
	pumpStreamedRequestBodyMessages(ctx, "req_1", cancel, func() (tunnelproto.Message, error) {
		step := steps[idx]
		idx++
		return step.msg, step.err
	}, out)

	var chunks [][]byte
	for chunk := range out {
		chunks = append(chunks, append([]byte(nil), chunk...))
	}

	if len(chunks) != 1 || string(chunks[0]) != "chunk-1" {
		t.Fatalf("expected first chunk to be forwarded before failure, got %q", chunks)
	}

	select {
	case <-ctx.Done():
	default:
		t.Fatal("expected context cancellation on stream read error")
	}
}

func TestRequestContextAppliesMessageTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := requestContext(context.Background(), &tunnelproto.HTTPRequest{TimeoutMs: 25})
	defer cancel()

	select {
	case <-ctx.Done():
		t.Fatal("request context canceled too early")
	case <-time.After(10 * time.Millisecond):
	}

	select {
	case <-ctx.Done():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("expected request context to time out")
	}
}

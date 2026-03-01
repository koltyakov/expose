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
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestNextBackoff(t *testing.T) {
	t.Parallel()

	// With jitter (±25%), results are in range [0.75*base, 1.25*base].
	got := nextBackoff(0)
	base := reconnectInitialDelay * 2
	lo := time.Duration(float64(base) * 0.75)
	hi := time.Duration(float64(base) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected initial backoff in [%s, %s], got %s", lo, hi, got)
	}

	got = nextBackoff(reconnectInitialDelay)
	base = reconnectInitialDelay * 2
	lo = time.Duration(float64(base) * 0.75)
	hi = time.Duration(float64(base) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected doubled delay in [%s, %s], got %s", lo, hi, got)
	}

	got = nextBackoff(reconnectMaxDelay)
	lo = time.Duration(float64(reconnectMaxDelay) * 0.75)
	hi = time.Duration(float64(reconnectMaxDelay) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected clamped delay in [%s, %s], got %s", lo, hi, got)
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
	if tr.MaxConnsPerHost != maxConcurrentForwards {
		t.Fatalf("expected MaxConnsPerHost=%d, got %d", maxConcurrentForwards, tr.MaxConnsPerHost)
	}
	if tr.ResponseHeaderTimeout != 2*time.Minute {
		t.Fatalf("expected ResponseHeaderTimeout=2m, got %s", tr.ResponseHeaderTimeout)
	}
}

func TestForwardLocalStripsHopByHopHeaders(t *testing.T) {
	t.Parallel()

	var gotConnection string
	var gotHop string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotHop = r.Header.Get("X-Hop")
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
	if gotConnection != "" {
		t.Fatalf("expected Connection header stripped before local forward, got %q", gotConnection)
	}
	if gotHop != "" {
		t.Fatalf("expected Connection-declared hop header stripped, got %q", gotHop)
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

func TestForwardLocalPreservesWebSocketUpgradeHeaders(t *testing.T) {
	t.Parallel()

	var gotConnection string
	var gotUpgrade string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotUpgrade = r.Header.Get("Upgrade")
		if !strings.EqualFold(gotUpgrade, "websocket") {
			t.Fatalf("expected Upgrade websocket, got %q", gotUpgrade)
		}
		if !strings.EqualFold(gotConnection, "upgrade") {
			t.Fatalf("expected Connection upgrade, got %q", gotConnection)
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
	if !strings.EqualFold(gotConnection, "upgrade") {
		t.Fatalf("expected Connection header preserved for local forward, got %q", gotConnection)
	}
	if !strings.EqualFold(gotUpgrade, "websocket") {
		t.Fatalf("expected Upgrade header preserved for local forward, got %q", gotUpgrade)
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

	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
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
	if gotHost != "myapp.example.com" {
		t.Fatalf("expected forwarded Host myapp.example.com, got %q", gotHost)
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
			return conn.WriteJSON(msg)
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
		for i := 0; i < streamingReqBodyBufSize+32; i++ {
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

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	reg := registerResponse{
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
		tc := tc
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

	var gotAuth string
	var gotUser string
	var gotMode string
	var gotPassword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotPassword = req.Password
		gotUser = req.User
		gotMode = req.AccessMode
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

	_, err := c.register(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotPassword != "session-pass" {
		t.Fatalf("expected password in register payload, got %q", gotPassword)
	}
	if gotUser != "admin" {
		t.Fatalf("expected user in register payload, got %q", gotUser)
	}
	if gotMode != "form" {
		t.Fatalf("expected access mode in register payload, got %q", gotMode)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("expected bearer auth header, got %q", gotAuth)
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
	decoded, _ := tunnelproto.DecodeBody(msgs[0].Response.BodyB64)
	if string(decoded) != responseBody {
		t.Fatalf("expected body %q, got %q", responseBody, string(decoded))
	}
	if firstHeaderValue(msgs[0].Response.Headers, "X-Test") != "yes" {
		t.Fatal("expected X-Test header to be preserved")
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
	if msgs[0].Response.BodyB64 != "" {
		t.Fatal("expected empty BodyB64 in streamed response header")
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
		chunk, _ := tunnelproto.DecodeBody(msg.BodyChunk.DataB64)
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

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
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
	if string(gotBody) != expected {
		t.Fatalf("expected local upstream to receive %q, got %q", expected, string(gotBody))
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

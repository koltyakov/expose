package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestClientRunReconnectsAfterH3MultiStreamV2ServerRestart(t *testing.T) {
	localUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer localUpstream.Close()

	localBase, err := url.Parse(localUpstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	localPort, err := strconv.Atoi(localBase.Port())
	if err != nil {
		t.Fatal(err)
	}

	var (
		registerMu    sync.Mutex
		h3Addr        string
		resumeHeaders []string
		modeHeaders   []string
	)

	firstGenDone := make(chan struct{})
	secondGenDone := make(chan struct{})

	startTunnelServer := func(done <-chan struct{}) (string, func()) {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/tunnels/connect-h3", func(w http.ResponseWriter, r *http.Request) {
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
				return
			}
			registerMu.Lock()
			modeHeaders = append(modeHeaders, r.Header.Get("X-Expose-H3-Mode"))
			registerMu.Unlock()
			w.Header().Set(h3SessionHeader, "session-token")
			w.WriteHeader(http.StatusOK)
			stream := streamer.HTTPStream()
			<-done
			closeHTTP3TestStream(stream)
		})
		mux.HandleFunc("/v1/tunnels/connect-h3/stream", func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(h3SessionHeader) == "" {
				http.Error(w, "missing h3 session", http.StatusUnauthorized)
				return
			}
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			stream := streamer.HTTPStream()
			<-done
			closeHTTP3TestStream(stream)
		})
		return startHTTP3TestServer(t, mux)
	}

	firstAddr, cleanupFirst := startTunnelServer(firstGenDone)
	registerMu.Lock()
	h3Addr = firstAddr
	registerMu.Unlock()
	defer cleanupFirst()

	registerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		registerMu.Lock()
		resumeHeaders = append(resumeHeaders, r.Header.Get(domain.RegisterResumeTunnelHeader))
		currentH3Addr := h3Addr
		registerMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.RegisterResponse{
			TunnelID:     "tun_h3",
			PublicURL:    "https://demo.example.com",
			WSURL:        "wss://unused.example.com/v1/tunnels/connect?token=unused",
			H3URL:        "https://" + currentH3Addr + "/v1/tunnels/connect-h3?token=abc",
			Capabilities: []string{tunnelCapabilityH3MultistreamV2},
		})
	}))
	defer registerSrv.Close()

	readyCh := make(chan TunnelReadyEvent, 4)
	dropCh := make(chan SessionDisconnectEvent, 4)
	runErrCh := make(chan error, 1)

	c := New(config.ClientConfig{
		ServerURL:    registerSrv.URL,
		APIKey:       "test-key",
		Transport:    "quic",
		LocalPort:    localPort,
		PingInterval: 0,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.h3TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	c.SetLifecycleHooks(LifecycleHooks{
		OnTunnelReady: func(ev TunnelReadyEvent) {
			readyCh <- ev
		},
		OnSessionDrop: func(ev SessionDisconnectEvent) {
			dropCh <- ev
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		runErrCh <- c.Run(ctx)
	}()

	firstReady := waitTunnelReadyEvent(t, readyCh, 8*time.Second, "first tunnel ready event")
	if firstReady.TunnelID != "tun_h3" {
		t.Fatalf("expected tunnel id tun_h3, got %q", firstReady.TunnelID)
	}
	if firstReady.Transport != "quic" {
		t.Fatalf("expected quic transport, got %q", firstReady.Transport)
	}

	secondAddr, cleanupSecond := startTunnelServer(secondGenDone)
	registerMu.Lock()
	h3Addr = secondAddr
	registerMu.Unlock()
	defer func() {
		close(secondGenDone)
		cleanupSecond()
	}()

	close(firstGenDone)
	cleanupFirst()

	drop := waitSessionDropEvent(t, dropCh, 8*time.Second, "session drop after first server shutdown")
	if drop.Err == nil {
		t.Fatal("expected disconnect error after first server shutdown")
	}

	secondReady := waitTunnelReadyEvent(t, readyCh, 20*time.Second, "second tunnel ready event")
	if secondReady.TunnelID != "tun_h3" {
		t.Fatalf("expected resumed tunnel id tun_h3, got %q", secondReady.TunnelID)
	}

	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("client run returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client run did not stop after cancellation")
	}

	registerMu.Lock()
	defer registerMu.Unlock()
	if len(resumeHeaders) < 2 {
		t.Fatalf("expected at least two register attempts, got %d", len(resumeHeaders))
	}
	if resumeHeaders[0] != "" {
		t.Fatalf("expected first register attempt without resume header, got %q", resumeHeaders[0])
	}
	if resumeHeaders[1] != "tun_h3" {
		t.Fatalf("expected reconnect to reuse tunnel id tun_h3, got %q", resumeHeaders[1])
	}
	if len(modeHeaders) < 2 {
		t.Fatalf("expected at least two http3 control connects, got %d", len(modeHeaders))
	}
	for i, got := range modeHeaders[:2] {
		if got != "multistream-v2" {
			t.Fatalf("expected http3 mode multistream-v2 on connect %d, got %q", i+1, got)
		}
	}
}

func TestClientRunH3DisplayTracksWebSockets(t *testing.T) {
	asyncErrCh := make(chan error, 8)
	localMessageCh := make(chan string, 1)
	localUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			recordAsyncTestError(asyncErrCh, "upgrade local websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			msgType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			select {
			case localMessageCh <- string(payload):
			default:
			}
			if err := conn.WriteMessage(msgType, []byte("pong")); err != nil {
				return
			}
		}
	}))
	defer localUpstream.Close()

	localBase, err := url.Parse(localUpstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	localPort, err := strconv.Atoi(localBase.Port())
	if err != nil {
		t.Fatal(err)
	}

	controlDone := make(chan struct{})
	closeWS := make(chan struct{})
	ackCh := make(chan tunnelproto.Message, 1)
	var dispatched atomic.Bool

	h3Addr, cleanupH3 := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tunnels/connect-h3":
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
				return
			}
			w.Header().Set(h3SessionHeader, "session-token")
			w.WriteHeader(http.StatusOK)
			stream := streamer.HTTPStream()
			<-controlDone
			closeHTTP3TestStream(stream)
		case "/v1/tunnels/connect-h3/stream":
			if r.Header.Get(h3SessionHeader) == "" {
				http.Error(w, "missing h3 session", http.StatusUnauthorized)
				return
			}
			streamer, ok := w.(http3.HTTPStreamer)
			if !ok {
				http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			stream := streamer.HTTPStream()
			defer closeHTTP3TestStream(stream)

			if !dispatched.CompareAndSwap(false, true) {
				<-controlDone
				return
			}

			err := tunnelproto.WriteStreamJSONV2(stream, tunnelproto.Message{
				Kind: tunnelproto.KindWSOpen,
				WSOpen: &tunnelproto.WSOpen{
					ID:     "ws_h3_display",
					Method: http.MethodGet,
					Path:   "/ws",
					Headers: map[string][]string{
						"X-Forwarded-For": {"1.2.3.4"},
						"User-Agent":      {"Browser/1.0"},
					},
				},
			})
			if err != nil {
				recordAsyncTestError(asyncErrCh, "write websocket open to worker stream: %v", err)
				return
			}

			var ack tunnelproto.Message
			if err := tunnelproto.ReadStreamMessageV2(stream, clientWSReadLimit, &ack); err != nil {
				recordAsyncTestError(asyncErrCh, "read websocket open ack from worker stream: %v", err)
				return
			}
			ackCh <- ack

			if err := tunnelproto.WriteStreamBinaryFrameV2(stream, tunnelproto.BinaryFrameWSData, "ws_h3_display", websocket.TextMessage, []byte("ping")); err != nil {
				recordAsyncTestError(asyncErrCh, "write websocket data to worker stream: %v", err)
				return
			}

			var reply tunnelproto.Message
			if err := tunnelproto.ReadStreamMessageV2(stream, clientWSReadLimit, &reply); err != nil {
				recordAsyncTestError(asyncErrCh, "read websocket reply from worker stream: %v", err)
				return
			}
			ackCh <- reply

			<-closeWS
			if err := tunnelproto.WriteStreamJSONV2(stream, tunnelproto.Message{
				Kind: tunnelproto.KindWSClose,
				WSClose: &tunnelproto.WSClose{
					ID:   "ws_h3_display",
					Code: websocket.CloseNormalClosure,
				},
			}); err != nil {
				recordAsyncTestError(asyncErrCh, "write websocket close to worker stream: %v", err)
				return
			}

			<-controlDone
		default:
			http.NotFound(w, r)
		}
	}))
	defer func() {
		close(controlDone)
		cleanupH3()
	}()

	registerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(domain.RegisterResponse{
			TunnelID:     "tun_h3_display",
			PublicURL:    "https://demo.example.com",
			WSURL:        "wss://unused.example.com/v1/tunnels/connect?token=unused",
			H3URL:        "https://" + h3Addr + "/v1/tunnels/connect-h3?token=abc",
			Capabilities: []string{tunnelCapabilityH3MultistreamV2},
		})
	}))
	defer registerSrv.Close()

	display, buf := newTestDisplay(false)
	readyCh := make(chan TunnelReadyEvent, 1)
	runErrCh := make(chan error, 1)

	c := New(config.ClientConfig{
		ServerURL:    registerSrv.URL,
		APIKey:       "test-key",
		Transport:    "quic",
		LocalPort:    localPort,
		PingInterval: 0,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	c.SetDisplay(display)
	c.SetTrafficSink(display)
	c.SetLifecycleHooks(LifecycleHooks{
		OnTunnelReady: func(ev TunnelReadyEvent) {
			readyCh <- ev
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		runErrCh <- c.Run(ctx)
	}()

	waitTunnelReadyEvent(t, readyCh, 8*time.Second, "h3 tunnel ready event")
	requireNoAsyncTestError(t, asyncErrCh)
	ack := waitForCondition(t, 5*time.Second, "websocket open ack on h3 worker", func() (tunnelproto.Message, bool) {
		select {
		case msg := <-ackCh:
			return msg, true
		default:
			return tunnelproto.Message{}, false
		}
	})
	if ack.WSOpenAck == nil || !ack.WSOpenAck.OK {
		t.Fatalf("expected successful websocket open ack, got: %+v", ack.WSOpenAck)
	}
	requireNoAsyncTestError(t, asyncErrCh)
	waitForCondition(t, 5*time.Second, "local websocket message delivery", func() (string, bool) {
		select {
		case msg := <-localMessageCh:
			return msg, msg == "ping"
		default:
			return "", false
		}
	})
	reply := waitForCondition(t, 5*time.Second, "websocket reply on h3 worker", func() (tunnelproto.Message, bool) {
		select {
		case msg := <-ackCh:
			return msg, msg.Kind == tunnelproto.KindWSData
		default:
			return tunnelproto.Message{}, false
		}
	})
	replyPayload, err := reply.WSData.Payload()
	if err != nil {
		t.Fatalf("decode websocket reply payload: %v", err)
	}
	if string(replyPayload) != "pong" {
		t.Fatalf("expected websocket reply payload %q, got %q", "pong", string(replyPayload))
	}
	requireNoAsyncTestError(t, asyncErrCh)

	buf.Reset()
	display.mu.Lock()
	display.redraw()
	display.mu.Unlock()
	out := buf.String()
	if !strings.Contains(out, "1 open") {
		t.Fatalf("expected websocket counter in QUIC display, got: %s", out)
	}
	if !strings.Contains(out, "Traffic") || !strings.Contains(out, "In 4 B total (4 B/s) | Out 4 B total (4 B/s)") {
		t.Fatalf("expected websocket traffic in QUIC display, got: %s", out)
	}

	close(closeWS)
	waitForCondition(t, 5*time.Second, "websocket close to reach display state", func() (struct{}, bool) {
		display.mu.Lock()
		defer display.mu.Unlock()
		_, ok := display.wsConns["ws_h3_display"]
		return struct{}{}, !ok
	})

	time.Sleep(wsCloseDebounce + 100*time.Millisecond)
	buf.Reset()
	display.mu.Lock()
	display.redraw()
	display.mu.Unlock()
	out = buf.String()
	if strings.Contains(out, "1 open") {
		t.Fatalf("expected websocket counter to clear after close, got: %s", out)
	}
	if !strings.Contains(out, "WebSockets") || !strings.Contains(out, "--") {
		t.Fatalf("expected websocket placeholder after close, got: %s", out)
	}
	requireNoAsyncTestError(t, asyncErrCh)

	cancel()
	select {
	case err := <-runErrCh:
		if err != nil {
			t.Fatalf("client run returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client run did not stop after cancellation")
	}
	requireNoAsyncTestError(t, asyncErrCh)
}

func waitTunnelReadyEvent(t testing.TB, ch <-chan TunnelReadyEvent, timeout time.Duration, label string) TunnelReadyEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
		return TunnelReadyEvent{}
	}
}

func waitSessionDropEvent(t testing.TB, ch <-chan SessionDisconnectEvent, timeout time.Duration, label string) SessionDisconnectEvent {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %s", label)
		return SessionDisconnectEvent{}
	}
}

func waitForCondition[T any](t testing.TB, timeout time.Duration, label string, fn func() (T, bool)) T {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if value, ok := fn(); ok {
			return value
		}
		time.Sleep(25 * time.Millisecond)
	}
	var zero T
	t.Fatalf("timed out waiting for %s", label)
	return zero
}

func recordAsyncTestError(ch chan<- error, format string, args ...any) {
	select {
	case ch <- fmt.Errorf(format, args...):
	default:
	}
}

func requireNoAsyncTestError(t testing.TB, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		t.Fatal(err)
	default:
	}
}

func startHTTP3TestServer(t testing.TB, handler http.Handler) (string, func()) {
	t.Helper()

	cert := selfSignedCertForLoopback(t)
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	addr := conn.LocalAddr().String()
	server := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConf,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(conn); err != nil {
			errCh <- err
		}
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		select {
		case <-waitCtx.Done():
			t.Fatalf("http3 test server did not start in time: %v", waitCtx.Err())
		case err := <-errCh:
			t.Fatalf("http3 test server failed: %v", err)
		default:
		}
		probeCtx, probeCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		probeConn, err := quic.DialAddr(probeCtx, addr, &tls.Config{
			MinVersion:         tls.VersionTLS13,
			NextProtos:         []string{http3.NextProtoH3},
			ServerName:         "localhost",
			InsecureSkipVerify: true,
		}, nil)
		probeCancel()
		if err == nil {
			_ = probeConn.CloseWithError(0, "")
			return addr, func() {
				_ = server.Close()
				_ = conn.Close()
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func closeHTTP3TestStream(stream *http3.Stream) {
	if stream == nil {
		return
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	_ = stream.Close()
}

func selfSignedCertForLoopback(t testing.TB) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("create key pair: %v", err)
	}
	return cert
}

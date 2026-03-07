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
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
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

	h3Addr := randomLoopbackUDPAddr(t)

	var (
		registerMu    sync.Mutex
		resumeHeaders []string
		modeHeaders   []string
	)

	firstGenDone := make(chan struct{})
	secondGenDone := make(chan struct{})

	startTunnelServer := func(done <-chan struct{}) func() {
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
		return startHTTP3TestServerAtAddr(t, h3Addr, mux)
	}

	cleanupFirst := startTunnelServer(firstGenDone)
	defer cleanupFirst()

	registerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		registerMu.Lock()
		resumeHeaders = append(resumeHeaders, r.Header.Get(domain.RegisterResumeTunnelHeader))
		registerMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registerResponse{
			TunnelID:     "tun_h3",
			PublicURL:    "https://demo.example.com",
			WSURL:        "wss://unused.example.com/v1/tunnels/connect?token=unused",
			H3URL:        "https://" + h3Addr + "/v1/tunnels/connect-h3?token=abc",
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

	close(firstGenDone)
	cleanupFirst()

	cleanupSecond := startTunnelServer(secondGenDone)
	defer func() {
		close(secondGenDone)
		cleanupSecond()
	}()

	drop := waitSessionDropEvent(t, dropCh, 8*time.Second, "session drop after first server shutdown")
	if drop.Err == nil {
		t.Fatal("expected disconnect error after first server shutdown")
	}

	secondReady := waitTunnelReadyEvent(t, readyCh, 10*time.Second, "second tunnel ready event")
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

func startHTTP3TestServerAtAddr(t testing.TB, addr string, handler http.Handler) func() {
	t.Helper()

	cert := selfSignedCertForLoopback(t)
	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
	server := &http3.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsConf,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil {
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
		conn, err := net.DialTimeout("udp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return func() {
				_ = server.Close()
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

func randomLoopbackUDPAddr(t testing.TB) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen random udp addr: %v", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.LocalAddr().String()
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

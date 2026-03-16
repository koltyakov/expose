package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestHTTP3IntegrationControlAndWorkerStreamRoundTrip(t *testing.T) {
	t.Parallel()

	const sessionToken = "h3StreamPool_test_token"
	workerCh := make(chan *http3.Stream, 2)

	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set(h3SessionHeader, sessionToken)
		w.WriteHeader(http.StatusOK)
		_ = streamer.HTTPStream()
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h3SessionHeader) != sessionToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		workerCh <- streamer.HTTPStream()
	})

	addr, shutdown := startHTTP3IntegrationServer(t, mux)
	defer shutdown()

	_, clientConn, closeClient := newHTTP3IntegrationClient(t, addr)
	defer closeClient()

	control := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/control", "")
	controlResp, err := control.ReadResponse()
	if err != nil {
		t.Fatalf("read control response: %v", err)
	}
	if got := controlResp.Header.Get(h3SessionHeader); got != sessionToken {
		t.Fatalf("expected session header %q, got %q", sessionToken, got)
	}

	worker := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/stream", sessionToken)
	workerResp, err := worker.ReadResponse()
	if err != nil {
		t.Fatalf("read worker response: %v", err)
	}
	if workerResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 worker status, got %d", workerResp.StatusCode)
	}

	var serverWorker *http3.Stream
	select {
	case serverWorker = <-workerCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server worker stream")
	}

	reqMsg := tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:     "req_1",
			Method: http.MethodGet,
			Path:   "/bench",
		},
	}
	if err := tunnelproto.WriteStreamJSON(serverWorker, reqMsg); err != nil {
		t.Fatalf("server write request: %v", err)
	}

	var gotReq tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(worker, 1<<20, &gotReq); err != nil {
		t.Fatalf("client read request: %v", err)
	}
	if gotReq.Kind != tunnelproto.KindRequest || gotReq.Request == nil || gotReq.Request.ID != "req_1" {
		t.Fatalf("unexpected request message: %+v", gotReq)
	}

	respMsg := tunnelproto.Message{
		Kind: tunnelproto.KindResponse,
		Response: &tunnelproto.HTTPResponse{
			ID:     "req_1",
			Status: http.StatusAccepted,
		},
	}
	if err := tunnelproto.WriteStreamJSON(worker, respMsg); err != nil {
		t.Fatalf("client write response: %v", err)
	}

	var gotResp tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(serverWorker, 1<<20, &gotResp); err != nil {
		t.Fatalf("server read response: %v", err)
	}
	if gotResp.Kind != tunnelproto.KindResponse || gotResp.Response == nil || gotResp.Response.Status != http.StatusAccepted {
		t.Fatalf("unexpected response message: %+v", gotResp)
	}
}

func TestHTTP3IntegrationDistinctWorkerStreamsForHTTPAndWS(t *testing.T) {
	t.Parallel()

	const sessionToken = "h3StreamPool_stream_map"
	workerCh := make(chan *http3.Stream, 4)

	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set(h3SessionHeader, sessionToken)
		w.WriteHeader(http.StatusOK)
		_ = streamer.HTTPStream()
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(h3SessionHeader) != sessionToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		workerCh <- streamer.HTTPStream()
	})

	addr, shutdown := startHTTP3IntegrationServer(t, mux)
	defer shutdown()

	_, clientConn, closeClient := newHTTP3IntegrationClient(t, addr)
	defer closeClient()

	control := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/control", "")
	if _, err := control.ReadResponse(); err != nil {
		t.Fatalf("read control response: %v", err)
	}

	workerA := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/stream", sessionToken)
	if _, err := workerA.ReadResponse(); err != nil {
		t.Fatalf("read worker A response: %v", err)
	}
	workerB := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/stream", sessionToken)
	if _, err := workerB.ReadResponse(); err != nil {
		t.Fatalf("read worker B response: %v", err)
	}

	var serverA, serverB *http3.Stream
	select {
	case serverA = <-workerCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker A")
	}
	select {
	case serverB = <-workerCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for worker B")
	}

	if serverA.StreamID() == serverB.StreamID() {
		t.Fatal("expected distinct HTTP/3 worker streams")
	}

	if err := tunnelproto.WriteStreamJSON(serverA, tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:     "req_http",
			Method: http.MethodGet,
			Path:   "/hello",
		},
	}); err != nil {
		t.Fatalf("server write request: %v", err)
	}
	if err := tunnelproto.WriteStreamJSON(serverB, tunnelproto.Message{
		Kind: tunnelproto.KindWSOpen,
		WSOpen: &tunnelproto.WSOpen{
			ID:     "ws_1",
			Method: http.MethodGet,
			Path:   "/ws",
		},
	}); err != nil {
		t.Fatalf("server write ws_open: %v", err)
	}

	var (
		gotHTTP bool
		gotWS   bool
		mu      sync.Mutex
	)
	readAndRespond := func(clientStream *http3.RequestStream) {
		var msg tunnelproto.Message
		if err := tunnelproto.ReadStreamMessage(clientStream, 1<<20, &msg); err != nil {
			t.Fatalf("client read stream message: %v", err)
		}
		switch msg.Kind {
		case tunnelproto.KindRequest:
			mu.Lock()
			gotHTTP = true
			mu.Unlock()
			_ = tunnelproto.WriteStreamJSON(clientStream, tunnelproto.Message{
				Kind: tunnelproto.KindResponse,
				Response: &tunnelproto.HTTPResponse{
					ID:     msg.Request.ID,
					Status: http.StatusOK,
				},
			})
		case tunnelproto.KindWSOpen:
			mu.Lock()
			gotWS = true
			mu.Unlock()
			_ = tunnelproto.WriteStreamJSON(clientStream, tunnelproto.Message{
				Kind: tunnelproto.KindWSOpenAck,
				WSOpenAck: &tunnelproto.WSOpenAck{
					ID:     msg.WSOpen.ID,
					OK:     true,
					Status: http.StatusSwitchingProtocols,
				},
			})
		default:
			t.Fatalf("unexpected stream message kind: %s", msg.Kind)
		}
	}

	readAndRespond(workerA)
	readAndRespond(workerB)

	var gotResp tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(serverA, 1<<20, &gotResp); err != nil {
		t.Fatalf("server read http response: %v", err)
	}
	if gotResp.Kind != tunnelproto.KindResponse {
		t.Fatalf("unexpected http response kind: %s", gotResp.Kind)
	}

	var gotAck tunnelproto.Message
	if err := tunnelproto.ReadStreamMessage(serverB, 1<<20, &gotAck); err != nil {
		t.Fatalf("server read ws ack: %v", err)
	}
	if gotAck.Kind != tunnelproto.KindWSOpenAck {
		t.Fatalf("unexpected ws ack kind: %s", gotAck.Kind)
	}

	mu.Lock()
	defer mu.Unlock()
	if !gotHTTP || !gotWS {
		t.Fatalf("expected both HTTP and WS flows, gotHTTP=%v gotWS=%v", gotHTTP, gotWS)
	}
}

func startHTTP3IntegrationServer(t testing.TB, handler http.Handler) (string, func()) {
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
		err := server.Serve(conn)
		if err != nil {
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

func newHTTP3IntegrationClient(t testing.TB, addr string) (*quic.Conn, *http3.ClientConn, func()) {
	t.Helper()
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	}
	quicConn, err := quic.DialAddr(context.Background(), addr, tlsConf, nil)
	if err != nil {
		t.Fatalf("dial quic: %v", err)
	}
	transport := &http3.Transport{TLSClientConfig: tlsConf}
	clientConn := transport.NewClientConn(quicConn)
	return quicConn, clientConn, func() {
		_ = transport.Close()
		_ = quicConn.CloseWithError(0, "")
	}
}

func openHTTP3RequestStream(t testing.TB, clientConn *http3.ClientConn, rawURL, sessionToken string) *http3.RequestStream {
	t.Helper()

	stream, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatalf("open request stream: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if sessionToken != "" {
		req.Header.Set(h3SessionHeader, sessionToken)
	}
	if err := stream.SendRequestHeader(req); err != nil {
		t.Fatalf("send request header: %v", err)
	}
	return stream
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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/server"
	"github.com/koltyakov/expose/internal/serviceapi"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

type endToEndTunnel struct {
	client *http.Client
	url    string
}

// This starts the production server, registration handler, tunnel runtime, WAF,
// and local HTTP transport. TLS verification is disabled only for the generated
// loopback certificate; both the public and tunnel connections are encrypted.
func newEndToEndTunnel(t testing.TB, transport string, upstreamHandler http.Handler, timeout time.Duration) *endToEndTunnel {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ready" {
			_, _ = io.WriteString(w, "ready")
			return
		}
		upstreamHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	base, _ := http.NewRequest(http.MethodGet, upstream.URL, nil)
	port, _ := strconv.Atoi(base.URL.Port())
	dir := t.TempDir()
	store, err := sqlite.Open(filepath.Join(dir, "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateAPIKeyWithLimit(t.Context(), "e2e", auth.HashAPIKey("e2e-key", ""), -1); err != nil {
		t.Fatal(err)
	}
	cert := selfSignedCertForLoopback(t)
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	addr := endToEndListenAddress(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(config.ServerConfig{
		ListenHTTPS: addr, ListenHTTP: "127.0.0.1:0", BaseDomain: "example.com",
		TLSMode: "auto", TLSCertFile: certPath, TLSKeyFile: keyPath, CertCacheDir: dir,
		RequestTimeout: timeout, HTTPSWriteTimeout: timeout, MaxBodyBytes: 10 << 20,
		ConnectTokenTTL: time.Minute, ClientPingTimeout: time.Minute,
		HeartbeatCheckInterval: time.Minute, CleanupInterval: time.Hour, TunnelRetention: time.Hour,
		ShutdownDrainTime: time.Second, ShutdownWaitTime: time.Second,
		WAFEnabled: true, WAFBodyInspectLimit: 16 << 10,
	}, store, logger, "test")
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- srv.Run(serverCtx) }()
	t.Cleanup(func() {
		stopServer()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server failed to stop")
		}
	})
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	publicTransport := &http.Transport{TLSClientConfig: tlsConfig.Clone(), ForceAttemptHTTP2: true, MaxIdleConns: 128, MaxIdleConnsPerHost: 128}
	publicClient := &http.Client{Transport: publicTransport, Timeout: 5 * time.Second}
	t.Cleanup(publicTransport.CloseIdleConnections)
	serverURL := "https://" + addr
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := publicClient.Get(serverURL + serviceapi.Health)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	c := New(config.ClientConfig{ServerURL: serverURL, APIKey: "e2e-key", Name: "bench", LocalPort: port, Transport: transport, Timeout: 5 * time.Second, PingInterval: time.Second}, logger)
	c.apiClient.Transport = publicTransport
	c.h3TLSConfig = tlsConfig.Clone()
	t.Cleanup(c.fwdClient.CloseIdleConnections)
	reg, err := c.register(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var rt sessionRuntime
	if transport == "ws" {
		dialURL, token := splitConnectToken(reg.WSURL, reg)
		dialer := websocket.Dialer{TLSClientConfig: tlsConfig.Clone(), HandshakeTimeout: 5 * time.Second, ReadBufferSize: tunnelWSBufferSize, WriteBufferSize: tunnelWSWriteBufferSize, WriteBufferPool: wsWriteBufferPool}
		conn, _, err := dialer.DialContext(t.Context(), dialURL, connectAuthHeader(token))
		if err != nil {
			t.Fatal(err)
		}
		rt, err = newClientSessionRuntimeFromConn(c, t.Context(), base.URL, sessionTransportConn{
			transport: tunneltransport.NewWebSocketTransport(conn),
			writer:    tunneltransport.NewWebSocketWritePump(conn, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
			name:      "ws", protocol: "ws_v1",
		})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		rt, err = newSessionRuntime(c, t.Context(), base.URL, reg)
		if err != nil {
			t.Fatal(err)
		}
	}
	runtimeDone := make(chan struct{})
	go func() { defer close(runtimeDone); _ = rt.run() }()
	t.Cleanup(func() { rt.close(); <-runtimeDone })
	h := &endToEndTunnel{client: publicClient, url: serverURL}
	deadline = time.Now().Add(5 * time.Second)
	for {
		resp, err := h.get(t.Context(), "/ready")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return h
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel did not become ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func endToEndListenAddress(t testing.TB) string {
	t.Helper()
	// TCP and UDP ephemeral ports are allocated independently. Check both so
	// another package's QUIC fixture cannot already own our HTTPS port on UDP.
	for range 100 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		packet, err := net.ListenPacket("udp", addr)
		_ = listener.Close()
		if err == nil {
			_ = packet.Close()
			return addr
		}
	}
	t.Fatal("could not find a free TCP/UDP listen address")
	return ""
}

func (h *endToEndTunnel) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.url+path, nil)
	if err != nil {
		return nil, err
	}
	req.Host = "bench.example.com"
	return h.client.Do(req)
}

func TestTunnelEndToEndActiveStreamOutlivesTimeout(t *testing.T) {
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				for range 24 {
					_, _ = io.WriteString(w, "data: heartbeat\n\n")
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(25 * time.Millisecond):
					}
				}
			}), 200*time.Millisecond)
			resp, err := h.get(t.Context(), "/events")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil || resp.StatusCode != http.StatusOK || string(body) != strings.Repeat("data: heartbeat\n\n", 24) {
				t.Fatalf("stream failed: status=%d bytes=%d err=%v", resp.StatusCode, len(body), err)
			}
		})
	}
}

func BenchmarkTunnelEndToEnd(b *testing.B) {
	for _, transport := range []string{"ws", "quic"} {
		for _, size := range []int{8 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%dKiB", transport, size>>10), func(b *testing.B) {
				payload := make([]byte, size)
				h := newEndToEndTunnel(b, transport, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("Content-Length", strconv.Itoa(size))
					_, _ = w.Write(payload)
				}), 5*time.Second)
				const samples = 8192
				latencies := make([]atomic.Int64, samples)
				var count atomic.Uint64
				stopSampling := sampleEndToEndHeap(b)
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						started := time.Now()
						resp, err := h.get(b.Context(), "/bench")
						if err != nil {
							b.Error(err)
							return
						}
						n, err := io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						if err != nil || resp.StatusCode != http.StatusOK || n != int64(size) {
							b.Errorf("response status=%d bytes=%d err=%v", resp.StatusCode, n, err)
							return
						}
						i := count.Add(1) - 1
						latencies[i%samples].Store(time.Since(started).Nanoseconds())
					}
				})
				b.StopTimer()
				stopSampling()
				values := make([]int64, min(count.Load(), samples))
				for i := range values {
					values[i] = latencies[i].Load()
				}
				slices.Sort(values)
				if len(values) > 0 {
					b.ReportMetric(float64(values[(len(values)-1)*95/100])/1e6, "p95_ms")
					b.ReportMetric(float64(values[(len(values)-1)*99/100])/1e6, "p99_ms")
				}
			})
		}
	}
}

// Heap sampling is opt-in because runtime.ReadMemStats perturbs latency. It
// measures both endpoints in this process, not RSS or per-request live memory.
func sampleEndToEndHeap(b *testing.B) func() {
	if os.Getenv("EXPOSE_E2E_SAMPLE_HEAP") != "true" {
		return func() {}
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	baseline, peak := stats.HeapAlloc, stats.HeapAlloc
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				runtime.ReadMemStats(&stats)
				peak = max(peak, stats.HeapAlloc)
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		b.ReportMetric(float64(peak-baseline), "peak_heap_delta_B")
	}
}

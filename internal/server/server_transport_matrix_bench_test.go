package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

const (
	benchTransportResponseSize   = 32 * 1024
	benchH3WorkerCountFloor      = 2
	benchH3WorkerCountCeiling    = 64
	benchRequesterCountCeiling   = 100
	benchHTTPResponseStatus      = http.StatusOK
	benchHTTPResponseContentType = "application/octet-stream"
	benchWSHandshakeTimeout      = 10 * time.Second
)

type transportMatrixBenchHarness struct {
	publicURL string
	hosts     []string
	client    *http.Client
	cleanup   func()
}

type transportMatrixBenchCase struct {
	tunnels           int
	requestsPerTunnel int
}

var defaultTransportMatrixBenchCases = []transportMatrixBenchCase{
	{tunnels: 25, requestsPerTunnel: 10},
	{tunnels: 50, requestsPerTunnel: 10},
}

const transportMatrixBenchCasesEnv = "EXPOSE_TRANSPORT_MATRIX_CASES"

var transportMatrixBenchScenarioSeparators = func(r rune) bool {
	return r == ',' || r == ';'
}

func BenchmarkPublicHTTPRoundTripTransportMatrix(b *testing.B) {
	for _, tc := range transportMatrixBenchCases(b) {
		totalRequests := benchTotalRequests(tc.tunnels, tc.requestsPerTunnel)
		requesters := benchConcurrentRequesters(tc.tunnels, totalRequests)
		for _, transportName := range []string{"ws", "quic"} {
			name := fmt.Sprintf(
				"%s_tunnels_%d_requests_per_tunnel_%d",
				transportName,
				tc.tunnels,
				tc.requestsPerTunnel,
			)
			b.Run(name, func(b *testing.B) {
				h := newTransportMatrixBenchHarness(b, transportName, tc.tunnels, requesters, benchTransportResponseSize)
				defer h.close()

				h.warmup(b)

				b.ReportAllocs()
				b.SetBytes(int64(benchTransportResponseSize * totalRequests))
				b.ReportMetric(float64(tc.tunnels), "tunnels")
				b.ReportMetric(float64(tc.requestsPerTunnel), "requests_per_tunnel")
				b.ReportMetric(float64(totalRequests), "total_requests")
				b.ReportMetric(float64(requesters), "requesters")
				if transportName == "quic" {
					b.ReportMetric(float64(benchWorkersPerTunnel(tc.tunnels, requesters)), "workers_per_tunnel")
				}

				h.runSweeps(b, totalRequests, requesters)
			})
		}
	}
}

func transportMatrixBenchCases(b *testing.B) []transportMatrixBenchCase {
	b.Helper()

	raw := strings.TrimSpace(os.Getenv(transportMatrixBenchCasesEnv))
	if raw == "" {
		return defaultTransportMatrixBenchCases
	}

	parts := strings.FieldsFunc(raw, transportMatrixBenchScenarioSeparators)
	cases := make([]transportMatrixBenchCase, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		dims := strings.SplitN(strings.ToLower(part), "x", 2)
		if len(dims) != 2 {
			b.Fatalf("invalid %s value %q: expected <tunnels>x<requests-per-tunnel>", transportMatrixBenchCasesEnv, part)
		}
		tunnels, err := strconv.Atoi(strings.TrimSpace(dims[0]))
		if err != nil || tunnels <= 0 {
			b.Fatalf("invalid tunnel count in %s value %q", transportMatrixBenchCasesEnv, part)
		}
		requestsPerTunnel, err := strconv.Atoi(strings.TrimSpace(dims[1]))
		if err != nil || requestsPerTunnel <= 0 {
			b.Fatalf("invalid requests-per-tunnel in %s value %q", transportMatrixBenchCasesEnv, part)
		}
		cases = append(cases, transportMatrixBenchCase{
			tunnels:           tunnels,
			requestsPerTunnel: requestsPerTunnel,
		})
	}
	if len(cases) == 0 {
		b.Fatalf("%s did not contain any benchmark cases", transportMatrixBenchCasesEnv)
	}
	return cases
}

func newTransportMatrixBenchHarness(
	b *testing.B,
	transportName string,
	tunnels, requesters, responseSize int,
) *transportMatrixBenchHarness {
	b.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &Server{
		cfg: config.ServerConfig{
			RequestTimeout:      5 * time.Second,
			MaxPendingPerTunnel: max(512, requesters*2),
		},
		log: logger,
		hub: &hub{
			sessions: make(map[string]*session, tunnels),
		},
		routes: routeCache{
			entries:       make(map[string]routeCacheEntry, tunnels),
			hostsByTunnel: make(map[string]map[string]struct{}, tunnels),
			ttl:           time.Minute,
		},
	}

	hosts := make([]string, tunnels)
	for i := range tunnels {
		hosts[i] = fmt.Sprintf("bench-%03d.example.test", i+1)
	}

	var cleanupFns []func()
	switch transportName {
	case "ws":
		setupBenchmarkWSSessions(b, srv, hosts, responseSize, &cleanupFns)
	case "quic":
		setupBenchmarkQUICSessions(b, srv, hosts, requesters, responseSize, &cleanupFns)
	default:
		b.Fatalf("unsupported transport %q", transportName)
	}

	publicSrv := httptest.NewServer(http.HandlerFunc(srv.handlePublic))
	cleanupFns = append(cleanupFns, publicSrv.Close)

	transport := &http.Transport{
		MaxIdleConns:        max(256, requesters*2),
		MaxIdleConnsPerHost: max(256, requesters*2),
		MaxConnsPerHost:     max(256, requesters*2),
		IdleConnTimeout:     90 * time.Second,
	}
	cleanupFns = append(cleanupFns, transport.CloseIdleConnections)

	return &transportMatrixBenchHarness{
		publicURL: publicSrv.URL,
		hosts:     hosts,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		cleanup: func() {
			for i := len(cleanupFns) - 1; i >= 0; i-- {
				cleanupFns[i]()
			}
		},
	}
}

func (h *transportMatrixBenchHarness) close() {
	if h != nil && h.cleanup != nil {
		h.cleanup()
	}
}

func (h *transportMatrixBenchHarness) warmup(b *testing.B) {
	b.Helper()
	warmups := min(4, len(h.hosts))
	for i := range warmups {
		if err := h.doRequest(h.hosts[i]); err != nil {
			b.Fatal(err)
		}
	}
}

func (h *transportMatrixBenchHarness) runSweeps(b *testing.B, totalRequests, requesters int) {
	b.Helper()

	for b.Loop() {
		if err := h.runSweep(totalRequests, requesters); err != nil {
			b.StopTimer()
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func (h *transportMatrixBenchHarness) runSweep(totalRequests, requesters int) error {
	var (
		nextOp  atomic.Uint64
		failed  atomic.Bool
		firstMu sync.Mutex
		first   error
		wg      sync.WaitGroup
		start   = make(chan struct{})
	)

	if totalRequests <= 0 {
		totalRequests = 1
	}
	if requesters <= 0 {
		requesters = 1
	}

	recordErr := func(err error) {
		if err == nil || !failed.CompareAndSwap(false, true) {
			return
		}
		firstMu.Lock()
		first = err
		firstMu.Unlock()
	}

	for range requesters {
		wg.Go(func() {
			<-start
			for {
				if failed.Load() {
					return
				}
				op := int(nextOp.Add(1)) - 1
				if op >= totalRequests {
					return
				}
				host := h.hosts[op%len(h.hosts)]
				if err := h.doRequest(host); err != nil {
					recordErr(err)
					return
				}
			}
		})
	}

	close(start)
	wg.Wait()

	firstMu.Lock()
	defer firstMu.Unlock()
	if first != nil {
		return first
	}
	return nil
}

func (h *transportMatrixBenchHarness) doRequest(host string) error {
	var lastErr error
	for range 3 {
		req, err := http.NewRequest(http.MethodGet, h.publicURL+"/bench", nil)
		if err != nil {
			return fmt.Errorf("create benchmark request: %w", err)
		}
		req.Host = host

		resp, err := h.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("perform benchmark request: %w", err)
			continue
		}
		func() {
			defer func() { _ = resp.Body.Close() }()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				lastErr = fmt.Errorf("drain benchmark response: %w", err)
				return
			}
			if resp.StatusCode != benchHTTPResponseStatus {
				lastErr = fmt.Errorf("unexpected benchmark status: %d", resp.StatusCode)
				return
			}
			lastErr = nil
		}()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

func setupBenchmarkWSSessions(
	b *testing.B,
	srv *Server,
	hosts []string,
	responseSize int,
	cleanupFns *[]func(),
) {
	b.Helper()

	payload := makeBenchmarkPayload(responseSize)
	accepted := make(chan *websocket.Conn, len(hosts))
	wsPeer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		accepted <- conn
	}))
	*cleanupFns = append(*cleanupFns, wsPeer.Close)

	dialer := websocket.Dialer{
		HandshakeTimeout: benchWSHandshakeTimeout,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		},
	}
	target := "wss" + strings.TrimPrefix(wsPeer.URL, "https")
	var pendingResponses atomic.Int64

	for i, host := range hosts {
		tunnelID := fmt.Sprintf("t-ws-%03d", i+1)

		clientConn, _, err := dialer.Dial(target, nil)
		if err != nil {
			b.Fatalf("dial benchmark ws peer: %v", err)
		}

		var serverConn *websocket.Conn
		select {
		case serverConn = <-accepted:
		case <-time.After(5 * time.Second):
			b.Fatal("timed out waiting for benchmark ws session")
		}

		sess := &session{
			tunnelID:      tunnelID,
			conn:          serverConn,
			transport:     tunneltransport.NewWebSocketTransport(serverConn),
			writer:        tunneltransport.NewWebSocketWritePump(serverConn, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
			transportName: "ws",
			pending:       make(map[string]*pendingRequest),
			wsPending:     make(map[string]chan tunnelproto.Message),
		}
		sess.touch(time.Now())
		srv.hub.sessions[tunnelID] = sess
		route := domain.TunnelRoute{
			Domain: domain.Domain{ID: fmt.Sprintf("d-ws-%03d", i+1), Hostname: host},
			Tunnel: domain.Tunnel{ID: tunnelID, State: domain.TunnelStateConnected},
		}
		srv.routes.set(host, route)
		srv.liveRoutes.upsert(route)
		srv.liveRoutes.attachSession(tunnelID, sess)

		go runBenchmarkSessionReadLoop(sess)
		go runBenchmarkWSResponder(clientConn, payload, &pendingResponses)

		*cleanupFns = append(*cleanupFns, func() {
			_ = clientConn.Close()
		})
		*cleanupFns = append(*cleanupFns, func() {
			if sess.writer != nil {
				sess.writer.Close()
			}
		})
		*cleanupFns = append(*cleanupFns, func() {
			_ = sess.conn.Close()
		})
	}

	*cleanupFns = append(*cleanupFns, func() {
		deadline := time.Now().Add(2 * time.Second)
		for pendingResponses.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func setupBenchmarkQUICSessions(
	b *testing.B,
	srv *Server,
	hosts []string,
	requesters int,
	responseSize int,
	cleanupFns *[]func(),
) {
	b.Helper()

	payload := makeBenchmarkPayload(responseSize)
	workersPerTunnel := benchWorkersPerTunnel(len(hosts), requesters)

	type workerRegistration struct {
		tunnelID string
		stream   *http3.Stream
	}

	registrations := make(chan workerRegistration, len(hosts)*workersPerTunnel)
	mux := http.NewServeMux()
	mux.HandleFunc("/worker", func(w http.ResponseWriter, r *http.Request) {
		tunnelID := strings.TrimSpace(r.Header.Get("X-Bench-Tunnel-ID"))
		if tunnelID == "" {
			http.Error(w, "missing tunnel id", http.StatusBadRequest)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "http3 stream takeover unavailable", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		registrations <- workerRegistration{tunnelID: tunnelID, stream: streamer.HTTPStream()}
	})

	addr, shutdown := startHTTP3IntegrationServer(b, mux)
	*cleanupFns = append(*cleanupFns, shutdown)

	for i, host := range hosts {
		tunnelID := fmt.Sprintf("t-quic-%03d", i+1)
		_, clientConn, closeClient := newHTTP3IntegrationClient(b, addr)
		*cleanupFns = append(*cleanupFns, closeClient)

		sess := &session{
			tunnelID:      tunnelID,
			transportName: "quic",
			h3StreamV2:    true,
			h3StreamPool:  newH3StreamPool(workersPerTunnel * 2),
			pending:       make(map[string]*pendingRequest),
			wsPending:     make(map[string]chan tunnelproto.Message),
		}
		sess.touch(time.Now())
		srv.hub.sessions[tunnelID] = sess
		route := domain.TunnelRoute{
			Domain: domain.Domain{ID: fmt.Sprintf("d-quic-%03d", i+1), Hostname: host},
			Tunnel: domain.Tunnel{ID: tunnelID, State: domain.TunnelStateConnected},
		}
		srv.routes.set(host, route)
		srv.liveRoutes.upsert(route)

		for range workersPerTunnel {
			stream := openBenchmarkH3WorkerStream(b, clientConn, "https://"+addr+"/worker", tunnelID)

			var reg workerRegistration
			select {
			case reg = <-registrations:
			case <-time.After(5 * time.Second):
				b.Fatalf("timed out waiting for benchmark h3 worker stream for %s", tunnelID)
			}
			if reg.tunnelID != tunnelID {
				b.Fatalf("benchmark h3 worker mismatch: got %s want %s", reg.tunnelID, tunnelID)
			}
			if !sess.addH3Worker(reg.stream) {
				b.Fatalf("failed to add benchmark h3 worker stream for %s", tunnelID)
			}

			go runBenchmarkH3WorkerResponder(stream, payload)
		}

		*cleanupFns = append(*cleanupFns, sess.closeH3StreamPool)
	}
}

func runBenchmarkWSResponder(conn *websocket.Conn, payload []byte, pendingResponses *atomic.Int64) {
	var writeMu sync.Mutex

	writeResponse := func(msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
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

	for {
		var msg tunnelproto.Message
		if err := tunnelproto.ReadWSMessage(conn, &msg); err != nil {
			return
		}

		switch msg.Kind {
		case tunnelproto.KindPing:
			_ = writeResponse(tunnelproto.Message{Kind: tunnelproto.KindPong})
		case tunnelproto.KindRequest:
			if msg.Request == nil {
				continue
			}
			pendingResponses.Add(1)
			go func(reqID string) {
				defer pendingResponses.Add(-1)
				resp := tunnelproto.Message{
					Kind: tunnelproto.KindResponse,
					Response: &tunnelproto.HTTPResponse{
						ID:      reqID,
						Status:  benchHTTPResponseStatus,
						Headers: map[string][]string{"Content-Type": {benchHTTPResponseContentType}},
						Body:    payload,
					},
				}
				_ = writeResponse(resp)
			}(msg.Request.ID)
		case tunnelproto.KindReqCancel:
		}
	}
}

func runBenchmarkH3WorkerResponder(stream *http3.RequestStream, payload []byte) {
	for {
		msg, err := readBenchmarkH3RequestStreamMessage(stream)
		if err != nil {
			return
		}

		switch msg.Kind {
		case tunnelproto.KindPing:
			if err := tunnelproto.WriteStreamJSONV2(stream, tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil {
				return
			}
		case tunnelproto.KindRequest:
			if msg.Request == nil {
				continue
			}
			resp := tunnelproto.Message{
				Kind: tunnelproto.KindResponse,
				Response: &tunnelproto.HTTPResponse{
					ID:      msg.Request.ID,
					Status:  benchHTTPResponseStatus,
					Headers: map[string][]string{"Content-Type": {benchHTTPResponseContentType}},
					Body:    payload,
				},
			}
			if err := tunnelproto.WriteStreamJSONV2(stream, resp); err != nil {
				return
			}
		case tunnelproto.KindReqCancel:
		}
	}
}

func openBenchmarkH3WorkerStream(
	b *testing.B,
	clientConn *http3.ClientConn,
	rawURL, tunnelID string,
) *http3.RequestStream {
	b.Helper()

	stream, err := clientConn.OpenRequestStream(context.Background())
	if err != nil {
		b.Fatalf("open benchmark h3 worker request stream: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, nil)
	if err != nil {
		b.Fatalf("create benchmark h3 worker request: %v", err)
	}
	req.Header.Set("X-Bench-Tunnel-ID", tunnelID)
	if err := stream.SendRequestHeader(req); err != nil {
		b.Fatalf("send benchmark h3 worker request header: %v", err)
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		b.Fatalf("read benchmark h3 worker response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("unexpected benchmark h3 worker status: %d", resp.StatusCode)
	}
	return stream
}

func readBenchmarkH3RequestStreamMessage(stream *http3.RequestStream) (tunnelproto.Message, error) {
	var msg tunnelproto.Message
	if stream == nil {
		return msg, io.EOF
	}
	if err := tunnelproto.ReadStreamMessageV2(stream, minWSReadLimit*2, &msg); err != nil {
		return tunnelproto.Message{}, err
	}
	return msg, nil
}

func benchWorkersPerTunnel(tunnels, requesters int) int {
	if tunnels <= 0 {
		return benchH3WorkerCountFloor
	}
	workers := (requesters+tunnels-1)/tunnels + 1
	if workers < benchH3WorkerCountFloor {
		return benchH3WorkerCountFloor
	}
	if workers > benchH3WorkerCountCeiling {
		return benchH3WorkerCountCeiling
	}
	return workers
}

func benchTotalRequests(tunnels, requestsPerTunnel int) int {
	if tunnels <= 0 {
		tunnels = 1
	}
	if requestsPerTunnel <= 0 {
		requestsPerTunnel = 1
	}
	return tunnels * requestsPerTunnel
}

func benchConcurrentRequesters(tunnels, totalRequests int) int {
	if tunnels <= 0 {
		tunnels = 1
	}
	requesters := (tunnels + 1) / 2
	if requesters < 8 {
		requesters = min(8, totalRequests)
	}
	if totalRequests < requesters {
		requesters = totalRequests
	}
	// Keep loopback benchmark reruns stable at higher request counts.
	if requesters > benchRequesterCountCeiling {
		requesters = benchRequesterCountCeiling
	}
	return requesters
}

func makeBenchmarkPayload(size int) []byte {
	if size <= 0 {
		return nil
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return payload
}

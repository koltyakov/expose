package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
	"github.com/koltyakov/expose/internal/waf"
)

func BenchmarkRouteCacheGetHit(b *testing.B) {
	cache := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}
	host := "bench.example.com"
	cache.entries[host] = routeCacheEntry{
		route:             domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t-bench"}},
		found:             true,
		expiresAtUnixNano: time.Now().Add(24 * time.Hour).UnixNano(),
	}
	cache.hostsByTunnel["t-bench"] = map[string]struct{}{host: {}}

	b.ReportAllocs()
	for b.Loop() {
		if _, ok := cache.get(host); !ok {
			b.Fatal("expected cache hit")
		}
	}
}

func BenchmarkRouteCacheDeleteByTunnelID(b *testing.B) {
	const hostsPerTunnel = 2048

	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		cache := routeCache{
			entries:       make(map[string]routeCacheEntry, hostsPerTunnel),
			hostsByTunnel: make(map[string]map[string]struct{}, 1),
		}
		cache.hostsByTunnel["t-bench"] = make(map[string]struct{}, hostsPerTunnel)
		expiresAt := time.Now().Add(24 * time.Hour).UnixNano()
		for n := range hostsPerTunnel {
			host := fmt.Sprintf("h-%d.example.com", n)
			cache.entries[host] = routeCacheEntry{
				route:             domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t-bench"}},
				found:             true,
				expiresAtUnixNano: expiresAt,
			}
			cache.hostsByTunnel["t-bench"][host] = struct{}{}
		}
		b.StartTimer()

		cache.deleteByTunnelID("t-bench")
	}
}

func BenchmarkSessionWSPendingSendBuffered(b *testing.B) {
	stream := newWSStream(1)
	sess := &session{
		wsPending: map[string]*wsStream{
			"stream-1": stream,
		},
	}
	msg := tunnelproto.Message{
		Kind:   tunnelproto.KindWSData,
		WSData: &tunnelproto.WSData{ID: "stream-1", MessageType: 1, DataB64: "Yg=="},
	}

	b.ReportAllocs()
	for b.Loop() {
		if ok := sess.wsPendingSend("stream-1", msg, 0); !ok {
			b.Fatal("expected ws pending send to succeed")
		}
		<-stream.ch
	}
}

func BenchmarkQueueDomainTouchDeduplicate(b *testing.B) {
	srv := &Server{
		domainTouches: make(chan string, 1),
		domainTouched: make(map[string]struct{}),
	}

	b.ReportAllocs()
	for b.Loop() {
		srv.queueDomainTouch("d-bench")
		srv.queueDomainTouch("d-bench")
		domainID := <-srv.domainTouches
		srv.completeDomainTouch(domainID)
	}
}

func BenchmarkPublicHTTPRoundTripSingleTunnel(b *testing.B) {
	h := newPublicTunnelBenchHarness(b, 32*1024, 0)
	h.doRequest(b)

	b.ReportAllocs()
	b.SetBytes(32 * 1024)
	for b.Loop() {
		h.doRequest(b)
	}
}

func BenchmarkPublicHTTPRoundTripParallel(b *testing.B) {
	h := newPublicTunnelBenchHarness(b, 8*1024, 0)
	h.doRequest(b)

	b.ReportAllocs()
	b.SetBytes(8 * 1024)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			h.doRequest(b)
		}
	})
}

func BenchmarkPublicHTTPRoundTripStreamedResponse(b *testing.B) {
	payloadSize := streamingThreshold + (2 * streamingChunkSize)
	h := newPublicTunnelBenchHarness(b, payloadSize, 0)
	h.doRequest(b)

	b.ReportAllocs()
	b.SetBytes(int64(payloadSize))
	for b.Loop() {
		h.doRequest(b)
	}
}

func BenchmarkPublicHTTPRoundTripWAF(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		b.Run(name, func(b *testing.B) {
			h := newPublicTunnelBenchHarnessWithWAF(b, 8*1024, 0, enabled)
			h.doRequest(b)

			b.ReportAllocs()
			b.SetBytes(8 * 1024)
			for b.Loop() {
				h.doRequest(b)
			}
		})
	}
}

type publicTunnelBenchHarness struct {
	publicURL string
	host      string
	client    *http.Client
}

func newPublicTunnelBenchHarness(b *testing.B, responseSize int, responseDelay time.Duration) *publicTunnelBenchHarness {
	return newPublicTunnelBenchHarnessWithWAF(b, responseSize, responseDelay, false)
}

func newPublicTunnelBenchHarnessWithWAF(b *testing.B, responseSize int, responseDelay time.Duration, wafEnabled bool) *publicTunnelBenchHarness {
	b.Helper()

	const (
		host     = "bench.example.com"
		tunnelID = "t-bench"
	)

	payload := make([]byte, responseSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var writeMu sync.Mutex
	var pendingResponses atomic.Int64

	writeJSON := func(conn *websocket.Conn, msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
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

	writeRespBodyChunk := func(conn *websocket.Conn, id string, chunk []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
		writer, err := conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			return err
		}
		if err := tunnelproto.WriteBinaryFrame(writer, tunnelproto.BinaryFrameRespBody, id, 0, chunk); err != nil {
			_ = writer.Close()
			return err
		}
		return writer.Close()
	}

	wsSessCh := make(chan *session, 1)
	wsPeer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wsUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		wsSessCh <- &session{
			tunnelID:  tunnelID,
			conn:      conn,
			writer:    tunneltransport.NewWebSocketWritePump(conn, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
			pending:   make(map[string]*pendingRequest),
			wsPending: make(map[string]*wsStream),
		}
	}))
	b.Cleanup(wsPeer.Close)

	clientConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(wsPeer.URL, "http"), nil)
	if err != nil {
		b.Fatalf("dial benchmark tunnel peer: %v", err)
	}
	b.Cleanup(func() { _ = clientConn.Close() })

	sess := <-wsSessCh
	sess.touch(time.Now())
	b.Cleanup(func() {
		_ = sess.conn.Close()
		if sess.writer != nil {
			sess.writer.Close()
		}
	})
	go runBenchmarkSessionReadLoop(sess)

	go func() {
		for {
			var msg tunnelproto.Message
			if err := tunnelproto.ReadWSMessage(clientConn, &msg); err != nil {
				return
			}
			switch msg.Kind {
			case tunnelproto.KindPing:
				if err := writeJSON(clientConn, tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil {
					return
				}
			case tunnelproto.KindRequest:
				req := msg.Request
				if req == nil {
					continue
				}
				pendingResponses.Add(1)
				go func(reqID string) {
					defer pendingResponses.Add(-1)
					if responseDelay > 0 {
						time.Sleep(responseDelay)
					}

					resp := tunnelproto.Message{
						Kind: tunnelproto.KindResponse,
						Response: &tunnelproto.HTTPResponse{
							ID:      reqID,
							Status:  http.StatusOK,
							Headers: map[string][]string{"Content-Type": {"application/octet-stream"}},
						},
					}
					if len(payload) > streamingThreshold {
						resp.Response.Streamed = true
						if err := writeJSON(clientConn, resp); err != nil {
							return
						}
						for offset := 0; offset < len(payload); offset += streamingChunkSize {
							end := min(offset+streamingChunkSize, len(payload))
							if err := writeRespBodyChunk(clientConn, reqID, payload[offset:end]); err != nil {
								return
							}
						}
						_ = writeJSON(clientConn, tunnelproto.Message{
							Kind:      tunnelproto.KindRespBodyEnd,
							BodyChunk: &tunnelproto.BodyChunk{ID: reqID},
						})
						return
					}

					resp.Response.Body = payload
					_ = writeJSON(clientConn, resp)
				}(req.ID)
			case tunnelproto.KindReqCancel:
				// The benchmark peer has no cancellable upstream; consume the signal.
			}
		}
	}()

	srv := &Server{
		cfg: config.ServerConfig{
			RequestTimeout:      5 * time.Second,
			MaxPendingPerTunnel: 512,
		},
		log: logger,
		hub: &hub{
			sessions: map[string]*session{
				tunnelID: sess,
			},
		},
		liveRoutes: newLiveRouteIndex(),
		routes: routeCache{
			entries:       make(map[string]routeCacheEntry),
			hostsByTunnel: make(map[string]map[string]struct{}),
			ttl:           time.Minute,
		},
	}
	srv.routes.set(host, domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-bench", Hostname: host},
		Tunnel: domain.Tunnel{ID: tunnelID, State: domain.TunnelStateConnected},
	})
	srv.liveRoutes.upsert(domain.TunnelRoute{
		Domain: domain.Domain{ID: "d-bench", Hostname: host},
		Tunnel: domain.Tunnel{ID: tunnelID, State: domain.TunnelStateConnected},
	})
	srv.liveRoutes.attachSession(tunnelID, sess)

	var publicHandler http.Handler = http.HandlerFunc(srv.handlePublic)
	if wafEnabled {
		publicHandler = waf.NewMiddleware(waf.Config{
			Enabled:           true,
			BodyInspectLimit:  16 * 1024,
			ShouldInspectBody: shouldInspectWAFBody,
		}, logger)(publicHandler)
	}
	publicSrv := httptest.NewServer(publicHandler)
	b.Cleanup(publicSrv.Close)

	transport := &http.Transport{
		MaxIdleConns:        512,
		MaxIdleConnsPerHost: 512,
		MaxConnsPerHost:     512,
		IdleConnTimeout:     90 * time.Second,
	}
	b.Cleanup(transport.CloseIdleConnections)

	b.Cleanup(func() {
		deadline := time.Now().Add(2 * time.Second)
		for pendingResponses.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	})

	return &publicTunnelBenchHarness{
		publicURL: publicSrv.URL,
		host:      host,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

func (h *publicTunnelBenchHarness) doRequest(b *testing.B) {
	b.Helper()

	req, err := http.NewRequest(http.MethodGet, h.publicURL+"/bench", nil)
	if err != nil {
		b.Fatalf("create benchmark request: %v", err)
	}
	req.Host = h.host

	resp, err := h.client.Do(req)
	if err != nil {
		b.Fatalf("perform benchmark request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b.Fatalf("unexpected benchmark status: %d", resp.StatusCode)
	}
}

func runBenchmarkSessionReadLoop(sess *session) {
	for {
		var msg tunnelproto.Message
		if err := tunnelproto.ReadWSMessage(sess.conn, &msg); err != nil {
			return
		}
		sess.touch(time.Now())

		switch msg.Kind {
		case tunnelproto.KindResponse:
			if msg.Response == nil {
				continue
			}
			if msg.Response.Streamed {
				if pending, ok := sess.pendingLoad(msg.Response.ID); ok {
					pending.deliverHeader(msg.Response)
				}
				continue
			}
			if pending, ok := sess.pendingLoadAndDelete(msg.Response.ID); ok {
				sess.releasePending()
				pending.deliverHeader(msg.Response)
				pending.finish()
			}
		case tunnelproto.KindRespBody:
			if msg.BodyChunk == nil {
				continue
			}
			if pending, ok := sess.pendingLoad(msg.BodyChunk.ID); ok {
				bodyCh := pending.ensureBodyCh()
				payload, err := msg.BodyChunk.Payload()
				if err != nil {
					continue
				}
				if !sess.streamSend(bodyCh, payload, streamBodySendTimeout) {
					if pending, deleted := sess.pendingDelete(msg.BodyChunk.ID); deleted {
						sess.releasePending()
						pending.abort()
					}
				}
			}
		case tunnelproto.KindRespBodyEnd:
			if msg.BodyChunk == nil {
				continue
			}
			if pending, ok := sess.pendingLoadAndDelete(msg.BodyChunk.ID); ok {
				sess.releasePending()
				pending.finish()
			}
		}
	}
}

// BenchmarkBypassProxyParallel drives concurrent requests through a reserved
// bypass route and reports how many upstream connections each request opened.
func BenchmarkBypassProxyParallel(b *testing.B) {
	payload := make([]byte, 8*1024)
	var newConns atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()

	_, rawPort, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		b.Fatal(err)
	}
	srv := New(config.ServerConfig{
		BaseDomain: "example.com",
		Bypasses:   []config.ServerBypass{{Subdomain: "app", Port: port, DisableRateLimit: true}},
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "bench")

	newConns.Store(0)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := httptest.NewRequest(http.MethodGet, "https://app.example.com/asset", nil)
			r.RemoteAddr = "203.0.113.7:1234"
			w := httptest.NewRecorder()
			if !srv.serveBypass(w, r, "app.example.com") || w.Code != http.StatusOK || w.Body.Len() != len(payload) {
				b.Errorf("bypass response: status=%d bytes=%d", w.Code, w.Body.Len())
				return
			}
		}
	})
	b.StopTimer()
	b.ReportMetric(float64(newConns.Load())/float64(b.N), "upstream-conns/op")
}

// BenchmarkPublishedSiteGET serves server-hosted publication files through the
// public handler: a small asset, the index, and an SPA route that falls back
// to index.html after its candidate files miss.
func BenchmarkPublishedSiteGET(b *testing.B) {
	ctx := context.Background()
	dir := b.TempDir()
	dbPath := filepath.Join(dir, "sites.db")
	st, err := sqlite.Open(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if _, err := st.CreateAPIKey(ctx, "owner", auth.HashAPIKey("owner", "")); err != nil {
		b.Fatal(err)
	}
	srv := New(config.ServerConfig{BaseDomain: "example.com", DBPath: dbPath}, st, slog.New(slog.NewTextHandler(io.Discard, nil)), "bench")
	srv.authLimiter, srv.regLimiter = nil, nil
	root := filepath.Join(dir, "src")
	files := map[string]string{
		"index.html":    "<html><body>" + strings.Repeat("x", 4096) + "</body></html>",
		"assets/app.js": strings.Repeat("console.log(1);\n", 512),
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			b.Fatal(err)
		}
	}
	var archive bytes.Buffer
	if err := publish.Archive(root, &archive); err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/_expose/v1/sites?domain=bench", bytes.NewReader(archive.Bytes()))
	r.Header.Set("Authorization", "Bearer owner")
	w := httptest.NewRecorder()
	srv.handleSites(w, r)
	if w.Code != http.StatusCreated {
		b.Fatalf("publish: %d %s", w.Code, w.Body.String())
	}

	for _, tc := range []struct{ name, path string }{
		{"asset", "/assets/app.js"},
		{"index", "/"},
		{"spa-route", "/dashboard/settings"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					r := httptest.NewRequest(http.MethodGet, "https://bench.example.com"+tc.path, nil)
					r.RemoteAddr = "192.0.2.1:5678"
					w := httptest.NewRecorder()
					srv.handlePublic(w, r)
					if w.Code != http.StatusOK {
						b.Errorf("GET %s: %d", tc.path, w.Code)
						return
					}
				}
			})
		})
	}
}

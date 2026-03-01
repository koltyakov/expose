package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := cache.get(host); !ok {
			b.Fatal("expected cache hit")
		}
	}
}

func BenchmarkRouteCacheDeleteByTunnelID(b *testing.B) {
	const hostsPerTunnel = 2048

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		cache := routeCache{
			entries:       make(map[string]routeCacheEntry, hostsPerTunnel),
			hostsByTunnel: make(map[string]map[string]struct{}, 1),
		}
		cache.hostsByTunnel["t-bench"] = make(map[string]struct{}, hostsPerTunnel)
		expiresAt := time.Now().Add(24 * time.Hour).UnixNano()
		for n := 0; n < hostsPerTunnel; n++ {
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
	ch := make(chan tunnelproto.Message, 1)
	sess := &session{
		wsPending: map[string]chan tunnelproto.Message{
			"stream-1": ch,
		},
	}
	msg := tunnelproto.Message{
		Kind:   tunnelproto.KindWSData,
		WSData: &tunnelproto.WSData{ID: "stream-1", MessageType: 1, DataB64: "Yg=="},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok := sess.wsPendingSend("stream-1", msg, 0); !ok {
			b.Fatal("expected ws pending send to succeed")
		}
		<-ch
	}
}

func BenchmarkQueueDomainTouchDeduplicate(b *testing.B) {
	srv := &Server{
		domainTouches: make(chan string, 1),
		domainTouched: make(map[string]struct{}),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.doRequest(b)
	}
}

type publicTunnelBenchHarness struct {
	publicURL string
	host      string
	client    *http.Client
}

func newPublicTunnelBenchHarness(b *testing.B, responseSize int, responseDelay time.Duration) *publicTunnelBenchHarness {
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
		return conn.WriteJSON(msg)
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
			writer:    tunnelproto.NewWSWritePump(conn, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
			pending:   make(map[string]chan tunnelproto.Message),
			wsPending: make(map[string]chan tunnelproto.Message),
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

					resp.Response.BodyB64 = tunnelproto.EncodeBody(payload)
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

	publicSrv := httptest.NewServer(http.HandlerFunc(srv.handlePublic))
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
				if ch, ok := sess.pendingLoad(msg.Response.ID); ok {
					select {
					case ch <- msg:
					default:
					}
				}
				continue
			}
			if ch, ok := sess.pendingLoadAndDelete(msg.Response.ID); ok {
				sess.releasePending()
				select {
				case ch <- msg:
				default:
				}
				close(ch)
			}
		case tunnelproto.KindRespBody:
			if msg.BodyChunk == nil {
				continue
			}
			if ch, ok := sess.pendingLoad(msg.BodyChunk.ID); ok {
				if !sess.streamSend(ch, msg, streamBodySendTimeout) {
					if sess.pendingDelete(msg.BodyChunk.ID) {
						sess.releasePending()
						close(ch)
					}
				}
			}
		case tunnelproto.KindRespBodyEnd:
			if msg.BodyChunk == nil {
				continue
			}
			if ch, ok := sess.pendingLoadAndDelete(msg.BodyChunk.ID); ok {
				sess.releasePending()
				select {
				case ch <- msg:
				default:
				}
				close(ch)
			}
		}
	}
}

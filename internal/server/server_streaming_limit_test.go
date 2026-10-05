package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

func TestPublicHTTPStreamsBeyondFormerBodyLimit(t *testing.T) {
	for _, transport := range []string{"ws", "h3-multistream", "h3-multistream-v2"} {
		for _, knownLength := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/known-length=%t", transport, knownLength), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				const size = 16 << 20
				firstChunk := make(chan struct{})
				sess, read, write := newStreamingLimitTestPeer(t, transport)
				srv := New(config.ServerConfig{MaxBodyBytes: 10 << 20, RequestTimeout: 10 * time.Second}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
				const host = "upload.example.test"
				route := domain.TunnelRoute{
					Domain: domain.Domain{ID: "upload-domain", Hostname: host},
					Tunnel: domain.Tunnel{ID: sess.tunnelID, State: domain.TunnelStateConnected},
				}
				srv.hub.sessions[sess.tunnelID] = sess
				srv.routes.set(host, route)
				peerDone := make(chan error, 1)
				go func() { peerDone <- receiveStreamingLimitTestBody(read, write, firstChunk, size) }()
				public := httptest.NewServer(http.HandlerFunc(srv.handlePublic))
				defer public.Close()
				body := &streamingLimitTestReader{ctx: ctx, size: size, firstChunk: firstChunk}
				req, err := http.NewRequestWithContext(ctx, http.MethodPut, public.URL+"/upload", body)
				if err != nil {
					t.Fatal(err)
				}
				req.Host = host
				req.Header.Set("Content-Type", "application/octet-stream")
				if knownLength {
					req.ContentLength = size
				}
				resp, err := public.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = resp.Body.Close() }()
				result, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("streamed upload status=%d, body=%q", resp.StatusCode, result)
				}
				expected := sha256.New()
				if _, err := io.Copy(expected, &streamingLimitTestReader{ctx: ctx, size: size}); err != nil {
					t.Fatal(err)
				}
				if string(result) != hex.EncodeToString(expected.Sum(nil)) {
					t.Fatal("streamed body checksum mismatch")
				}
				select {
				case err := <-peerDone:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if sess.pendingCount.Load() != 0 {
					t.Fatal("completed upload retained pending admission")
				}
			})
		}
	}
}

// The producer cannot generate bytes beyond the first bounded chunk until
// the tunnel peer receives that chunk. Whole-body buffering would deadlock.
type streamingLimitTestReader struct {
	ctx        context.Context
	size       int64
	offset     int64
	firstChunk <-chan struct{}
}

func (r *streamingLimitTestReader) Read(p []byte) (int, error) {
	if r.offset >= r.size {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.size-r.offset)
	if r.firstChunk != nil {
		if r.offset >= streamingThreshold+1 {
			select {
			case <-r.firstChunk:
			case <-r.ctx.Done():
				return 0, r.ctx.Err()
			}
		} else {
			n = min(n, streamingThreshold+1-r.offset)
		}
	}
	for i := range int(n) {
		p[i] = byte((r.offset + int64(i)) % 251)
	}
	r.offset += n
	return int(n), nil
}

func receiveStreamingLimitTestBody(read func() (tunnelproto.Message, error), write func(tunnelproto.Message) error, firstChunk chan struct{}, size int64) error {
	request, err := read()
	if err != nil {
		return err
	}
	if request.Kind != tunnelproto.KindRequest || request.Request == nil || !request.Request.Streamed || len(request.Request.Body) != 0 {
		return fmt.Errorf("expected streamed request envelope")
	}
	hash := sha256.New()
	var received int64
	for {
		msg, err := read()
		if err != nil {
			return err
		}
		switch msg.Kind {
		case tunnelproto.KindReqBody:
			if msg.BodyChunk == nil || msg.BodyChunk.ID != request.Request.ID {
				return fmt.Errorf("invalid body chunk identity")
			}
			payload, err := msg.BodyChunk.Payload()
			if err != nil {
				return err
			}
			if len(payload) == 0 || len(payload) > streamingThreshold+1 {
				tunnelproto.ReleaseBodyChunk(payload)
				return fmt.Errorf("unbounded body chunk: %d bytes", len(payload))
			}
			_, _ = hash.Write(payload)
			tunnelproto.ReleaseBodyChunk(payload)
			if received == 0 {
				close(firstChunk)
			}
			received += int64(len(payload))
		case tunnelproto.KindReqBodyEnd:
			if received != size {
				return fmt.Errorf("received %d bytes, expected %d", received, size)
			}
			return write(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{
				ID: request.Request.ID, Status: http.StatusOK, Body: []byte(hex.EncodeToString(hash.Sum(nil))),
			}})
		default:
			return fmt.Errorf("unexpected streamed message %s", msg.Kind)
		}
	}
}

func newStreamingLimitTestPeer(t *testing.T, transport string) (*session, func() (tunnelproto.Message, error), func(tunnelproto.Message) error) {
	t.Helper()
	sess := &session{tunnelID: "streaming-test", pending: make(map[string]*pendingRequest), transportName: "quic"}
	if transport == "ws" {
		accepted := make(chan *websocket.Conn, 1)
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := wsUpgrader.Upgrade(w, r, nil)
			if err == nil {
				accepted <- conn
			}
		}))
		t.Cleanup(peer.Close)
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(peer.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		sess.conn = <-accepted
		sess.transportName = "ws"
		sess.writer = tunneltransport.NewWebSocketWritePump(sess.conn, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			var msg tunnelproto.Message
			if err := tunnelproto.ReadWSMessage(sess.conn, &msg); err == nil && msg.Response != nil {
				if pending, ok := sess.pendingLoadAndDelete(msg.Response.ID); ok {
					sess.releasePending()
					pending.deliverHeader(msg.Response)
					pending.finish()
				}
			}
		}()
		t.Cleanup(func() {
			_ = sess.conn.Close()
			sess.writer.Close()
			<-readDone
		})
		return sess, func() (tunnelproto.Message, error) {
				var msg tunnelproto.Message
				err := tunnelproto.ReadWSMessage(conn, &msg)
				return msg, err
			}, func(msg tunnelproto.Message) error {
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
	}
	workers := make(chan *http3.Stream, 1)
	addr, shutdown := startHTTP3IntegrationServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		workers <- w.(http3.HTTPStreamer).HTTPStream()
	}))
	t.Cleanup(shutdown)
	_, clientConn, closeClient := newHTTP3IntegrationClient(t, addr)
	t.Cleanup(closeClient)
	stream := openHTTP3RequestStream(t, clientConn, "https://"+addr+"/worker", "")
	if _, err := stream.ReadResponse(); err != nil {
		t.Fatal(err)
	}
	sess.h3StreamV2 = transport == "h3-multistream-v2"
	sess.h3StreamPool = newH3StreamPool(1)
	if !sess.addH3Worker(<-workers) {
		t.Fatal("failed to add HTTP/3 worker")
	}
	t.Cleanup(sess.closeH3StreamPool)
	return sess, func() (tunnelproto.Message, error) {
			var msg tunnelproto.Message
			var err error
			if sess.h3StreamV2 {
				err = tunnelproto.ReadStreamMessageV2(stream, minWSReadLimit, &msg)
			} else {
				err = tunnelproto.ReadStreamMessage(stream, minWSReadLimit, &msg)
			}
			return msg, err
		}, func(msg tunnelproto.Message) error {
			if sess.h3StreamV2 {
				return tunnelproto.WriteStreamJSONV2(stream, msg)
			}
			return tunnelproto.WriteStreamJSON(stream, msg)
		}
}

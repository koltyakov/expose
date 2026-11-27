package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

// readUploadPrefix reads the streamed request envelope and n body bytes.
func readUploadPrefix(read func() (tunnelproto.Message, error), n int) (string, error) {
	msg, err := read()
	if err != nil {
		return "", err
	}
	id := msg.Request.ID
	for got := 0; got < n; {
		chunk, err := read()
		if err != nil {
			return id, err
		}
		if chunk.Kind == tunnelproto.KindReqBody && chunk.BodyChunk != nil {
			payload, _ := chunk.BodyChunk.Payload()
			got += len(payload)
		}
	}
	return id, nil
}

// The peer answers after reading part of an upload the visitor keeps open.
// The response reaches the visitor at once, and a worker whose upload was cut
// short is never reused.
func TestH3PublicEarlyResponseDuringOpenUpload(t *testing.T) {
	const prefix = 32 << 10
	for _, mode := range []string{"h3-multistream", "h3-multistream-v2"} {
		t.Run(mode, func(t *testing.T) {
			sess, read, write := newStreamingLimitTestPeer(t, mode)
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: 10 * time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			peerDone := make(chan error, 1)
			go func() {
				id, err := readUploadPrefix(read, prefix)
				if err == nil {
					err = write(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{
						ID: id, Status: http.StatusRequestEntityTooLarge, Body: []byte("too large"),
					}})
				}
				peerDone <- err
			}()
			pr, pw := io.Pipe()
			defer func() { _ = pw.Close() }()
			go func() { _, _ = pw.Write(bytes.Repeat([]byte("u"), prefix)) }()
			req := httptest.NewRequest(http.MethodPost, "/upload", pr)
			rr := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.proxyPublicHTTPH3MultiStream(rr, req, domain.TunnelRoute{}, sess)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("early response waited for the upload to end")
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			if rr.Code != http.StatusRequestEntityTooLarge || rr.Body.String() != "too large" {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if sess.pendingCount.Load() != 0 || sess.h3StreamPool.idle() != 0 {
				t.Fatal("interrupted upload retained admission or requeued its worker")
			}
			if _, err := read(); err == nil {
				t.Fatal("worker with an interrupted upload was not reset")
			}
		})
	}
}

func TestH3WorkerWithStaleResponseIsRetired(t *testing.T) {
	sess, read, write := newStreamingLimitTestPeer(t, "h3-multistream-v2")
	srv := &Server{cfg: config.ServerConfig{RequestTimeout: time.Second}}
	peerDone := make(chan error, 1)
	go func() {
		_, err := read()
		if err == nil {
			err = write(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{
				ID: "previous", Status: http.StatusOK, Body: []byte("previous response"),
			}})
		}
		peerDone <- err
	}()
	w := httptest.NewRecorder()
	srv.proxyPublicHTTPH3MultiStream(w, httptest.NewRequest(http.MethodGet, "/", nil), domain.TunnelRoute{}, sess)
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusBadGateway || sess.h3StreamPool.idle() != 0 {
		t.Fatalf("stale worker: HTTP %d, %d workers idle", w.Code, sess.h3StreamPool.idle())
	}
}

// A peer that streams its response while it still reads the upload gets the
// whole body, and the worker is reused once both directions completed.
func TestH3PublicFullDuplexUploadCompletesAndRequeues(t *testing.T) {
	for _, mode := range []string{"h3-multistream", "h3-multistream-v2"} {
		t.Run(mode, func(t *testing.T) {
			sess, read, write := newStreamingLimitTestPeer(t, mode)
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: 10 * time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			pr, pw := io.Pipe()
			peerDone := make(chan error, 1)
			var received bytes.Buffer
			go func() {
				peerDone <- func() error {
					msg, err := read()
					if err != nil {
						return err
					}
					id := msg.Request.ID
					// Headers go out before the visitor has sent anything.
					if err := write(tunnelproto.Message{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: id, Status: http.StatusOK, Streamed: true}}); err != nil {
						return err
					}
					for {
						msg, err := read()
						if err != nil {
							return err
						}
						if msg.Kind == tunnelproto.KindReqBodyEnd {
							break
						}
						payload, _ := msg.BodyChunk.Payload()
						received.Write(payload)
						if err := write(tunnelproto.Message{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: id, Data: bytes.ToUpper(payload)}}); err != nil {
							return err
						}
					}
					return write(tunnelproto.Message{Kind: tunnelproto.KindRespBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: id}})
				}()
			}()
			go func() {
				for range 3 {
					_, _ = pw.Write([]byte("abcd"))
					time.Sleep(10 * time.Millisecond)
				}
				_ = pw.Close()
			}()
			rr := httptest.NewRecorder()
			srv.proxyPublicHTTPH3MultiStream(rr, httptest.NewRequest(http.MethodPost, "/echo", pr), domain.TunnelRoute{}, sess)
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			if received.String() != "abcdabcdabcd" || rr.Code != http.StatusOK || rr.Body.String() != "ABCDABCDABCD" {
				t.Fatalf("received=%q status=%d body=%q", received.String(), rr.Code, rr.Body.String())
			}
			if sess.h3StreamPool.idle() != 1 {
				t.Fatal("completed full-duplex worker was not requeued")
			}
		})
	}
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// A visitor leaving mid-upload resets the worker. The upload goroutine is
// still writing; it must be joined before the stream is closed, so the race
// detector sees no Close concurrent with Write.
func TestH3PublicCancelDuringUploadJoinsWriter(t *testing.T) {
	for _, mode := range []string{"h3-multistream", "h3-multistream-v2"} {
		t.Run(mode, func(t *testing.T) {
			sess, read, _ := newStreamingLimitTestPeer(t, mode)
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: 10 * time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req := httptest.NewRequest(http.MethodPost, "/upload", io.NopCloser(endlessReader{})).WithContext(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.proxyPublicHTTPH3MultiStream(httptest.NewRecorder(), req, domain.TunnelRoute{}, sess)
			}()
			if _, err := readUploadPrefix(read, 64<<10); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("canceled upload did not stop")
			}
			if sess.pendingCount.Load() != 0 || sess.h3StreamPool.idle() != 0 {
				t.Fatal("canceled upload retained admission or requeued its worker")
			}
		})
	}
}

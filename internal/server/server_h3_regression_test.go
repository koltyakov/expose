package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestH3PublicTruncatedStreamAborts(t *testing.T) {
	for _, mode := range []string{"h3-multistream", "h3-multistream-v2"} {
		t.Run(mode, func(t *testing.T) {
			sess, read, write := newStreamingLimitTestPeer(t, mode)
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			peerDone := make(chan error, 1)
			go func() {
				req, err := read()
				if err != nil {
					peerDone <- err
					return
				}
				for _, msg := range []tunnelproto.Message{
					{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: req.Request.ID, Status: http.StatusOK, Streamed: true}},
					{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: req.Request.ID, Data: []byte("partial")}},
					{Kind: tunnelproto.KindRespBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: req.Request.ID, Error: "upstream body failed"}},
				} {
					if err := write(msg); err != nil {
						peerDone <- err
						return
					}
				}
				peerDone <- nil
			}()
			rr := httptest.NewRecorder()
			var aborted any
			func() {
				defer func() { aborted = recover() }()
				srv.proxyPublicHTTPH3MultiStream(rr, httptest.NewRequest(http.MethodGet, "/events", nil), domain.TunnelRoute{}, sess)
			}()
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
			if aborted != http.ErrAbortHandler {
				t.Fatalf("truncated response completed normally: panic=%v, body=%q", aborted, rr.Body.String())
			}
			if rr.Body.String() != "partial" {
				t.Fatalf("body=%q", rr.Body.String())
			}
			if sess.pendingCount.Load() != 0 || sess.h3StreamPool.idle() != 0 {
				t.Fatal("failed response retained admission or requeued dirty worker")
			}
		})
	}
}

func TestH3PublicTruncationFailsTransfer(t *testing.T) {
	for _, ingress := range []string{"tcp", "h3"} {
		t.Run(ingress, func(t *testing.T) {
			sess, read, write := newStreamingLimitTestPeer(t, "h3-multistream-v2")
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: 10 * time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			peerDone := make(chan error, 1)
			finish := make(chan struct{})
			var finishOnce sync.Once
			release := func() { finishOnce.Do(func() { close(finish) }) }
			go func() {
				req, err := read()
				if err != nil {
					peerDone <- err
					return
				}
				for _, msg := range []tunnelproto.Message{
					{Kind: tunnelproto.KindResponse, Response: &tunnelproto.HTTPResponse{ID: req.Request.ID, Status: http.StatusOK, Streamed: true}},
					{Kind: tunnelproto.KindRespBody, BodyChunk: &tunnelproto.BodyChunk{ID: req.Request.ID, Data: []byte("partial")}},
					{Kind: tunnelproto.KindRespBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: req.Request.ID, Error: "upstream failed"}},
				} {
					if msg.Kind == tunnelproto.KindRespBodyEnd {
						<-finish // Let the public reader receive headers and bytes first.
					}
					if err := write(msg); err != nil {
						peerDone <- err
						return
					}
				}
				peerDone <- nil
			}()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				srv.proxyPublicHTTPH3MultiStream(w, r, domain.TunnelRoute{}, sess)
			})
			var target string
			var client *http.Client
			if ingress == "tcp" {
				public := httptest.NewServer(handler)
				defer func() { release(); public.Close() }()
				target, client = public.URL, public.Client()
			} else {
				addr, shutdown := startHTTP3IntegrationServer(t, handler)
				defer func() { release(); shutdown() }()
				_, cc, closeClient := newHTTP3IntegrationClient(t, addr)
				defer closeClient()
				target, client = "https://"+addr, &http.Client{Transport: cc}
			}
			defer release()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			first := make([]byte, len("partial"))
			if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "partial" {
				t.Fatalf("initial public bytes=%q, error=%v", first, err)
			}
			release()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Fatalf("truncated %s response ended with clean EOF: %q", ingress, body)
			}
			if len(body) != 0 {
				t.Fatalf("body=%q, error=%v", body, err)
			}
			if ingress == "h3" && resp.ProtoMajor != 3 {
				t.Fatal("did not exercise public HTTP/3")
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestH3PublicDisconnectClosesOnlyActiveWorker(t *testing.T) {
	for _, mode := range []string{"h3-multistream", "h3-multistream-v2"} {
		t.Run(mode, func(t *testing.T) {
			sess, read, _ := newStreamingLimitTestPeer(t, mode)
			srv := &Server{cfg: config.ServerConfig{RequestTimeout: 10 * time.Second}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				srv.proxyPublicHTTPH3MultiStream(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil).WithContext(ctx), domain.TunnelRoute{}, sess)
			}()
			if _, err := read(); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("public disconnect waited for request timeout")
			}
			if sess.pendingCount.Load() != 0 || sess.h3StreamPool.idle() != 0 {
				t.Fatal("canceled request retained admission or reused worker")
			}
			if _, err := read(); err == nil || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("worker not reset: %v", err)
			}
		})
	}
}

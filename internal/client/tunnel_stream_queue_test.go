package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTunnelEndToEndConcurrentSmallStreams(t *testing.T) {
	const streams, chunks, rounds = 16, 64, 3
	payload := func(id string) string {
		var body strings.Builder
		for chunk := range chunks {
			fmt.Fprintf(&body, "data: %s/%02d\n\n", id, chunk)
		}
		return body.String()
	}
	for _, transport := range []string{"ws", "quic"} {
		t.Run(transport, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			ready := make(chan struct{}, streams)
			release := make(chan struct{}, streams)
			h := newEndToEndTunnel(t, transport, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				id := r.URL.Query().Get("id")
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload(id))))
				w.(http.Flusher).Flush()
				ready <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				for chunk := range chunks {
					if _, err := fmt.Fprintf(w, "data: %s/%02d\n\n", id, chunk); err != nil {
						return
					}
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(time.Millisecond):
					}
				}
			}), 5*time.Second)
			// Match the original reproduction's public HTTP/1.1 connections.
			// The fixture's separate management connection may still use HTTP/2.
			publicTransport := &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // generated loopback certificate
				},
				MaxIdleConnsPerHost: streams,
			}
			t.Cleanup(publicTransport.CloseIdleConnections)
			h.client = &http.Client{Transport: publicTransport, Timeout: 5 * time.Second}
			for round := range rounds {
				results := make(chan error, streams)
				for i := range streams {
					id := fmt.Sprintf("%02d-%02d", round, i)
					go func() {
						resp, err := h.get(ctx, "/events?id="+id)
						if err != nil {
							results <- err
							return
						}
						body, err := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						if err != nil || resp.ProtoMajor != 1 || resp.StatusCode != http.StatusOK || string(body) != payload(id) {
							results <- fmt.Errorf("%s: status=%d bytes=%d, want %d ordered bytes: %v",
								id, resp.StatusCode, len(body), len(payload(id)), err)
							return
						}
						results <- nil
					}()
				}
				for range streams {
					select {
					case <-ready:
					case <-ctx.Done():
						t.Fatal("concurrent upstream streams did not become ready")
					}
				}
				for range streams {
					release <- struct{}{}
				}
				for range streams {
					select {
					case err := <-results:
						if err != nil {
							t.Error(err)
						}
					case <-ctx.Done():
						t.Fatal("concurrent responses did not complete")
					}
				}
			}
			metrics := httptest.NewRecorder()
			h.server.MetricsHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/debug/metrics", nil))
			for _, metric := range []string{"expose_response_queue_rejects_total", "expose_response_queue_bytes"} {
				if !strings.Contains("\n"+metrics.Body.String(), "\n"+metric+" 0\n") {
					t.Errorf("expected %s=0 after concurrent streams:\n%s", metric, metrics.Body.String())
				}
			}
		})
	}
}

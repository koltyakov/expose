package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestForwardActiveResponseOutlivesInactivityTimeout(t *testing.T) {
	for _, contentType := range []string{"text/event-stream", "text/plain"} {
		t.Run(contentType, func(t *testing.T) {
			t.Parallel()
			const chunks = 24
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				for range chunks {
					_, _ = io.WriteString(w, "heartbeat\n")
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(25 * time.Millisecond):
					}
				}
			}))
			defer upstream.Close()
			base, _ := url.Parse(upstream.URL)
			c := New(config.ClientConfig{}, nil)
			defer c.fwdClient.CloseIdleConnections()
			req := &tunnelproto.HTTPRequest{ID: "active", Method: http.MethodGet, Path: "/", TimeoutMs: 200}
			ctx, cancel := requestContext(t.Context(), req)
			defer cancel()
			var body strings.Builder
			ended := false
			c.forwardAndSend(ctx, base, req, nil, func(msg tunnelproto.Message) error {
				if msg.Response != nil {
					if msg.Response.Status != http.StatusOK {
						t.Errorf("upstream status=%d", msg.Response.Status)
					}
					body.Write(msg.Response.Body)
				}
				if msg.Kind == tunnelproto.KindRespBodyEnd {
					ended = msg.BodyChunk.Error == ""
				}
				return nil
			}, func(_ string, data []byte) error { _, _ = body.Write(data); return nil })
			if !ended || body.String() != strings.Repeat("heartbeat\n", chunks) {
				t.Fatalf("active stream cut off: clean_end=%t bytes=%d", ended, body.Len())
			}
		})
	}
}

func TestForwardUpstreamInactivityCancelsRequest(t *testing.T) {
	for _, sendHeaders := range []bool{false, true} {
		name := "headers"
		if sendHeaders {
			name = "body"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if sendHeaders {
					w.Header().Set("Content-Type", "text/event-stream")
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer upstream.Close()
			base, _ := url.Parse(upstream.URL)
			c := New(config.ClientConfig{}, nil)
			defer c.fwdClient.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			failed := false
			started := time.Now()
			c.forwardAndSend(ctx, base, &tunnelproto.HTTPRequest{ID: "idle", Method: http.MethodGet, Path: "/", TimeoutMs: 100}, nil, func(msg tunnelproto.Message) error {
				if msg.Response != nil && msg.Response.Status == http.StatusBadGateway {
					failed = true
				}
				if msg.Kind == tunnelproto.KindRespBodyEnd && msg.BodyChunk.Error != "" {
					failed = true
				}
				return nil
			}, nil)
			if !failed || time.Since(started) > 2*time.Second {
				t.Fatal("upstream inactivity did not terminate promptly as a failed response")
			}
		})
	}
}

func TestForwardActiveUploadOutlivesInactivityTimeout(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != 24 {
			http.Error(w, "incomplete upload", http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	c := New(config.ClientConfig{}, nil)
	defer c.fwdClient.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	body := make(chan []byte)
	go func() {
		defer close(body)
		for range 24 {
			select {
			case body <- []byte("x"):
			case <-ctx.Done():
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	status := 0
	c.forwardAndSend(ctx, base, &tunnelproto.HTTPRequest{ID: "upload", Method: http.MethodPost, Path: "/", Streamed: true, TimeoutMs: 200}, body, func(msg tunnelproto.Message) error {
		if msg.Response != nil {
			status = msg.Response.Status
		}
		return nil
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("active upload failed: status=%d", status)
	}
}

func TestUpstreamIdleTimeoutFallbacks(t *testing.T) {
	c := &Client{cfg: config.ClientConfig{Timeout: 5 * time.Second}}
	if got := c.upstreamIdleTimeout(&tunnelproto.HTTPRequest{TimeoutMs: 123}); got != 123*time.Millisecond {
		t.Fatalf("message timeout=%s", got)
	}
	if got := c.upstreamIdleTimeout(&tunnelproto.HTTPRequest{}); got != 5*time.Second {
		t.Fatalf("client fallback=%s", got)
	}
	if got := (&Client{}).upstreamIdleTimeout(nil); got != 2*time.Minute {
		t.Fatalf("default fallback=%s", got)
	}
}

func TestRequestActivityReusesTimerWithoutCancelingPausedReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	activity := newRequestActivity(time.Hour, cancel)
	defer activity.stop()
	timer := activity.timer
	activity.finishHeaders()
	activity.mu.Lock()
	activity.deadline = time.Now().Add(-time.Second)
	activity.mu.Unlock()
	activity.expire() // A callback already queued when the header timer stopped.
	if ctx.Err() != nil {
		t.Fatal("paused timer canceled the request")
	}
	activity.beginRead()
	deadline := activity.deadline
	activity.touch() // A duplex upload must not extend the response read deadline.
	if activity.deadline != deadline || activity.timer != timer {
		t.Fatal("response read changed timer ownership or accepted upload activity")
	}
	activity.expire() // An older callback must honor the newly armed deadline.
	if ctx.Err() != nil {
		t.Fatal("stale callback canceled a fresh read")
	}
	activity.endRead()
	activity.beginRead()
	activity.mu.Lock()
	activity.deadline = time.Now().Add(-time.Second)
	activity.mu.Unlock()
	activity.expire()
	if ctx.Err() == nil {
		t.Fatal("expired active read did not cancel the request")
	}
}

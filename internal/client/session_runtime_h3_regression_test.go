package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestH3RequestBodyEndErrorCancelsForward(t *testing.T) {
	for _, bodyError := range []string{"", "public upload failed"} {
		t.Run(bodyError, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			out := make(chan []byte, 1)
			pumpStreamedRequestBodyMessages(ctx, "req_1", cancel, func() (tunnelproto.Message, error) {
				return tunnelproto.Message{Kind: tunnelproto.KindReqBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: "req_1", Error: bodyError}}, nil
			}, out, nil)
			if got := ctx.Err(); (got != nil) != (bodyError != "") {
				t.Fatalf("body end error %q: context error=%v", bodyError, got)
			}
		})
	}
}

// STOP_SENDING from a canceled public handler must cancel local HTTP work even
// when the inline request has no body-reader goroutine to notice the reset.
func TestH3WorkerDisconnectCancelsInlineForward(t *testing.T) {
	serverStreams := make(chan *http3.Stream, 2)
	addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		serverStreams <- w.(http3.HTTPStreamer).HTTPStream()
	}))
	defer shutdown()
	started := make(chan struct{})
	c := &Client{h3TLSConfig: &tls.Config{InsecureSkipVerify: true}, fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/slow" {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("healthy")), Request: r}, nil
		}
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}}
	target, _ := url.Parse("https://" + addr + "/worker")
	conn, transport, cc, err := c.openHTTP3ClientConnection(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.Close() }()
	defer func() { _ = conn.CloseWithError(0, "") }()
	open := func() *http3.RequestStream {
		t.Helper()
		stream, err := cc.OpenRequestStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, target.String(), nil)
		if err := stream.SendRequestHeader(req); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.ReadResponse(); err != nil {
			t.Fatal(err)
		}
		return stream
	}
	stream := open()
	defer closeH3RequestStream(stream)
	serverStream := <-serverStreams
	defer closeHTTP3TestStream(serverStream)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	base, _ := url.Parse("http://127.0.0.1:8080")
	rt := &clientH3MultiStreamRuntime{client: c, localBase: base, ctx: ctx, useStreamV2: true}
	done := make(chan error, 1)
	go func() {
		done <- rt.handleWorkerHTTPRequest(stream, &tunnelproto.HTTPRequest{ID: "cancel_me", Method: http.MethodGet, Path: "/slow", TimeoutMs: 10000})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("local forwarding did not start")
	}
	serverStream.CancelRead(0)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled worker returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("inline forwarding survived the worker disconnect")
	}
	if ctx.Err() != nil || conn.Context().Err() != nil {
		t.Fatal("worker cancel closed the session")
	}
	// The same connection remains usable on a different, clean worker.
	healthy := open()
	defer closeH3RequestStream(healthy)
	serverHealthy := <-serverStreams
	defer closeHTTP3TestStream(serverHealthy)
	if healthy.StreamID() == stream.StreamID() {
		t.Fatal("reused the canceled worker")
	}
	healthyDone := make(chan error, 1)
	go func() {
		healthyDone <- rt.handleWorkerHTTPRequest(healthy, &tunnelproto.HTTPRequest{ID: "healthy", Method: http.MethodGet, Path: "/healthy"})
	}()
	_ = serverHealthy.SetReadDeadline(time.Now().Add(time.Second))
	var msg tunnelproto.Message
	if err := tunnelproto.ReadStreamMessageV2(serverHealthy, clientWSReadLimit, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Response == nil || msg.Response.ID != "healthy" || string(msg.Response.Body) != "healthy" {
		t.Fatalf("healthy worker received %+v", msg)
	}
	if err := <-healthyDone; err != nil {
		t.Fatal(err)
	}
}

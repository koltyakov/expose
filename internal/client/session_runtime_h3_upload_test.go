package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

// newH3WorkerTestPair opens one worker stream between a client runtime and a
// test HTTP/3 server, returning both ends.
func newH3WorkerTestPair(t *testing.T, c *Client) (*clientH3MultiStreamRuntime, *http3.RequestStream, *http3.Stream) {
	t.Helper()
	serverStreams := make(chan *http3.Stream, 1)
	addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		stream, err := takeOverHTTP3Stream(w, w.(http3.HTTPStreamer))
		if err != nil {
			t.Errorf("take over worker stream: %v", err)
			return
		}
		serverStreams <- stream
	}))
	t.Cleanup(shutdown)
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	target, _ := url.Parse("https://" + addr + "/worker")
	conn, transport, cc, err := c.openHTTP3ClientConnection(t.Context(), target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
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
	t.Cleanup(func() { closeH3RequestStream(stream) })
	serverStream := <-serverStreams
	t.Cleanup(func() { closeHTTP3TestStream(serverStream) })
	base, _ := url.Parse("http://127.0.0.1:8080")
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &clientH3MultiStreamRuntime{client: c, localBase: base, ctx: ctx, useStreamV2: true}, stream, serverStream
}

// The origin answers after reading part of a body the server has already
// sent in full. The worker drains the rest up to the end marker and stays
// usable for the next request instead of being reset.
func TestH3WorkerDrainsUploadAfterEarlyResponse(t *testing.T) {
	const prefix = 32 << 10
	c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Body != nil && r.URL.Path == "/upload" {
			if _, err := io.ReadFull(r.Body, make([]byte, prefix)); err != nil {
				return nil, err
			}
		}
		return &http.Response{StatusCode: http.StatusRequestEntityTooLarge, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("too large")), ContentLength: 9, Request: r}, nil
	})}}
	rt, stream, server := newH3WorkerTestPair(t, c)
	writeServer := func(msg tunnelproto.Message) {
		t.Helper()
		if err := tunnelproto.WriteStreamJSONV2(server, msg); err != nil {
			t.Fatal(err)
		}
	}
	readServer := func() tunnelproto.Message {
		t.Helper()
		_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
		var msg tunnelproto.Message
		if err := tunnelproto.ReadStreamMessageV2(server, clientWSReadLimit, &msg); err != nil {
			t.Fatal(err)
		}
		return msg
	}

	done := make(chan error, 1)
	go func() {
		done <- rt.handleWorkerHTTPRequest(stream, &tunnelproto.HTTPRequest{ID: "upload", Method: http.MethodPost, Path: "/upload", Streamed: true, TimeoutMs: 5000})
	}()
	chunk := bytes.Repeat([]byte("u"), 16<<10)
	for range 2 {
		if err := tunnelproto.WriteStreamBinaryFrameV2(server, tunnelproto.BinaryFrameReqBody, "upload", 0, chunk); err != nil {
			t.Fatal(err)
		}
	}
	if resp := readServer(); resp.Response == nil || resp.Response.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("early response: %+v", resp)
	}
	// The rest of the body was already on its way when the origin answered.
	for range 4 {
		if err := tunnelproto.WriteStreamBinaryFrameV2(server, tunnelproto.BinaryFrameReqBody, "upload", 0, chunk); err != nil {
			t.Fatal(err)
		}
	}
	writeServer(tunnelproto.Message{Kind: tunnelproto.KindReqBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: "upload"}})
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drained worker reported %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not finish draining")
	}

	// The same stream carries the next request.
	go func() {
		done <- rt.handleWorkerHTTPRequest(stream, &tunnelproto.HTTPRequest{ID: "next", Method: http.MethodGet, Path: "/next"})
	}()
	if resp := readServer(); resp.Response == nil || resp.Response.ID != "next" {
		t.Fatalf("next response on the reused worker: %+v", resp)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A server that stops mid-upload resets the worker. The drain then ends on
// the read error, and the body pump is joined before the worker returns.
func TestH3WorkerDrainEndsWhenServerResets(t *testing.T) {
	c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusRequestEntityTooLarge, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("too large")), ContentLength: 9, Request: r}, nil
	})}}
	rt, stream, server := newH3WorkerTestPair(t, c)
	done := make(chan error, 1)
	go func() {
		done <- rt.handleWorkerHTTPRequest(stream, &tunnelproto.HTTPRequest{ID: "upload", Method: http.MethodPost, Path: "/upload", Streamed: true, TimeoutMs: 5000})
	}()
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg tunnelproto.Message
	if err := tunnelproto.ReadStreamMessageV2(server, clientWSReadLimit, &msg); err != nil || msg.Response == nil {
		t.Fatalf("early response: %+v %v", msg, err)
	}
	server.CancelRead(0)
	server.CancelWrite(0)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reset worker reported reusable")
		}
	case <-time.After(h3RequestBodyDrainTimeout / 2):
		t.Fatal("drain outlived the server reset")
	}
}

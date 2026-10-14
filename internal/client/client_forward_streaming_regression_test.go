package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestForwardExplicitStreamDispatchesHeadersWithoutBody(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		length      int64
	}{
		{"events", "text/event-stream", -1},
		{"events-parameters", "Text/Event-Stream; charset=utf-8", -1},
		{"known-large", "application/octet-stream", streamingThreshold + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer func() { _ = pr.Close() }()
			defer func() { _ = pw.Close() }()
			c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {tc.contentType}}, ContentLength: tc.length, Body: pr, Request: r}, nil
			})}}
			base, _ := url.Parse("http://127.0.0.1:8080")
			started := time.Now()
			var dispatch time.Duration
			var msgs []tunnelproto.Message
			c.forwardAndSend(t.Context(), base, &tunnelproto.HTTPRequest{ID: "events", Method: http.MethodGet, Path: "/"}, nil, func(msg tunnelproto.Message) error {
				msgs = append(msgs, retainTestMessage(msg))
				if msg.Kind == tunnelproto.KindResponse {
					dispatch = time.Since(started)
					// The body cannot finish until its headers have been sent.
					_ = pw.Close()
				}
				return nil
			}, nil)
			t.Logf("header dispatch=%s", dispatch)
			if dispatch >= inlineResponseWindow/2 {
				t.Fatalf("explicit stream used the inline decision window: %s", dispatch)
			}
			if len(msgs) != 2 || msgs[0].Response == nil || !msgs[0].Response.Streamed || msgs[1].Kind != tunnelproto.KindRespBodyEnd {
				t.Fatalf("unexpected messages: %#v", msgs)
			}
		})
	}
}

func TestForwardExplicitStreamingPreservesBodylessResponses(t *testing.T) {
	for _, tc := range []struct {
		method string
		status int
	}{
		{http.MethodHead, http.StatusOK}, {http.MethodGet, http.StatusNoContent}, {http.MethodGet, http.StatusNotModified}, {http.MethodGet, http.StatusOK},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.method, tc.status), func(t *testing.T) {
			c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/event-stream"}}, ContentLength: streamingThreshold * 2, Body: http.NoBody, Request: r}, nil
			})}}
			base, _ := url.Parse("http://127.0.0.1:8080")
			var msgs []tunnelproto.Message
			c.forwardAndSend(t.Context(), base, &tunnelproto.HTTPRequest{ID: "empty", Method: tc.method, Path: "/"}, nil, func(msg tunnelproto.Message) error { msgs = append(msgs, retainTestMessage(msg)); return nil }, nil)
			if len(msgs) != 1 || msgs[0].Response.Streamed || len(msgs[0].Response.Body) != 0 || msgs[0].Response.Status != tc.status {
				t.Fatalf("bodyless response changed: %#v", msgs)
			}
		})
	}
}

func TestForwardBodyFailureIsNotCleanEOF(t *testing.T) {
	for _, streamed := range []bool{false, true} {
		t.Run(fmt.Sprint(streamed), func(t *testing.T) {
			contentType := "application/json"
			if streamed {
				contentType = "text/event-stream"
			}
			c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {contentType}}, ContentLength: -1, Body: &readErrorAfterFirstBody{first: []byte("partial"), err: io.ErrUnexpectedEOF}, Request: r}, nil
			})}}
			base, _ := url.Parse("http://127.0.0.1:8080")
			var msgs []tunnelproto.Message
			c.forwardAndSend(t.Context(), base, &tunnelproto.HTTPRequest{ID: "failed", Method: http.MethodGet, Path: "/"}, nil, func(msg tunnelproto.Message) error { msgs = append(msgs, retainTestMessage(msg)); return nil }, nil)
			if !streamed {
				if len(msgs) != 1 || msgs[0].Response.Status != http.StatusBadGateway {
					t.Fatalf("inline truncation accepted: %#v", msgs)
				}
			} else if len(msgs) != 3 || !msgs[0].Response.Streamed || string(msgs[1].BodyChunk.Data) != "partial" || msgs[2].BodyChunk.Error == "" {
				t.Fatalf("stream truncation accepted: %#v", msgs)
			}
		})
	}
}

// Short first reads and a full second read force both accumulated and overflow
// owners. Concurrent requests recycle those pools while synchronous writers
// consume each slice, catching early returns and double-return aliases under -race.
func TestForwardStreamBufferOwnership(t *testing.T) {
	base, _ := url.Parse("http://127.0.0.1:8080")
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			payload := bytes.Repeat([]byte{byte(i + 1)}, streamingThreshold*2+33)
			for range 10 {
				reader := &shortFirstResponseReader{Reader: bytes.NewReader(payload)}
				c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), ContentLength: -1, Body: io.NopCloser(reader), Request: r}, nil
				})}}
				var got bytes.Buffer
				c.forwardAndSend(t.Context(), base, &tunnelproto.HTTPRequest{ID: fmt.Sprint(i), Method: http.MethodGet, Path: "/"}, nil, func(msg tunnelproto.Message) error {
					if msg.BodyChunk != nil && msg.Kind == tunnelproto.KindRespBodyEnd && msg.BodyChunk.Error != "" {
						return errors.New(msg.BodyChunk.Error)
					}
					return nil
				}, func(_ string, chunk []byte) error {
					_, _ = got.Write(chunk)
					return nil
				})
				if !bytes.Equal(got.Bytes(), payload) {
					t.Errorf("request %d recycled a live buffer: received %d bytes", i, got.Len())
					return
				}
			}
		})
	}
	wg.Wait()
}

type shortFirstResponseReader struct {
	*bytes.Reader
	first bool
}

func (r *shortFirstResponseReader) Read(p []byte) (int, error) {
	if !r.first {
		r.first = true
		p = p[:min(len(p), 128*1024)]
	}
	return r.Reader.Read(p)
}

func TestForwardExplicitStreamCancellation(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		context.AfterFunc(r.Context(), func() { _ = pw.CloseWithError(r.Context().Err()) })
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, ContentLength: -1, Body: pr, Request: r}, nil
	})}}
	base, _ := url.Parse("http://127.0.0.1:8080")
	var ended bool
	c.forwardAndSend(ctx, base, &tunnelproto.HTTPRequest{ID: "cancel", Method: http.MethodGet, Path: "/"}, nil, func(msg tunnelproto.Message) error {
		if msg.Kind == tunnelproto.KindResponse {
			cancel()
		}
		if msg.Kind == tunnelproto.KindRespBodyEnd {
			ended = msg.BodyChunk.Error != ""
		}
		return nil
	}, nil)
	if !ended {
		t.Fatal("canceled explicit stream did not report failed body end")
	}
}

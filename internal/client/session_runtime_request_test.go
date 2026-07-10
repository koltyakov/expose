package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestClientSessionRuntimeDispatchesStreamBodyWhileNextRequestWaits(t *testing.T) {
	t.Parallel()

	var active atomic.Int32
	var exceededLimit atomic.Bool
	started := make(chan string, 2)
	bodyA := make(chan string, 1)
	c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if active.Add(1) > 1 {
			exceededLimit.Store(true)
		}
		defer active.Add(-1)
		started <- req.URL.Path
		if req.URL.Path == "/a" {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			bodyA <- string(body)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       http.NoBody,
		}, nil
	})}}

	ctx, cancel := context.WithCancel(context.Background())
	rt := &clientSessionRuntime{
		client:           c,
		localBase:        &url.URL{Scheme: "http", Host: "local.test"},
		ctx:              ctx,
		cancel:           cancel,
		requestSem:       make(chan struct{}, 1),
		reqCancel:        make(map[string]context.CancelFunc),
		streamedReqState: make(map[string]*streamedRequestState),
	}
	defer rt.close()

	dispatched := make(chan struct{})
	go func() {
		defer close(dispatched)
		_ = rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindRequest, Request: &tunnelproto.HTTPRequest{
			ID: "a", Method: http.MethodPost, Path: "/a", Streamed: true,
		}})
		_ = rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindRequest, Request: &tunnelproto.HTTPRequest{
			ID: "b", Method: http.MethodGet, Path: "/b",
		}})
		_ = rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindReqBody, BodyChunk: &tunnelproto.BodyChunk{
			ID: "a", Data: []byte("body-a"),
		}})
		_ = rt.handleMessage(tunnelproto.Message{Kind: tunnelproto.KindReqBodyEnd, BodyChunk: &tunnelproto.BodyChunk{ID: "a"}})
	}()

	select {
	case <-dispatched:
	case <-time.After(2 * time.Second):
		t.Fatal("protocol dispatcher blocked while request B waited for concurrency slot")
	}

	forwarded := make([]string, 0, 2)
	for len(forwarded) < 2 {
		select {
		case path := <-started:
			forwarded = append(forwarded, path)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for forwarded requests")
		}
	}
	if forwarded[0] != "/a" || forwarded[1] != "/b" {
		t.Fatalf("expected forwarding order [/a /b], got %v", forwarded)
	}
	if got := <-bodyA; got != "body-a" {
		t.Fatalf("expected request A body %q, got %q", "body-a", got)
	}
	if exceededLimit.Load() {
		t.Fatal("forwarding exceeded max concurrency of 1")
	}
}

func TestClientSessionRuntimeAbortsErroredStreamedRequest(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	bodyErr := make(chan error, 1)
	c := &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		_, err := io.ReadAll(req.Body)
		bodyErr <- err
		return nil, err
	})}}

	ctx, cancel := context.WithCancel(context.Background())
	rt := &clientSessionRuntime{
		client:           c,
		localBase:        &url.URL{Scheme: "http", Host: "local.test"},
		ctx:              ctx,
		cancel:           cancel,
		requestSem:       make(chan struct{}, 1),
		reqCancel:        make(map[string]context.CancelFunc),
		streamedReqState: make(map[string]*streamedRequestState),
	}
	defer rt.close()

	rt.handleRequest(&tunnelproto.HTTPRequest{ID: "truncated", Method: http.MethodPost, Path: "/", Streamed: true})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("local upstream request did not start")
	}

	rt.handleReqBodyEnd(&tunnelproto.BodyChunk{ID: "truncated", Error: "request body truncated"})
	select {
	case err := <-bodyErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected local request body cancellation error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("errored stream end did not fail the local request body")
	}
}

func TestClientSessionRuntimeCancelsStalledStreamedRequest(t *testing.T) {
	t.Parallel()

	var forwarded atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	rt := &clientSessionRuntime{
		client: &Client{fwdClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			forwarded.Add(1)
			return nil, context.Canceled
		})}},
		localBase:        &url.URL{Scheme: "http", Host: "local.test"},
		ctx:              ctx,
		cancel:           cancel,
		requestSem:       make(chan struct{}, 1),
		reqCancel:        make(map[string]context.CancelFunc),
		streamedReqState: make(map[string]*streamedRequestState),
	}
	rt.requestSem <- struct{}{}
	defer rt.close()

	rt.handleRequest(&tunnelproto.HTTPRequest{ID: "stalled", Method: http.MethodPost, Path: "/", Streamed: true})
	for i := 0; i <= streamingReqBodyBufSize; i++ {
		if err := rt.handleReqBody(&tunnelproto.BodyChunk{ID: "stalled", Data: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}

	done := make(chan struct{})
	go func() {
		rt.requestWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stalled streamed request was not canceled")
	}
	<-rt.requestSem
	if forwarded.Load() != 0 {
		t.Fatal("stalled request reached local upstream after cancellation")
	}
}

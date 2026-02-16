package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestNextBackoff(t *testing.T) {
	t.Parallel()

	if got := nextBackoff(0); got != reconnectInitialDelay {
		t.Fatalf("expected initial delay %s, got %s", reconnectInitialDelay, got)
	}
	if got := nextBackoff(reconnectInitialDelay); got != reconnectInitialDelay*2 {
		t.Fatalf("expected doubled delay, got %s", got)
	}
	if got := nextBackoff(reconnectMaxDelay); got != reconnectMaxDelay {
		t.Fatalf("expected max delay clamp, got %s", got)
	}
}

func TestForwardLocalStripsHopByHopHeaders(t *testing.T) {
	t.Parallel()

	var gotConnection string
	var gotHop string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotHop = r.Header.Get("X-Hop")
		w.Header().Set("Connection", "close")
		w.Header().Set("Proxy-Connection", "keep-alive")
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	base, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	c := &Client{
		fwdClient: &http.Client{Timeout: 5 * time.Second},
	}
	resp := c.forwardLocal(context.Background(), base, &tunnelproto.HTTPRequest{
		ID:     "req_1",
		Method: http.MethodGet,
		Path:   "/hello",
		Headers: map[string][]string{
			"Connection": {"keep-alive, X-Hop"},
			"X-Hop":      {"drop"},
			"X-Keep":     {"keep"},
		},
	})

	if resp.Status != http.StatusCreated {
		t.Fatalf("expected %d, got %d", http.StatusCreated, resp.Status)
	}
	if gotConnection != "" {
		t.Fatalf("expected Connection header stripped before local forward, got %q", gotConnection)
	}
	if gotHop != "" {
		t.Fatalf("expected Connection-declared hop header stripped, got %q", gotHop)
	}
	if resp.Headers["Connection"] != nil {
		t.Fatalf("expected Connection header removed from response")
	}
	if resp.Headers["Proxy-Connection"] != nil {
		t.Fatalf("expected Proxy-Connection header removed from response")
	}
	if got := firstHeaderValue(resp.Headers, "X-Upstream"); got != "ok" {
		t.Fatalf("expected X-Upstream header to be preserved, got %q", got)
	}
}

func firstHeaderValue(h map[string][]string, key string) string {
	if len(h[key]) == 0 {
		return ""
	}
	return h[key][0]
}

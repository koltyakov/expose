package client

import (
	"context"
	"encoding/json"
	"errors"
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

func TestNextBackoff(t *testing.T) {
	t.Parallel()

	// With jitter (±25%), results are in range [0.75*base, 1.25*base].
	got := nextBackoff(0)
	base := reconnectInitialDelay * 2
	lo := time.Duration(float64(base) * 0.75)
	hi := time.Duration(float64(base) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected initial backoff in [%s, %s], got %s", lo, hi, got)
	}

	got = nextBackoff(reconnectInitialDelay)
	base = reconnectInitialDelay * 2
	lo = time.Duration(float64(base) * 0.75)
	hi = time.Duration(float64(base) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected doubled delay in [%s, %s], got %s", lo, hi, got)
	}

	got = nextBackoff(reconnectMaxDelay)
	lo = time.Duration(float64(reconnectMaxDelay) * 0.75)
	hi = time.Duration(float64(reconnectMaxDelay) * 1.25)
	if got < lo || got > hi {
		t.Fatalf("expected clamped delay in [%s, %s], got %s", lo, hi, got)
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

func TestIsNonRetriableRegisterError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "hostname conflict code",
			err:  &registerError{StatusCode: http.StatusConflict, Code: "hostname_in_use", Message: "hostname already in use"},
			want: true,
		},
		{
			name: "unauthorized status",
			err:  &registerError{StatusCode: http.StatusUnauthorized, Message: "unauthorized"},
			want: true,
		},
		{
			name: "bad request status",
			err:  &registerError{StatusCode: http.StatusBadRequest, Message: "invalid mode"},
			want: true,
		},
		{
			name: "rate limit status",
			err:  &registerError{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"},
			want: false,
		},
		{
			name: "server error status",
			err:  &registerError{StatusCode: http.StatusBadGateway, Message: "upstream"},
			want: false,
		},
		{
			name: "plain unauthorized fallback",
			err:  io.ErrUnexpectedEOF,
			want: false,
		},
	}

	for _, tc := range cases {
		if got := isNonRetriableRegisterError(tc.err); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}

	if got := isNonRetriableRegisterError(errors.New("unauthorized")); !got {
		t.Fatal("expected plain unauthorized error to be non-retriable")
	}
}

func firstHeaderValue(h map[string][]string, key string) string {
	if len(h[key]) == 0 {
		return ""
	}
	return h[key][0]
}

func TestRegisterSendsOptionalPassword(t *testing.T) {
	t.Parallel()

	var gotAuth string
	var gotUser string
	var gotPassword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tunnels/register" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotPassword = req.Password
		gotUser = req.User
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tunnel_id":"t_1","public_url":"https://demo.example.com","ws_url":"wss://example.com/v1/tunnels/connect?token=abc"}`)
	}))
	defer srv.Close()

	c := New(config.ClientConfig{
		ServerURL: srv.URL,
		APIKey:    "key123",
		User:      "admin",
		Password:  "session-pass",
		LocalPort: 8080,
	}, nil)

	_, err := c.register(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotPassword != "session-pass" {
		t.Fatalf("expected password in register payload, got %q", gotPassword)
	}
	if gotUser != "admin" {
		t.Fatalf("expected user in register payload, got %q", gotUser)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("expected bearer auth header, got %q", gotAuth)
	}
}

func TestNormalizeWSURLPort(t *testing.T) {
	tests := []struct {
		name      string
		wsURL     string
		serverURL string
		want      string
	}{
		{
			name:      "inject non-default server port",
			wsURL:     "wss://myapp.example.com/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com:10443",
			want:      "wss://myapp.example.com:10443/v1/tunnels/connect?token=abc",
		},
		{
			name:      "keep explicit ws port",
			wsURL:     "wss://myapp.example.com:9443/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com:10443",
			want:      "wss://myapp.example.com:9443/v1/tunnels/connect?token=abc",
		},
		{
			name:      "ignore default server port",
			wsURL:     "wss://myapp.example.com/v1/tunnels/connect?token=abc",
			serverURL: "https://example.com",
			want:      "wss://myapp.example.com/v1/tunnels/connect?token=abc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeWSURLPort(tt.wsURL, tt.serverURL); got != tt.want {
				t.Fatalf("normalizeWSURLPort(): got %q, want %q", got, tt.want)
			}
		})
	}
}

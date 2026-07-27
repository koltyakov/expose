package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestValidateSecureTransportURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		rawURL          string
		wantScheme      string
		plaintextScheme string
		wantErr         bool
	}{
		{name: "wss allowed", rawURL: "wss://example.com/connect", wantScheme: "wss", plaintextScheme: "ws"},
		{name: "ws rejected", rawURL: "ws://example.com/connect", wantScheme: "wss", plaintextScheme: "ws", wantErr: true},
		{name: "ws loopback allowed", rawURL: "ws://127.0.0.1:8080/connect", wantScheme: "wss", plaintextScheme: "ws"},
		{name: "ws localhost allowed", rawURL: "ws://localhost:8080/connect", wantScheme: "wss", plaintextScheme: "ws"},
		{name: "ws ipv6 loopback allowed", rawURL: "ws://[::1]:8080/connect", wantScheme: "wss", plaintextScheme: "ws"},
		{name: "http as ws rejected", rawURL: "http://example.com/connect", wantScheme: "wss", plaintextScheme: "ws", wantErr: true},
		{name: "https allowed", rawURL: "https://example.com/connect-h3", wantScheme: "https"},
		{name: "http rejected", rawURL: "http://example.com/connect-h3", wantScheme: "https", wantErr: true},
		{name: "http loopback h3 rejected", rawURL: "http://127.0.0.1:8080/connect-h3", wantScheme: "https", wantErr: true},
		{name: "empty scheme rejected", rawURL: "example.com/connect", wantScheme: "wss", plaintextScheme: "ws", wantErr: true},
	}
	for _, tt := range cases {
		err := validateSecureTransportURL(tt.rawURL, tt.wantScheme, tt.plaintextScheme)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: validateSecureTransportURL(%q) err = %v, wantErr %v", tt.name, tt.rawURL, err, tt.wantErr)
		}
	}
}

func TestSplitConnectToken(t *testing.T) {
	t.Parallel()

	withHeader := domain.RegisterResponse{Capabilities: []string{domain.CapabilityConnectTokenHeader}}
	legacy := domain.RegisterResponse{Capabilities: []string{"ws_v1"}}

	// Capable server: the token leaves the URL entirely.
	url, token := splitConnectToken("wss://a.example.com/v1/tunnels/connect?token=secret", withHeader)
	if token != "secret" {
		t.Fatalf("token = %q, want %q", token, "secret")
	}
	if strings.Contains(url, "secret") || strings.Contains(url, "token") {
		t.Fatalf("dial URL %q still carries the token", url)
	}

	// Other query parameters survive the rewrite.
	url, token = splitConnectToken("wss://a.example.com/connect?token=secret&mode=fast", withHeader)
	if token != "secret" || !strings.Contains(url, "mode=fast") {
		t.Fatalf("splitConnectToken() = %q, %q; want mode=fast preserved", url, token)
	}

	// Server without the capability only reads the query parameter, so the
	// URL must be left exactly as issued.
	const legacyURL = "wss://a.example.com/v1/tunnels/connect?token=secret"
	url, token = splitConnectToken(legacyURL, legacy)
	if url != legacyURL || token != "" {
		t.Fatalf("splitConnectToken(legacy) = %q, %q; want URL unchanged and no token", url, token)
	}

	// No token in the URL at all.
	if url, token = splitConnectToken("wss://a.example.com/connect", withHeader); token != "" {
		t.Fatalf("splitConnectToken(no token) = %q, %q", url, token)
	}
}

func TestConnectAuthHeader(t *testing.T) {
	t.Parallel()

	if got := connectAuthHeader(""); got != nil {
		t.Fatalf("connectAuthHeader(\"\") = %v, want nil", got)
	}
	if got := connectAuthHeader("secret").Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("Authorization = %q, want %q", got, "Bearer secret")
	}
}

func TestConnectWebSocketTransportRejectsPlaintext(t *testing.T) {
	t.Parallel()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.connectWebSocketTransport(ctx, domain.RegisterResponse{
		WSURL: "ws://203.0.113.10/v1/tunnels/connect?token=abc",
	})
	if err == nil {
		t.Fatal("expected plaintext ws:// URL to be rejected")
	}
	if !strings.Contains(err.Error(), "wss://") {
		t.Fatalf("expected error to mention wss://, got %v", err)
	}
}

func TestConnectHTTP3TransportsRejectPlaintext(t *testing.T) {
	t.Parallel()

	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reg := domain.RegisterResponse{
		H3URL:        "http://203.0.113.10/v1/tunnels/connect-h3?token=abc",
		Capabilities: []string{tunnelCapabilityH3CompatV1, tunnelCapabilityH3MultistreamV2},
	}
	if _, err := c.connectHTTP3Transport(ctx, reg); err == nil {
		t.Fatal("expected plaintext http:// h3_url to be rejected")
	}
	if _, err := c.connectHTTP3MultiStreamTransport(ctx, reg); err == nil {
		t.Fatal("expected plaintext http:// h3_url to be rejected (multistream)")
	}
}

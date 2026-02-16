package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStableTemporarySubdomain(t *testing.T) {
	a := stableTemporarySubdomain("WORKSTATION-1", "3000")
	b := stableTemporarySubdomain("WORKSTATION-1", "3000")
	if a == "" || b == "" {
		t.Fatal("expected non-empty stable subdomain")
	}
	if a != b {
		t.Fatalf("expected deterministic value, got %s and %s", a, b)
	}
	if len(a) != 6 {
		t.Fatalf("expected short 6-char subdomain, got %q (%d)", a, len(a))
	}

	c := stableTemporarySubdomain("WORKSTATION-1", "3001")
	if c == a {
		t.Fatalf("expected different hash for different port, got same %s", c)
	}
}

func TestStableTemporarySubdomainRequiresInputs(t *testing.T) {
	if got := stableTemporarySubdomain("", "3000"); got != "" {
		t.Fatalf("expected empty hash for empty host, got %q", got)
	}
	if got := stableTemporarySubdomain("host", ""); got != "" {
		t.Fatalf("expected empty hash for empty port, got %q", got)
	}
}

func TestDecodeJSONBodyRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/tunnels/register", strings.NewReader(`{"mode":"temporary","unknown":"x"}`))
	w := httptest.NewRecorder()
	var body registerRequest

	if err := decodeJSONBody(w, req, maxRegisterBodyBytes, &body); err == nil {
		t.Fatal("expected unknown JSON fields to be rejected")
	}
}

func TestReadLimitedBodyReturnsTooLargeError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte("123456")))
	w := httptest.NewRecorder()

	_, err := readLimitedBody(w, req, 4)
	if !isBodyTooLargeError(err) {
		t.Fatalf("expected request body too large error, got %v", err)
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := normalizeHost("Example.com:443"); got != "example.com" {
		t.Fatalf("expected normalized host, got %q", got)
	}
	if got := normalizeHost("[2001:db8::1]:10443"); got != "2001:db8::1" {
		t.Fatalf("expected ipv6 host normalization, got %q", got)
	}
}

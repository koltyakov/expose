package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/auth"
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

func TestShouldDeleteCertCacheEntry(t *testing.T) {
	hostSet := map[string]struct{}{
		"a.example.com": {},
		"b.example.com": {},
	}
	cases := map[string]bool{
		"a.example.com":         true,
		"a.example.com+rsa":     true,
		"b.example.com+ecdsa":   true,
		"c.example.com":         false,
		"c.example.com+rsa":     false,
		"not-a-cert-cache-file": false,
	}
	for name, want := range cases {
		if got := shouldDeleteCertCacheEntry(name, hostSet); got != want {
			t.Fatalf("shouldDeleteCertCacheEntry(%q): got %v, want %v", name, got, want)
		}
	}
}

func TestRemoveTunnelCertCacheBatch(t *testing.T) {
	cacheDir := t.TempDir()
	toWrite := []string{
		"a.example.com",
		"a.example.com+rsa",
		"b.example.com",
		"c.example.com+ecdsa",
		"unrelated.txt",
	}
	for _, name := range toWrite {
		if err := os.WriteFile(filepath.Join(cacheDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	removed, failed, err := removeTunnelCertCacheBatch(cacheDir, []string{"a.example.com", "c.example.com", "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Fatalf("expected 3 removed files, got %d", removed)
	}
	if failed != 0 {
		t.Fatalf("expected 0 failed removals, got %d", failed)
	}

	if _, err := os.Stat(filepath.Join(cacheDir, "a.example.com")); !os.IsNotExist(err) {
		t.Fatalf("expected a.example.com to be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "a.example.com+rsa")); !os.IsNotExist(err) {
		t.Fatalf("expected a.example.com+rsa to be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "c.example.com+ecdsa")); !os.IsNotExist(err) {
		t.Fatalf("expected c.example.com+ecdsa to be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "b.example.com")); err != nil {
		t.Fatalf("expected b.example.com to remain, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "unrelated.txt")); err != nil {
		t.Fatalf("expected unrelated.txt to remain, err=%v", err)
	}
}

func TestWriteBasicAuthChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	writeBasicAuthChallenge(rr)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestIsAuthorizedBasicPassword(t *testing.T) {
	hash, err := auth.HashPassword("session-pass")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.SetBasicAuth("admin", "session-pass")
	if !isAuthorizedBasicPassword(req, "admin", hash) {
		t.Fatal("expected valid basic auth password to pass")
	}

	req = httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.SetBasicAuth("user", "wrong")
	if isAuthorizedBasicPassword(req, "admin", hash) {
		t.Fatal("expected wrong basic auth password to fail")
	}

	req = httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.SetBasicAuth("other", "session-pass")
	if isAuthorizedBasicPassword(req, "admin", hash) {
		t.Fatal("expected wrong basic auth username to fail")
	}
}

func TestRegistrationWSAuthority(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		fallback string
		want     string
	}{
		{name: "non default port preserved", host: "127.0.0.1.sslip.io:10443", fallback: "example.com", want: "127.0.0.1.sslip.io:10443"},
		{name: "default port removed", host: "example.com:443", fallback: "example.com", want: "example.com"},
		{name: "bare host", host: "example.com", fallback: "fallback.example.com", want: "example.com"},
		{name: "empty host uses fallback", host: "", fallback: "fallback.example.com", want: "fallback.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registrationWSAuthority(tt.host, tt.fallback); got != tt.want {
				t.Fatalf("registrationWSAuthority(%q): got %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestAuthorityPort(t *testing.T) {
	if got := authorityPort("example.com:10443"); got != "10443" {
		t.Fatalf("expected 10443, got %q", got)
	}
	if got := authorityPort("example.com"); got != "" {
		t.Fatalf("expected empty port, got %q", got)
	}
}

func TestIsLikelyTLSProvisioningReason(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		reason string
		want   bool
	}{
		{name: "bad certificate", reason: "remote error: tls: bad certificate", want: true},
		{name: "verify certificate", reason: "tls: failed to verify certificate: x509: certificate signed by unknown authority", want: true},
		{name: "standards compliant", reason: "x509: \"example.com\" certificate is not standards compliant", want: true},
		{name: "scanner eof", reason: "EOF", want: false},
		{name: "unsupported version", reason: "tls: client offered only unsupported versions: [302 301]", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isLikelyTLSProvisioningReason(tc.reason); got != tc.want {
				t.Fatalf("got %v, want %v for reason %q", got, tc.want, tc.reason)
			}
		})
	}
}

func TestIsLikelyScannerTLSReason(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		reason string
		want   bool
	}{
		{name: "eof", reason: "EOF", want: true},
		{name: "missing server name", reason: "acme/autocert: missing server name", want: true},
		{name: "unsupported protocols", reason: "tls: client requested unsupported application protocols ([\"http/0.9\" \"h2c\"])", want: true},
		{name: "unsupported versions", reason: "tls: client offered only unsupported versions: [302 301]", want: true},
		{name: "no shared cipher", reason: "tls: no cipher suite supported by both client and server", want: true},
		{name: "bad certificate", reason: "remote error: tls: bad certificate", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isLikelyScannerTLSReason(tc.reason); got != tc.want {
				t.Fatalf("got %v, want %v for reason %q", got, tc.want, tc.reason)
			}
		})
	}
}

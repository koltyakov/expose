package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

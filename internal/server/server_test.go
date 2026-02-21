package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
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

	_, cleanup, err := readLimitedBody(w, req, 4)
	if err == nil {
		cleanup()
	}
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

func TestRouteCacheDeleteByTunnelID(t *testing.T) {
	cache := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	cache.set("a.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t1"}})
	cache.set("b.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t1"}})
	cache.set("c.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t2"}})

	cache.deleteByTunnelID("t1")

	if _, ok := cache.get("a.example.com"); ok {
		t.Fatal("expected a.example.com cache entry to be deleted")
	}
	if _, ok := cache.get("b.example.com"); ok {
		t.Fatal("expected b.example.com cache entry to be deleted")
	}
	if _, ok := cache.get("c.example.com"); !ok {
		t.Fatal("expected c.example.com cache entry to remain")
	}
}

func TestRouteCacheSetReindexesTunnelLookup(t *testing.T) {
	cache := routeCache{
		entries:       make(map[string]routeCacheEntry),
		hostsByTunnel: make(map[string]map[string]struct{}),
	}

	cache.set("same.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "old"}})
	cache.set("same.example.com", domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "new"}})

	cache.deleteByTunnelID("old")
	if _, ok := cache.get("same.example.com"); !ok {
		t.Fatal("expected host to remain after deleting old tunnel index")
	}

	cache.deleteByTunnelID("new")
	if _, ok := cache.get("same.example.com"); ok {
		t.Fatal("expected host to be deleted with new tunnel index")
	}
}

func TestRouteCacheGetEvictsExpiredEntry(t *testing.T) {
	cache := routeCache{
		entries: make(map[string]routeCacheEntry),
		hostsByTunnel: map[string]map[string]struct{}{
			"t1": {"expired.example.com": {}},
		},
	}
	cache.entries["expired.example.com"] = routeCacheEntry{
		route:             domain.TunnelRoute{Tunnel: domain.Tunnel{ID: "t1"}},
		expiresAtUnixNano: time.Now().Add(-time.Second).UnixNano(),
	}

	if _, ok := cache.get("expired.example.com"); ok {
		t.Fatal("expected expired entry to miss")
	}

	cache.mu.RLock()
	_, entryExists := cache.entries["expired.example.com"]
	_, indexExists := cache.hostsByTunnel["t1"]
	cache.mu.RUnlock()
	if entryExists {
		t.Fatal("expected expired entry to be evicted")
	}
	if indexExists {
		t.Fatal("expected tunnel index to be evicted for expired entry")
	}
}

func TestSessionWSPendingSend(t *testing.T) {
	ch := make(chan tunnelproto.Message, 1)
	sess := &session{wsPending: map[string]chan tunnelproto.Message{"stream-1": ch}}
	msg := tunnelproto.Message{Kind: tunnelproto.KindWSData}

	if ok := sess.wsPendingSend("stream-1", msg, 0); !ok {
		t.Fatal("expected wsPendingSend to succeed for buffered channel")
	}

	select {
	case got := <-ch:
		if got.Kind != tunnelproto.KindWSData {
			t.Fatalf("expected ws data message, got %q", got.Kind)
		}
	default:
		t.Fatal("expected message in ws pending channel")
	}
}

func TestSessionWSPendingSendTimeout(t *testing.T) {
	ch := make(chan tunnelproto.Message)
	sess := &session{wsPending: map[string]chan tunnelproto.Message{"stream-1": ch}}

	start := time.Now()
	ok := sess.wsPendingSend("stream-1", tunnelproto.Message{Kind: tunnelproto.KindWSData}, 15*time.Millisecond)
	if ok {
		t.Fatal("expected wsPendingSend to fail on timeout")
	}
	if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
		t.Fatalf("expected wsPendingSend to wait before timing out, elapsed=%s", elapsed)
	}
}

func TestInjectForwardedFor(t *testing.T) {
	headers := map[string][]string{
		"X-Forwarded-For": {"1.2.3.4"},
	}
	injectForwardedFor(headers, "5.6.7.8:1234")
	if got := headers["X-Forwarded-For"]; len(got) != 1 || got[0] != "1.2.3.4, 5.6.7.8" {
		t.Fatalf("expected appended X-Forwarded-For, got %v", got)
	}
}

func TestInjectForwardedForCanonicalizesHeaderKey(t *testing.T) {
	headers := map[string][]string{
		"x-forwarded-for": {"9.9.9.9"},
	}
	injectForwardedFor(headers, "8.8.8.8")
	if _, ok := headers["x-forwarded-for"]; ok {
		t.Fatal("expected non-canonical X-Forwarded-For key to be removed")
	}
	if got := headers["X-Forwarded-For"]; len(got) != 1 || got[0] != "9.9.9.9, 8.8.8.8" {
		t.Fatalf("expected canonicalized appended header, got %v", got)
	}
}

func TestQueueDomainTouchDeduplicates(t *testing.T) {
	srv := &Server{
		domainTouches: make(chan string, 4),
		domainTouched: make(map[string]struct{}),
	}

	srv.queueDomainTouch("domain-1")
	srv.queueDomainTouch("domain-1")
	if got := len(srv.domainTouches); got != 1 {
		t.Fatalf("expected deduplicated queue length 1, got %d", got)
	}

	id := <-srv.domainTouches
	srv.completeDomainTouch(id)

	srv.queueDomainTouch("domain-1")
	if got := len(srv.domainTouches); got != 1 {
		t.Fatalf("expected requeue after completion, got %d", got)
	}
}

func TestQueueDomainTouchReleasesDedupOnOverflow(t *testing.T) {
	srv := &Server{
		domainTouches: make(chan string, 1),
		domainTouched: make(map[string]struct{}),
	}

	srv.queueDomainTouch("domain-1")
	srv.queueDomainTouch("domain-2") // dropped because queue is full

	if got := len(srv.domainTouches); got != 1 {
		t.Fatalf("expected queue length 1, got %d", got)
	}
	if ok := srv.reserveDomainTouch("domain-2"); !ok {
		t.Fatal("expected dropped domain touch to be released from dedupe tracking")
	}
	srv.completeDomainTouch("domain-2")
}

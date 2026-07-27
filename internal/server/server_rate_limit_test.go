package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

func TestPreAuthLimiterRejectsBeforeStoreAccess(t *testing.T) {
	t.Parallel()

	srv := &Server{authLimiter: newConfiguredRateLimiter(0, 1, time.Minute)}
	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/tunnels/register", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	if !srv.allowPreAuthRequest(first, req) {
		t.Fatal("first request should be allowed")
	}
	second := httptest.NewRecorder()
	if srv.allowPreAuthRequest(second, req) {
		t.Fatal("second request should be throttled")
	}
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimiterAllow(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// First burst should succeed up to the burst limit.
	for i := range int(regBurstLimit) {
		if !rl.allow("key-a") {
			t.Fatalf("expected allow on burst iteration %d", i)
		}
	}
	// Next call should be rate-limited.
	if rl.allow("key-a") {
		t.Fatal("expected rate limit after burst exhaustion")
	}
}

func TestRateLimiterIsolatesKeys(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// Exhaust key-a.
	for range int(regBurstLimit) {
		rl.allow("key-a")
	}
	if rl.allow("key-a") {
		t.Fatal("expected key-a to be rate-limited")
	}

	// key-b should still have its full burst available.
	if !rl.allow("key-b") {
		t.Fatal("expected key-b to be allowed independently")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()

	// Exhaust burst.
	for range int(regBurstLimit) {
		rl.allow("key-c")
	}
	if rl.allow("key-c") {
		t.Fatal("expected rate limit")
	}

	// Simulate passage of time by directly manipulating the bucket.
	s := rl.shard("key-c")
	s.mu.Lock()
	b := s.buckets["key-c"]
	b.lastCheck = b.lastCheck.Add(-1 * time.Second)
	s.mu.Unlock()

	// After 1 second at 5/s rate, at least 1 token should be available.
	if !rl.allow("key-c") {
		t.Fatal("expected allow after time passage")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()
	rl.allow("stale-key")

	// Age the bucket beyond cleanup threshold.
	s := rl.shard("stale-key")
	s.mu.Lock()
	s.buckets["stale-key"].lastCheck = time.Now().Add(-(regCleanupAge + time.Minute))
	s.mu.Unlock()

	rl.cleanup()

	s.mu.Lock()
	_, exists := s.buckets["stale-key"]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected stale bucket to be cleaned up")
	}
}

func TestRateLimiterConcurrent(t *testing.T) {
	t.Parallel()

	rl := newRateLimiter()
	const goroutines = 32
	const keysPerGoroutine = 10

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Go(func() {
			for k := range keysPerGoroutine {
				key := fmt.Sprintf("key-%d-%d", g, k)
				rl.allow(key)
			}
		})
	}
	wg.Wait()
}

func TestClientIPIgnoresSpoofedXFFFromUntrustedSource(t *testing.T) {
	t.Parallel()

	srv := New(config.ServerConfig{
		AccessCookieSecret: "test-secret",
		TrustedProxyCIDRs:  []string{"10.0.0.0/8"},
	}, nil, nil, "test")

	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := srv.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("clientIP with untrusted peer = %q, want remote addr", got)
	}

	// No trusted proxies configured: XFF is always ignored (current behavior).
	srv = New(config.ServerConfig{AccessCookieSecret: "test-secret"}, nil, nil, "test")
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := srv.clientIP(req); got != "203.0.113.7" {
		t.Fatalf("clientIP without trusted proxies = %q, want remote addr", got)
	}
}

// A client can send several X-Forwarded-For headers. If only the first were
// consulted, a proxy that forwards them verbatim instead of collapsing them
// would leave the trusted-hop walk running over a header the client fully
// controls, letting it pick its own rate-limit identity.
func TestClientIPConsidersAllXFFHeaders(t *testing.T) {
	t.Parallel()

	srv := New(config.ServerConfig{
		AccessCookieSecret: "test-secret",
		TrustedProxyCIDRs:  []string{"10.0.0.0/8"},
	}, nil, nil, "test")

	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "10.2.3.4:443"
	// Spoofed header first, the trusted proxy's own append second.
	req.Header.Add("X-Forwarded-For", "1.1.1.1")
	req.Header.Add("X-Forwarded-For", "198.51.100.9")
	if got := srv.clientIP(req); got != "198.51.100.9" {
		t.Fatalf("clientIP = %q, want the rightmost untrusted hop across all headers", got)
	}

	// A malformed hop anywhere to the right still fails closed to the peer.
	req.Header.Del("X-Forwarded-For")
	req.Header.Add("X-Forwarded-For", "198.51.100.9")
	req.Header.Add("X-Forwarded-For", "not-an-ip")
	if got := srv.clientIP(req); got != "10.2.3.4" {
		t.Fatalf("clientIP = %q, want peer fallback on malformed hop", got)
	}
}

func TestClientIPResolvesXFFBehindTrustedProxy(t *testing.T) {
	t.Parallel()

	srv := New(config.ServerConfig{
		AccessCookieSecret: "test-secret",
		TrustedProxyCIDRs:  []string{"10.0.0.0/8", "192.168.0.0/16"},
	}, nil, nil, "test")

	cases := []struct {
		name string
		xff  string
		want string
	}{
		{"single client hop", "198.51.100.9", "198.51.100.9"},
		{"rightmost untrusted wins", "203.0.113.1, 198.51.100.9, 10.1.1.1", "198.51.100.9"},
		{"spoofed leftmost entries ignored", "1.1.1.1, 2.2.2.2, 198.51.100.9", "198.51.100.9"},
		{"all trusted falls back to leftmost", "10.0.0.1, 192.168.1.1", "10.0.0.1"},
		{"malformed hop fails closed", "not-an-ip, 10.0.0.1", "10.2.3.4"},
		{"empty header uses peer", "", "10.2.3.4"},
		{"ipv6 client", "2001:db8::1, 10.0.0.1", "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
			req.RemoteAddr = "10.2.3.4:443"
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := srv.clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFailedAuthThrottleSeparatesClientsBehindTrustedProxy(t *testing.T) {
	t.Parallel()

	srv := &Server{
		accessLimiter:  newConfiguredRateLimiter(0, 1, time.Minute),
		trustedProxies: mustParsePrefixes(t, []string{"10.0.0.0/8"}),
	}
	req := func(xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
		r.RemoteAddr = "10.2.3.4:443"
		r.Header.Set("X-Forwarded-For", xff)
		return r
	}
	route := domain.TunnelRoute{Domain: domain.Domain{Hostname: "demo.example.com"}}

	// First failure for client A consumes its single token; the next attempt
	// is throttled, while client B behind the same proxy keeps its budget.
	srv.accessLimiter.allow(srv.accessAuthLimitKey(route, req("198.51.100.1")))
	if !srv.accessLimiter.exhausted(srv.accessAuthLimitKey(route, req("198.51.100.1"))) {
		t.Fatal("expected client A to be throttled")
	}
	if srv.accessLimiter.exhausted(srv.accessAuthLimitKey(route, req("198.51.100.2"))) {
		t.Fatal("client B must not share client A's throttle bucket")
	}
}

func TestACMEIssuanceLimiterRejectsOverQuota(t *testing.T) {
	t.Parallel()

	certDir := t.TempDir()
	srv := New(config.ServerConfig{
		AccessCookieSecret:   "test-secret",
		CertCacheDir:         certDir,
		ACMEIssueRatePerHour: 2,
	}, nil, nil, "test")
	if srv.acmeIssueLimiter == nil {
		t.Fatal("expected acme issue limiter to be configured")
	}

	if !srv.allowACMEIssuance("a.example.com") {
		t.Fatal("first issuance should be allowed")
	}
	for range 20 {
		if !srv.allowACMEIssuance("a.example.com") {
			t.Fatal("repeated handshakes for one admitted host must not consume more tokens")
		}
	}
	if !srv.allowACMEIssuance("b.example.com") {
		t.Fatal("second issuance should be allowed")
	}
	if srv.allowACMEIssuance("c.example.com") {
		t.Fatal("issuance beyond the hourly budget must be rejected")
	}

	// Hosts with an already-cached certificate bypass the limiter (autocert
	// consults HostPolicy on every handshake, before its own cache).
	if err := os.WriteFile(filepath.Join(certDir, "c.example.com"), []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !srv.allowACMEIssuance("c.example.com") {
		t.Fatal("cached certificate must bypass the issuance limiter")
	}
}

func TestACMEIssuanceLimiterDisabledByDefault(t *testing.T) {
	t.Parallel()

	srv := New(config.ServerConfig{AccessCookieSecret: "test-secret"}, nil, nil, "test")
	if srv.acmeIssueLimiter != nil {
		t.Fatal("expected limiter to be disabled when rate is 0")
	}
	if !srv.allowACMEIssuance("a.example.com") {
		t.Fatal("disabled limiter must allow issuance")
	}
}

func mustParsePrefixes(t *testing.T, cidrs []string) []netip.Prefix {
	t.Helper()
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func BenchmarkRateLimiterAllowSingleKey(b *testing.B) {
	rl := newRateLimiter()
	b.ReportAllocs()
	for b.Loop() {
		rl.allow("bench-key")
	}
}

func BenchmarkRateLimiterAllowDistinctKeys(b *testing.B) {
	rl := newRateLimiter()
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}
	i := 0
	b.ReportAllocs()
	for b.Loop() {
		rl.allow(keys[i%len(keys)])
		i++
	}
}

func BenchmarkRateLimiterAllowParallel(b *testing.B) {
	rl := newRateLimiter()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.allow(fmt.Sprintf("key-%d", i%100))
			i++
		}
	})
}

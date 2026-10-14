package waf

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const benchChromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func benchFirewall() *firewall {
	return &firewall{
		rules:      defaultRules(),
		bodyLimit:  16 * 1024,
		maxURI:     maxURILength,
		maxHeaders: maxHeaderCount,
	}
}

// benchJSONBody builds a JSON object of roughly target bytes with all-distinct
// keys and values, the worst case for body value extraction.
func benchJSONBody(target int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; b.Len() < target; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "%q:%q", fmt.Sprintf("k%06d", i), fmt.Sprintf("v%06dabcdef", i))
	}
	b.WriteString("}")
	return b.String()
}

// BenchmarkCheckNoBody covers the common case: a plain browser GET with no
// body, where every rule still evaluates URI, path, query, UA and headers.
func BenchmarkCheckNoBody(b *testing.B) {
	fw := benchFirewall()
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/items?page=2&sort=name", nil)
		r.Header.Set("User-Agent", benchChromeUA)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Sec-Ch-Ua", `"Chromium";v="120"`)
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Referer", "https://example.com/")
		r.Header.Set("Cookie", "sid=abc123")
		if matched, rule := fw.check(r); matched {
			b.Fatalf("unexpected match: %s", rule)
		}
	}
}

// BenchmarkScannerUA isolates the User-Agent rule, which runs on every request
// that carries a UA header.
func BenchmarkScannerUA(b *testing.B) {
	fw := benchFirewall()
	b.ReportAllocs()
	for b.Loop() {
		if fw.matchUserAgent(benchChromeUA) {
			b.Fatal("unexpected scanner match")
		}
	}
}

func benchCheckJSON(b *testing.B, size int) {
	fw := benchFirewall()
	body := []byte(benchJSONBody(size))
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", benchChromeUA)
		if matched, rule := fw.check(r); matched {
			b.Fatalf("unexpected match: %s", rule)
		}
	}
}

// BenchmarkCheckJSONBody1K/4K/15K exercise body extraction and matching at
// sizes under the inspection limit; 32K exceeds it and is truncated.
func BenchmarkCheckJSONBody1K(b *testing.B)  { benchCheckJSON(b, 1*1024) }
func BenchmarkCheckJSONBody4K(b *testing.B)  { benchCheckJSON(b, 4*1024) }
func BenchmarkCheckJSONBody15K(b *testing.B) { benchCheckJSON(b, 15*1024) }
func BenchmarkCheckJSONBody32K(b *testing.B) { benchCheckJSON(b, 32*1024) }

// BenchmarkCollectJSONBody separates extraction costs from rule matching and
// request construction. The 32K document uses the same truncated 16K preview
// as the firewall benchmarks.
func BenchmarkCollectJSONBody(b *testing.B) {
	for _, size := range []int{1024, 4 * 1024, 15 * 1024, 32 * 1024} {
		b.Run(fmt.Sprintf("%dK", size/1024), func(b *testing.B) {
			body := []byte(benchJSONBody(size))
			if len(body) > 16*1024 {
				body = body[:16*1024]
			}
			b.ReportAllocs()
			for b.Loop() {
				set := newValueSet(len(body) * bodyScanBudgetFactor)
				collectJSONBodyValues(set, body)
				if set.dropped || set.empty() {
					b.Fatal("unexpected extraction overflow or empty result")
				}
			}
		})
	}
}

// BenchmarkCheckMetadata excludes request construction and uses no listener or
// network traffic. These fixtures exercise benign UA/cookie regex work and
// encoded/unencoded variants without exempting any inspected header.
func BenchmarkCheckMetadata(b *testing.B) {
	for _, fixture := range []struct{ name, uri, ua, cookie string }{
		{"chrome", "/api/v1/items?page=2&sort=name", benchChromeUA, "sid=abc123; theme=dark"},
		{"safari", "/api/v1/items?page=2&sort=name", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15", "sid=abc123; theme=dark"},
		{"android", "/api/v1/items?page=2&sort=name", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36", "sid=abc123; theme=dark"},
		{"cookies", "/api/v1/items?page=2&sort=name", benchChromeUA, strings.Repeat("sid=abc123; theme=dark; ", 16)},
		{"encoded", "/api/v1/items?q=HELLO%2520WORLD%2Bthere", benchChromeUA, "sid=abc123; theme=dark"},
		{"uppercase", "/API/ITEMS?q=HELLO", benchChromeUA, "sid=abc123; theme=dark"},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			fw := benchFirewall()
			r := httptest.NewRequest(http.MethodGet, fixture.uri, nil)
			r.Header.Set("User-Agent", fixture.ua)
			r.Header.Set("Accept", "text/html")
			r.Header.Set("Accept-Language", "en-US,en;q=0.9")
			r.Header.Set("Referer", "https://example.com/")
			r.Header.Set("Cookie", fixture.cookie)
			b.ReportAllocs()
			for b.Loop() {
				if matched, rule := fw.check(r); matched {
					b.Fatalf("unexpected match: %s", rule)
				}
			}
		})
	}
}

func BenchmarkRequestView(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/API/ITEMS?q=HELLO", nil)
	r.Header.Set("User-Agent", benchChromeUA)
	r.Header.Set("Cookie", "sid=abc123; theme=dark")
	b.ReportAllocs()
	for b.Loop() {
		_ = newRequestView(r, maxURILength, maxHeaderCount)
	}
}

func BenchmarkCheckStructuralLimit(b *testing.B) {
	fw := benchFirewall()
	r := httptest.NewRequest(http.MethodPost, "/"+strings.Repeat("%41", maxURILength), nil)
	r.Header.Set("X-Custom", strings.Repeat("UPPERCASE", 1024))
	b.ReportAllocs()
	for b.Loop() {
		if matched, rule := fw.check(r); !matched || rule != "uri-too-long" {
			b.Fatalf("unexpected structural result: %v/%s", matched, rule)
		}
	}
}

func BenchmarkCheckTruncatedJSONString(b *testing.B) {
	fw := benchFirewall()
	body := []byte(`{"pad":"` + strings.Repeat("a", 32*1024) + `"}`)
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequest(http.MethodPost, "/api/items", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("User-Agent", benchChromeUA)
		if matched, rule := fw.check(r); matched {
			b.Fatalf("unexpected match: %s", rule)
		}
	}
}

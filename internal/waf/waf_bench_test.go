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

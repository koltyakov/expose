package waf

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenericBodyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty string", "", nil},
		{"plain text", "hello", []string{"hello"}},
		{"url encoded", "hello%20world", []string{"hello%20world", "hello world"}},
		{"plus encoded", "hello+world", []string{"hello+world", "hello world"}},
		{"double encoded", "%2527", []string{"%2527", "%27", "'"}},
		{"no encoding", "plain", []string{"plain"}},
		{"percent but invalid escape", "100%done", []string{"100%done"}},
		{"plus and percent", "a+b%20c", []string{"a+b%20c", "a b c", "a b%20c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := genericBodyValues(tt.raw)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("length mismatch: got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSensitiveBodyField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		field     string
		sensitive bool
	}{
		{"empty", "", false},
		{"username", "username", false},
		{"email", "email", false},
		{"password", "password", true},
		{"Password uppercase", "Password", true},
		{"user_password", "user_password", true},
		{"passwd", "passwd", true},
		{"passphrase", "passphrase", true},
		{"passcode", "passcode", true},
		{"pin exact", "pin", true},
		{"underscore pin suffix", "security_pin", true},
		{"hyphen pin suffix", "security-pin", true},
		{"pin as prefix", "pincode", false},
		{"whitespace padded", "  password  ", true},
		{"mixed case passwd", "  PASSWD  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sensitiveBodyField(tt.field)
			if got != tt.sensitive {
				t.Errorf("sensitiveBodyField(%q) = %v, want %v", tt.field, got, tt.sensitive)
			}
		})
	}
}

func TestCollectJSONStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     any
		parentKey string
		wantLen   int
	}{
		{"nil value", nil, "", 0},
		{"string value", "hello", "", 1},
		{"number value", json.Number("42"), "", 1},
		{"sensitive parent skipped", "secret123", "password", 0},
		{"sensitive parent number", json.Number("1234"), "user_pin", 0},
		{"nested map", map[string]any{"a": "val"}, "", 2}, // key "a" + value "val"
		{"array of strings", []any{"x", "y"}, "", 2},
		{"nested array in map", map[string]any{"items": []any{"one", "two"}}, "", 3}, // "items" + "one" + "two"
		{"bool value ignored", true, "", 0},
		{"empty map", map[string]any{}, "", 0},
		{"empty array", []any{}, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out []string
			collectJSONStrings(tt.value, tt.parentKey, &out)
			if len(out) != tt.wantLen {
				t.Errorf("got %d values %v, want %d", len(out), out, tt.wantLen)
			}
		})
	}
}

func TestCollectBodyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
		limit       int64
		wantNil     bool
		wantMinLen  int
	}{
		{
			name:    "nil body",
			limit:   1024,
			wantNil: true,
		},
		{
			name:    "zero limit",
			body:    "data",
			limit:   0,
			wantNil: true,
		},
		{
			name:        "form urlencoded",
			contentType: "application/x-www-form-urlencoded",
			body:        "key=value&foo=bar",
			limit:       1024,
			wantMinLen:  3, // key, value, foo, bar (at least 3)
		},
		{
			name:        "json body",
			contentType: "application/json",
			body:        `{"name":"test","count":5}`,
			limit:       1024,
			wantMinLen:  3, // "name", "test", "count", "5"
		},
		{
			name:        "json+suffix content type",
			contentType: "application/vnd.api+json",
			body:        `{"query":"hello"}`,
			limit:       1024,
			wantMinLen:  2, // "query", "hello"
		},
		{
			name:        "multipart skipped",
			contentType: "multipart/form-data; boundary=----",
			body:        "------\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ndata\r\n------",
			limit:       1024,
			wantNil:     true,
		},
		{
			name:        "octet-stream skipped",
			contentType: "application/octet-stream",
			body:        "\x00\x01\x02\x03",
			limit:       1024,
			wantNil:     true,
		},
		{
			name:        "plain text utf8",
			contentType: "text/plain",
			body:        "SELECT * FROM users",
			limit:       1024,
			wantMinLen:  1,
		},
		{
			name:        "binary non-utf8 skipped",
			contentType: "application/x-custom",
			body:        "\x80\x81\x82\x83\xff\xfe",
			limit:       1024,
			wantNil:     true,
		},
		{
			name:        "body exceeds limit is truncated",
			contentType: "text/plain",
			body:        strings.Repeat("a", 100),
			limit:       10,
			wantMinLen:  1,
		},
		{
			name:        "invalid json falls back to generic",
			contentType: "application/json",
			body:        `{invalid json`,
			limit:       1024,
			wantMinLen:  1,
		},
		{
			name:        "json with trailing data falls back to generic",
			contentType: "application/json",
			body:        `{"a":"b"}{"c":"d"}`,
			limit:       1024,
			wantMinLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var r *http.Request
			if tt.body != "" {
				r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
				if tt.contentType != "" {
					r.Header.Set("Content-Type", tt.contentType)
				}
			}

			got := collectBodyValues(r, tt.limit, nil)

			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if len(got) < tt.wantMinLen {
				t.Fatalf("got %d values %v, want at least %d", len(got), got, tt.wantMinLen)
			}
		})
	}
}

func TestCollectBodyValuesBodyGuard(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"q":"test"}`))
	r.Header.Set("Content-Type", "application/json")

	// Body guard returns false — inspection skipped
	got := collectBodyValues(r, 1024, func(*http.Request) bool { return false })
	if got != nil {
		t.Fatalf("expected nil when body guard rejects, got %v", got)
	}
}

func TestCollectBodyValuesNoBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	got := collectBodyValues(r, 1024, nil)
	if got != nil {
		t.Fatalf("expected nil for http.NoBody, got %v", got)
	}
}

func TestPreviewRequestBodyRestoresBody(t *testing.T) {
	t.Parallel()

	const payload = "original body content"
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	r.Header.Set("Content-Type", "text/plain")

	body, mediaType, ok := previewRequestBody(r, 1024)
	if !ok {
		t.Fatal("previewRequestBody returned ok=false")
	}
	if string(body) != payload {
		t.Fatalf("preview body = %q, want %q", body, payload)
	}
	if mediaType != "text/plain" {
		t.Fatalf("media type = %q, want text/plain", mediaType)
	}

	// Body should still be readable after preview
	restored, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading restored body: %v", err)
	}
	if string(restored) != payload {
		t.Fatalf("restored body = %q, want %q", restored, payload)
	}
}

func TestCollectFormBodyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		wantMinLen int
	}{
		{"simple form", "a=1&b=2", 4},                              // keys a, b + values 1, 2
		{"sensitive field skipped", "password=secret&name=joe", 3}, // password, name, joe (secret skipped)
		{"invalid form falls back", "%%%", 1},                      // falls back to genericBodyValues
		{"empty values form", "key=", 1},                           // just the key
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := collectFormBodyValues(tt.raw)
			if len(got) < tt.wantMinLen {
				t.Fatalf("got %d values %v, want at least %d", len(got), got, tt.wantMinLen)
			}
		})
	}
}

func TestCollectJSONBodyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantMinLen int
	}{
		{"simple object", `{"a":"b"}`, 2},
		{"nested object", `{"outer":{"inner":"val"}}`, 3},
		{"array", `{"items":["x","y"]}`, 3},
		{"with number", `{"count":42}`, 2},
		{"sensitive skipped", `{"password":"secret","name":"joe"}`, 3}, // password, name, joe (secret skipped)
		{"invalid json", `not json`, 1},
		{"trailing json", `{"a":"b"} extra`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := collectJSONBodyValues([]byte(tt.body))
			if len(got) < tt.wantMinLen {
				t.Fatalf("got %d values %v, want at least %d", len(got), got, tt.wantMinLen)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	t.Parallel()

	var dst []string
	appendUnique(&dst, "a")
	appendUnique(&dst, "b")
	appendUnique(&dst, "a") // duplicate
	appendUnique(&dst, "")  // empty, should be ignored

	if len(dst) != 2 {
		t.Fatalf("expected 2 unique values, got %v", dst)
	}
	if dst[0] != "a" || dst[1] != "b" {
		t.Fatalf("unexpected values: %v", dst)
	}
}

func TestAppendAllUnique(t *testing.T) {
	t.Parallel()

	var dst []string
	appendAllUnique(&dst, "a", "b", "a", "c")
	if len(dst) != 3 {
		t.Fatalf("expected 3 unique values, got %v", dst)
	}
}

func TestNewRequestView(t *testing.T) {
	t.Parallel()

	t.Run("double encoding detection", func(t *testing.T) {
		t.Parallel()
		// %2527 → first decode → %27 → second decode → '
		r := httptest.NewRequest(http.MethodGet, "/search?q=%2527test", nil)
		view := newRequestView(r, maxURILength, maxHeaderCount)
		if view.doubleDecoded == view.decodedQuery {
			t.Error("expected doubleDecoded to differ from decodedQuery for double-encoded input")
		}
	})

	t.Run("plus decoding", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/search?q=hello+world", nil)
		view := newRequestView(r, maxURILength, maxHeaderCount)
		if view.plusDecoded != "q=hello world" {
			t.Errorf("plusDecoded = %q, want %q", view.plusDecoded, "q=hello world")
		}
	})

	t.Run("uri too long", func(t *testing.T) {
		t.Parallel()
		longPath := "/" + strings.Repeat("x", maxURILength+1)
		r := httptest.NewRequest(http.MethodGet, longPath, nil)
		view := newRequestView(r, maxURILength, maxHeaderCount)
		if !view.uriTooLong {
			t.Error("expected uriTooLong to be true")
		}
	})

	t.Run("too many headers", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for i := range maxHeaderCount + 5 {
			r.Header.Add("X-Test-"+strings.Repeat("a", i+1), "val")
		}
		view := newRequestView(r, maxURILength, maxHeaderCount)
		if !view.tooManyHdrs {
			t.Error("expected tooManyHdrs to be true")
		}
	})

	t.Run("skip headers are excluded", func(t *testing.T) {
		t.Parallel()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer token")
		r.Header.Set("Accept", "text/html")
		r.Header.Set("X-Custom", "value")
		view := newRequestView(r, maxURILength, maxHeaderCount)
		// Only X-Custom should appear
		if len(view.headerValues) != 1 || view.headerValues[0] != "value" {
			t.Errorf("expected only custom header, got %v", view.headerValues)
		}
	})
}

func TestClientAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		xff  string
		addr string
		want string
	}{
		{"no xff", "", "192.168.1.1:1234", "192.168.1.1:1234"},
		{"single xff", "10.0.0.1", "", "10.0.0.1"},
		{"multiple xff", "10.0.0.1, 10.0.0.2", "", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.addr != "" {
				r.RemoteAddr = tt.addr
			}
			got := clientAddr(r)
			if got != tt.want {
				t.Errorf("clientAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

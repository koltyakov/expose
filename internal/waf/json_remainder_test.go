package waf

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWAFJSONRemainder(t *testing.T) {
	t.Parallel()
	const attack = "<script>alert(1)</script>"
	var escaped strings.Builder
	for _, char := range attack {
		fmt.Fprintf(&escaped, `\u%04x`, char)
	}
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"after complete document", `{"ok":1} ` + attack, true},
		{"inside incomplete string", `{"ok":1,"bad":"` + attack, true},
		{"encoded tail", `{"ok":1} ` + url.QueryEscape(attack), true},
		{"double encoded incomplete string", `{"ok":1,"bad":"` + url.QueryEscape(url.QueryEscape(attack)), true},
		{"encoded before unfinished percent escape", `{"ok":1,"bad":"` + url.QueryEscape(attack) + `%4`, true},
		{"encoded before malformed percent escape", `{"ok":1} ` + url.QueryEscape(attack) + `%GG`, true},
		{"double encoded before unfinished escape", `{"ok":1,"bad":"` + url.QueryEscape(url.QueryEscape(attack)) + `%25`, true},
		{"JSON escaped incomplete string", `{"ok":1,"bad":"` + escaped.String(), true},
		{"JSON escaped first string", `"` + escaped.String(), true},
		{"JSON escaped first key", `{"` + escaped.String(), true},
		{"JSON escaped before invalid escape", `{"ok":1,"bad":"` + escaped.String() + `\q`, true},
		{"JSON escaped before unfinished escape", `{"ok":1,"bad":"` + escaped.String() + `\u00`, true},
		{"escaped quote and slash", `{"ok":1,"bad":"\"<scr\u0069pt>\"<\/script>`, true},
		{"comma after successful number", `[1,` + attack, true},
		{"after successful boolean", `{"ok":true} ` + attack, true},
		{"another JSON document", `{"ok":1}{"q":"` + attack + `"}`, true},
		{"complete first string", `"` + attack + `"`, true},
		{"valid duplicate keys", `{"q":"` + attack + `","q":"safe"}`, true},
		{"normal document with whitespace", "{\"ok\":1} \t\r\n", false},
		{"benign malformed complete document", `{"ok":1} not json`, false},
		{"benign incomplete string", `{"ok":1,"bad":"safe`, false},
		{"benign incomplete JSON escape", `{"ok":1,"bad":"\u0068ello\u00`, false},
		{"benign plus only before unfinished escape", `{"ok":1,"bad":"` + strings.Repeat("a+", 1000) + `%`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var matchedRule string
			handler := newTestMiddlewareWithConfig(t, Config{
				Enabled: true, BodyInspectLimit: 16 * 1024,
				OnBlock: func(event BlockEvent) { matchedRule = event.Rule },
			})
			r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, r)
			if got := rr.Code == http.StatusForbidden; got != tt.want {
				t.Fatalf("blocked = %v, want %v; rule = %q", got, tt.want, matchedRule)
			}
			if tt.want && matchedRule != "xss" {
				t.Fatalf("expected actual tail detection by xss, got %q", matchedRule)
			}
		})
	}
}

func TestJSONRemainderKeepsTokenBoundaries(t *testing.T) {
	t.Parallel()
	const body = `{"ok":1,"bad":"unfinished`
	values := collectValuesForTest(func(set *valueSet) { collectJSONBodyValues(set, []byte(body)) })
	want := []string{"ok", "1", "bad", `:"unfinished`}
	if len(values) != len(want) {
		t.Fatalf("values = %q, want %q", values, want)
	}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("values = %q, want %q", values, want)
		}
	}
}

func TestWAFJSONInspectionLimitRemainder(t *testing.T) {
	t.Parallel()
	const limit = 16 * 1024
	for _, padding := range []string{strings.Repeat("a", 32*1024), strings.Repeat(`\u0061`, 8*1024)} {
		body := `{"pad":"` + padding + `","q":"<script>alert(1)</script>"}`
		var replayed string
		handler := NewMiddleware(Config{Enabled: true, BodyInspectLimit: limit}, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			replayed = string(data)
			w.WriteHeader(http.StatusOK)
		}))
		r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if rr.Code != http.StatusOK || replayed != body {
			t.Fatal("ordinary truncated JSON must pass and preserve the entire downstream body")
		}
	}

	// Complete attack text inside a string whose closing quote lies beyond the
	// preview limit still needs inspection, unlike bytes wholly beyond the limit.
	body := `{"ok":1,"q":"<script>alert(1)</script>` + strings.Repeat("a", limit)
	r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	assertBlocked(t, newTestMiddlewareWithConfig(t, Config{Enabled: true, BodyInspectLimit: limit}), r)

	for _, encoded := range []string{url.QueryEscape("<script>alert(1)</script>") + "%4", url.QueryEscape(url.QueryEscape("<script>alert(1)</script>")) + "%25"} {
		prefix := `{"ok":1,"q":"` + encoded
		suffix := `1"}`
		if strings.HasSuffix(encoded, "%25") {
			suffix = `41"}`
		}
		// Complete the percent escape and JSON string beyond the preview. The
		// backend sees valid input, but inspection ends inside that escape.
		r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(prefix+suffix))
		r.Header.Set("Content-Type", "application/json")
		fw := benchFirewall()
		fw.bodyLimit = int64(len(prefix))
		if matched, rule := fw.check(r); !matched || rule != "xss" {
			t.Fatalf("URL escape cut at limit: matched = %v/%q, want xss", matched, rule)
		}
	}
}

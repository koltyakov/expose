package waf

import (
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWAFBodyScanBudget(t *testing.T) {
	t.Parallel()

	const attack = "<script>alert(1)</script>"
	// Wire-order decoding leaves only 23 bytes for the final 24-byte attack.
	padded := func(value string) string {
		return fmt.Sprintf(`{"z1":%q,"z2":%q,"a":%q}`,
			strings.Repeat("x", 1000)+"%2541+",
			strings.Repeat("y", 33)+"%2542+", value)
	}
	if len(padded(attack)) != 1094 {
		t.Fatal("reproducer body size changed")
	}
	var multipartBody strings.Builder
	writer := multipart.NewWriter(&multipartBody)
	field, err := writer.CreateFormField("q")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(field, strings.Repeat("x", 1000)+"%2541+"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		body        string
		contentType string
		limit       int64
		wantStatus  int
		wantRule    string
	}{
		{"late raw attack", padded(attack), "application/json", 16 * 1024, http.StatusForbidden, ""},
		{"late encoded attack", padded(url.QueryEscape(attack)), "application/json", 16 * 1024, http.StatusForbidden, ""},
		{"late double encoded attack", padded(url.QueryEscape(url.QueryEscape(attack))), "application/json", 16 * 1024, http.StatusForbidden, ""},
		{"truncated after attack", strings.TrimSuffix(padded(attack), "}") + `,"tail":"unfinished`, "application/json", int64(len(padded(attack)) + 5), http.StatusForbidden, ""},
		{"duplicate key early attack", `{"q":"` + attack + `","q":"safe"}`, "application/json", 1024, http.StatusForbidden, ""},
		{"duplicate key late encoded attack", `{"q":"safe","q":"` + url.QueryEscape(attack) + `"}`, "application/json", 1024, http.StatusForbidden, ""},
		{"duplicate benign values", `{"q":"safe","q":"safe"}`, "application/json", 1024, http.StatusOK, ""},
		{"nested late attack", `{"a":[{},true,null,42],"b":{"q":"` + attack + `"}}`, "application/json", 1024, http.StatusForbidden, ""},
		{"truncated benign document", `{"q":"safe","tail":"unfinished`, "application/json", 20, http.StatusOK, ""},
		{"exact budget with duplicate variant", "xxxxxxxx+", "text/plain", 1024, http.StatusOK, ""},
		{"benign normalization overflow", strings.Repeat("x", 1000) + "%2541+", "text/plain", 2048, http.StatusForbidden, "body-scan-budget-exceeded"},
		{"benign JSON normalization overflow", padded("safe"), "application/json", 2048, http.StatusForbidden, "body-scan-budget-exceeded"},
		{"benign form normalization overflow", "q=" + strings.Repeat("x", 1000) + "%2541%2B", "application/x-www-form-urlencoded", 2048, http.StatusForbidden, "body-scan-budget-exceeded"},
		{"benign multipart normalization overflow", multipartBody.String(), writer.FormDataContentType(), 2048, http.StatusForbidden, "body-scan-budget-exceeded"},
		{"body inspection disabled", padded(attack), "application/json", 0, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var eventRule string
			handler := newTestMiddlewareWithConfig(t, Config{
				Enabled: true, BodyInspectLimit: tt.limit,
				OnBlock: func(event BlockEvent) { eventRule = event.Rule },
			})
			r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(tt.body))
			r.Header.Set("Content-Type", tt.contentType)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, r)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; rule = %q", rr.Code, tt.wantStatus, eventRule)
			}
			if tt.wantRule != "" && eventRule != tt.wantRule {
				t.Fatalf("rule = %q, want %q", eventRule, tt.wantRule)
			}
		})
	}
}

func TestWAFBodyScanBudgetPolicy(t *testing.T) {
	t.Parallel()
	const body = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%2541+"
	for _, mode := range []string{"block", "audit", "guard"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			var eventRule, downstreamBody string
			cfg := Config{
				Enabled: true, BodyInspectLimit: 1024, AuditOnly: mode == "audit",
				OnBlock: func(event BlockEvent) { eventRule = event.Rule },
			}
			if mode == "guard" {
				cfg.ShouldInspectBody = func(*http.Request) bool { return false }
			}
			handler := NewMiddleware(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				downstreamBody = string(data)
				w.WriteHeader(http.StatusOK)
			}))
			r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(body))
			r.Header.Set("Content-Type", "text/plain")
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, r)
			wantStatus := http.StatusOK
			if mode == "block" {
				wantStatus = http.StatusForbidden
			} else if downstreamBody != body {
				t.Fatalf("downstream body = %q, want %q", downstreamBody, body)
			}
			if rr.Code != wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, wantStatus)
			}
			wantRule := "body-scan-budget-exceeded"
			if mode == "guard" {
				wantRule = ""
			}
			if eventRule != wantRule {
				t.Fatalf("rule = %q, want %q", eventRule, wantRule)
			}
		})
	}
}

package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func referencePercentDecode(raw string) string {
	if strings.Contains(raw, "%") {
		if decoded, err := url.QueryUnescape(raw); err == nil {
			return decoded
		}
	}
	return raw
}

func TestRequestViewVariantReuse(t *testing.T) {
	t.Parallel()
	for _, uri := range []string{
		"/api", "/API?q=HELLO", "/Api%2Fitem?q=UNION%20SELECT", "/api?q=%2527+or+1%253D1",
		"/api?q=a+b%20c", "/api?q=one+two", "/api?q=%GG+safe", "/api?q=%25GG+safe",
		"/api?q=%C5%BFleep%281%29", "/api?q=ſleep(1)", "/api?q=%2B", "/api?q=%252B",
	} {
		t.Run(uri, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, uri, nil)
			r.Header.Set("User-Agent", benchChromeUA)
			r.Header["X-Custom"] = []string{benchChromeUA, "UPPERCASE", "ſqlmap"}
			view := newRequestView(r, maxURILength, maxHeaderCount)
			decodedURI := referencePercentDecode(r.RequestURI)
			decodedQuery := referencePercentDecode(r.URL.RawQuery)
			pairs := []struct {
				in   scanInput
				want string
			}{
				{view.requestURI, r.RequestURI}, {view.decodedURI, decodedURI},
				{view.doubleDecodedURI, referencePercentDecode(decodedURI)}, {view.path, r.URL.Path},
				{view.rawQuery, r.URL.RawQuery}, {view.decodedQuery, decodedQuery},
				{view.plusDecoded, strings.ReplaceAll(r.URL.RawQuery, "+", " ")},
				{view.doubleDecoded, referencePercentDecode(decodedQuery)}, {view.userAgent, benchChromeUA},
			}
			for _, pair := range pairs {
				if want := newScanInput(pair.want); pair.in != want {
					t.Fatalf("scan input = %#v, want %#v", pair.in, want)
				}
			}
			got := valueStrings(view.headerValues)
			want := []string{benchChromeUA, benchChromeUA, "UPPERCASE", "ſqlmap"}
			slices.Sort(got)
			slices.Sort(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("header coverage = %q, want %q", got, want)
			}
		})
	}
}

// referenceCheck uses unfiltered regexes and scans every query/URI variant,
// including identical values. It preserves the established rule/target order.
func referenceCheck(fw *firewall, r *http.Request) (bool, string) {
	view := newRequestView(r, fw.maxURI, fw.maxHeaders)
	if view.uriTooLong {
		return true, "uri-too-long"
	}
	if view.tooManyHdrs {
		return true, "too-many-headers"
	}
	var overflow bool
	view.bodyValues, overflow = collectBodyValues(r, fw.bodyLimit, fw.bodyGuard)
	if overflow {
		return true, "body-scan-budget-exceeded"
	}
	for _, rl := range fw.rules {
		pattern := rl.pattern
		if rl.name == "scanner-ua" {
			pattern = legacyScannerPattern
		}
		matches := func(in scanInput) bool { return in.raw != "" && pattern.MatchString(in.raw) }
		if rl.targets&targetURI != 0 && slices.ContainsFunc([]scanInput{view.requestURI, view.decodedURI, view.doubleDecodedURI}, matches) {
			return true, rl.name
		}
		if rl.targets&targetPath != 0 && (rl.name != "sensitive-file-probe" || !isWellKnownPath(view.path.raw)) && matches(view.path) {
			if fw.pathRuleGuard == nil || !fw.pathRuleGuard(r, rl.name) {
				return true, rl.name
			}
		}
		if rl.targets&targetQuery != 0 && view.rawQuery.raw != "" && slices.ContainsFunc([]scanInput{view.rawQuery, view.decodedQuery, view.plusDecoded, view.doubleDecoded}, matches) {
			return true, rl.name
		}
		if rl.targets&targetUA != 0 && matches(view.userAgent) {
			return true, rl.name
		}
		if rl.targets&targetHeaders != 0 && slices.ContainsFunc(view.headerValues, matches) {
			return true, rl.name
		}
		if rl.targets&targetBody != 0 && slices.ContainsFunc(view.bodyValues, matches) {
			return true, rl.name
		}
	}
	return false, ""
}

func TestRequestCheckReferenceParity(t *testing.T) {
	t.Parallel()
	fw := benchFirewall()
	for _, payload := range ruleDifferentialCorpus() {
		for _, encoded := range []string{payload, url.QueryEscape(payload), url.QueryEscape(url.QueryEscape(payload))} {
			for _, target := range []string{"query", "header", "body", "ua"} {
				makeRequest := func() *http.Request {
					uri, body := "/api?sort=name", ""
					if target == "query" {
						uri = "/api?q=" + url.QueryEscape(encoded)
					}
					if target == "body" {
						body = fmt.Sprintf(`{"q":%q}`, encoded)
					}
					r := httptest.NewRequest(http.MethodPost, uri, strings.NewReader(body))
					r.Header.Set("Content-Type", "application/json")
					r.Header.Set("User-Agent", benchChromeUA)
					if target == "header" {
						r.Header.Set("X-Custom", encoded)
					}
					if target == "ua" {
						r.Header.Set("User-Agent", encoded)
					}
					return r
				}
				got, gotRule := fw.check(makeRequest())
				want, wantRule := referenceCheck(fw, makeRequest())
				if got != want || gotRule != wantRule {
					t.Fatalf("%s payload %q: got %v/%q, reference %v/%q", target, encoded, got, gotRule, want, wantRule)
				}
			}
		}
	}
}

func TestEarlyStructuralLimits(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, uri, header, wantRule string
		count                       int
	}{
		{"URI at limit", "/" + strings.Repeat("a", maxURILength-1), "", "", 0},
		{"URI over limit", "/" + strings.Repeat("A", maxURILength), "", "uri-too-long", 0},
		{"headers at limit", "/", "X-Custom", "", maxHeaderCount},
		{"headers over limit", "/", "X-Custom", "too-many-headers", maxHeaderCount + 1},
		{"empty values still count", "/", "X-Custom", "too-many-headers", maxHeaderCount + 1},
		{"empty value slice does not count", "/", "X-Custom", "", 0},
		{"exempt values not counted", "/", "Authorization", "", maxHeaderCount + 1},
		{"noncanonical keys keep existing semantics", "/", "authorization", "too-many-headers", maxHeaderCount + 1},
		{"URI wins over headers", "/" + strings.Repeat("%41", maxURILength), "X-Custom", "uri-too-long", maxHeaderCount + 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodPost, tt.uri, strings.NewReader("safe body"))
			if tt.header != "" {
				r.Header[tt.header] = make([]string, tt.count)
				for i := range r.Header[tt.header] {
					if tt.name != "empty values still count" {
						r.Header[tt.header][i] = "safe"
					}
				}
			}
			bodyInspected := false
			fw := benchFirewall()
			fw.bodyGuard = func(*http.Request) bool { bodyInspected = true; return true }
			got, rule := fw.check(r)
			if got != (tt.wantRule != "") || rule != tt.wantRule {
				t.Fatalf("matched = %v/%q, want %q", got, rule, tt.wantRule)
			}
			if tt.wantRule != "" {
				if bodyInspected {
					t.Fatal("structural rejection reached body inspection")
				}
				view := newRequestView(r, maxURILength, maxHeaderCount)
				if view.requestURI.raw != "" || len(view.headerValues) != 0 {
					t.Fatal("structural rejection prepared scan inputs")
				}
			}
		})
	}
}

func TestWAFRulePriorityWithBody(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct{ query, body, want string }{
		{"<script>alert(1)</script>", `{"q":"' or 1=1"}`, "sql-injection"},
		{"' or 1=1", `{"q":"<script>alert(1)</script>"}`, "sql-injection"},
		{"' or 1=1", `{"pad":"` + strings.Repeat("x", 1000) + `%2541+"}`, "body-scan-budget-exceeded"},
	} {
		r := httptest.NewRequest(http.MethodPost, "/api?q="+url.QueryEscape(tt.query), strings.NewReader(tt.body))
		r.Header.Set("Content-Type", "application/json")
		if got, rule := benchFirewall().check(r); !got || rule != tt.want {
			t.Fatalf("matched = %v/%q, want %q", got, rule, tt.want)
		}
	}
}

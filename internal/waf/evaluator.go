package waf

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/koltyakov/expose/internal/netutil"
)

// skipHeaders are headers excluded from WAF pattern matching because they
// are either safe, controlled by the browser, or cause false positives.
var skipHeaders = map[string]struct{}{
	"host":                     {},
	"accept":                   {},
	"accept-language":          {},
	"accept-encoding":          {},
	"connection":               {},
	"content-length":           {},
	"content-type":             {},
	"if-modified-since":        {},
	"if-none-match":            {},
	"cache-control":            {},
	"upgrade":                  {},
	"authorization":            {},
	"sec-websocket-key":        {},
	"sec-websocket-version":    {},
	"sec-websocket-extensions": {},
	"sec-websocket-protocol":   {},
	"sec-fetch-dest":           {},
	"sec-fetch-mode":           {},
	"sec-fetch-site":           {},
	"sec-fetch-user":           {},
	"sec-ch-ua":                {},
	"sec-ch-ua-mobile":         {},
	"sec-ch-ua-platform":       {},
}

type requestView struct {
	requestURI   string
	path         string
	rawQuery     string
	decodedQuery string
	plusDecoded  string
	userAgent    string
	headerValues []string
}

func newRequestView(r *http.Request) requestView {
	rawQuery := r.URL.RawQuery
	decodedQuery := rawQuery
	if strings.Contains(rawQuery, "%") {
		if d, err := url.QueryUnescape(rawQuery); err == nil {
			decodedQuery = d
		}
	}

	plusDecoded := rawQuery
	if strings.Contains(rawQuery, "+") {
		plusDecoded = strings.ReplaceAll(rawQuery, "+", " ")
	}

	headerValues := make([]string, 0, len(r.Header))
	for name, values := range r.Header {
		if _, skip := skipHeaders[strings.ToLower(name)]; skip {
			continue
		}
		headerValues = append(headerValues, values...)
	}

	return requestView{
		requestURI:   r.RequestURI,
		path:         r.URL.Path,
		rawQuery:     rawQuery,
		decodedQuery: decodedQuery,
		plusDecoded:  plusDecoded,
		userAgent:    r.UserAgent(),
		headerValues: headerValues,
	}
}

// check tests the request against every rule and returns on the first match.
func (fw *firewall) check(r *http.Request) (matched bool, ruleName string) {
	view := newRequestView(r)

	for i := range fw.rules {
		rl := &fw.rules[i]

		if rl.targets&targetURI != 0 && rl.pattern.MatchString(view.requestURI) {
			return true, rl.name
		}
		if rl.targets&targetPath != 0 && rl.pattern.MatchString(view.path) {
			return true, rl.name
		}
		if rl.targets&targetQuery != 0 && view.rawQuery != "" {
			if rl.pattern.MatchString(view.rawQuery) ||
				rl.pattern.MatchString(view.decodedQuery) ||
				rl.pattern.MatchString(view.plusDecoded) {
				return true, rl.name
			}
		}
		if rl.targets&targetUA != 0 && view.userAgent != "" && rl.pattern.MatchString(view.userAgent) {
			return true, rl.name
		}
		if rl.targets&targetHeaders != 0 && fw.matchHeaderValues(rl, view.headerValues) {
			return true, rl.name
		}
	}

	return false, ""
}

// matchHeaderValues inspects all non-exempt header values for a rule match.
func (fw *firewall) matchHeaderValues(rl *rule, values []string) bool {
	for _, v := range values {
		if rl.pattern.MatchString(v) {
			return true
		}
	}
	return false
}

// clientAddr extracts the remote IP for logging. It prefers X-Forwarded-For
// when set (the server already overwrites this header to prevent spoofing).
func clientAddr(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return xff
	}
	return r.RemoteAddr
}

// normalizeHost normalizes host values for stable WAF counters and events.
func normalizeHost(host string) string {
	return netutil.NormalizeHost(host)
}

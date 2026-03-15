package waf

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

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
	requestURI    string
	path          string
	rawQuery      string
	decodedQuery  string
	plusDecoded   string
	doubleDecoded string // second pass URL-decode to catch double-encoding
	userAgent     string
	headerValues  []string
	bodyValues    []string
	uriTooLong    bool // URI exceeds safety limit
	tooManyHdrs   bool // excessive header count
}

// maxURILength is the maximum URI length before the WAF considers a request
// suspicious. Very long URIs are commonly used in buffer-overflow and
// smuggling attacks. 8 KiB is the de-facto limit of most HTTP servers.
const maxURILength = 8192

// maxHeaderCount is the maximum number of non-exempt headers before the WAF
// considers a request suspicious.
const maxHeaderCount = 64

func newRequestView(r *http.Request, maxURI, maxHeaders int) requestView {
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

	// Double-decode: attackers use double-encoding (%2527 → %27 → ') to
	// bypass single-pass decoding. Perform a second URL-unescape on the
	// already-decoded value.
	doubleDecoded := decodedQuery
	if strings.Contains(decodedQuery, "%") {
		if dd, err := url.QueryUnescape(decodedQuery); err == nil && dd != decodedQuery {
			doubleDecoded = dd
		}
	}

	headerValues := make([]string, 0, len(r.Header))
	for name, values := range r.Header {
		if _, skip := skipHeaders[strings.ToLower(name)]; skip {
			continue
		}
		headerValues = append(headerValues, values...)
	}

	return requestView{
		requestURI:    r.RequestURI,
		path:          r.URL.Path,
		rawQuery:      rawQuery,
		decodedQuery:  decodedQuery,
		plusDecoded:   plusDecoded,
		doubleDecoded: doubleDecoded,
		userAgent:     r.UserAgent(),
		headerValues:  headerValues,
		uriTooLong:    len(r.RequestURI) > maxURI,
		tooManyHdrs:   len(headerValues) > maxHeaders,
	}
}

// check tests the request against every rule and returns on the first match.
func (fw *firewall) check(r *http.Request) (matched bool, ruleName string) {
	view := newRequestView(r, fw.maxURI, fw.maxHeaders)

	// Structural limits — block before regex evaluation.
	if view.uriTooLong {
		return true, "uri-too-long"
	}
	if view.tooManyHdrs {
		return true, "too-many-headers"
	}

	view.bodyValues = collectBodyValues(r, fw.bodyLimit, fw.bodyGuard)

	for i := range fw.rules {
		rl := &fw.rules[i]

		if rl.targets&targetURI != 0 && rl.pattern.MatchString(view.requestURI) {
			return true, rl.name
		}
		if rl.targets&targetPath != 0 && matchPathRule(rl, view.path) {
			return true, rl.name
		}
		if rl.targets&targetQuery != 0 && view.rawQuery != "" {
			if rl.pattern.MatchString(view.rawQuery) ||
				rl.pattern.MatchString(view.decodedQuery) ||
				rl.pattern.MatchString(view.plusDecoded) ||
				(view.doubleDecoded != view.decodedQuery && rl.pattern.MatchString(view.doubleDecoded)) {
				return true, rl.name
			}
		}
		if rl.targets&targetUA != 0 && view.userAgent != "" && rl.pattern.MatchString(view.userAgent) {
			return true, rl.name
		}
		if rl.targets&targetHeaders != 0 && fw.matchHeaderValues(rl, view.headerValues) {
			return true, rl.name
		}
		if rl.targets&targetBody != 0 && fw.matchBodyValues(rl, view.bodyValues) {
			return true, rl.name
		}
	}

	return false, ""
}

func matchPathRule(rl *rule, path string) bool {
	if rl.name == "sensitive-file-probe" && isWellKnownPath(path) {
		return false
	}
	return rl.pattern.MatchString(path)
}

func isWellKnownPath(path string) bool {
	return path == "/.well-known" || strings.HasPrefix(path, "/.well-known/")
}

// matchHeaderValues inspects all non-exempt header values for a rule match.
func (fw *firewall) matchHeaderValues(rl *rule, values []string) bool {
	return slices.ContainsFunc(values, rl.pattern.MatchString)
}

// matchBodyValues inspects normalized body fragments for a rule match.
func (fw *firewall) matchBodyValues(rl *rule, values []string) bool {
	return slices.ContainsFunc(values, rl.pattern.MatchString)
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

type replayBody struct {
	io.Reader
	io.Closer
}

func collectBodyValues(r *http.Request, limit int64, bodyGuard func(*http.Request) bool) []string {
	if r == nil || r.Body == nil || r.Body == http.NoBody || limit <= 0 {
		return nil
	}
	if bodyGuard != nil && !bodyGuard(r) {
		return nil
	}

	body, mediaType, ok := previewRequestBody(r, limit)
	if !ok || len(body) == 0 {
		return nil
	}

	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		return nil
	case mediaType == "application/x-www-form-urlencoded":
		return collectFormBodyValues(string(body))
	case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"):
		return collectJSONBodyValues(body)
	case mediaType == "application/octet-stream":
		return nil
	case utf8.Valid(body):
		return genericBodyValues(string(body))
	default:
		return nil
	}
}

func previewRequestBody(r *http.Request, limit int64) ([]byte, string, bool) {
	mediaType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if mediaType != "" {
		parsedType, _, err := mime.ParseMediaType(mediaType)
		if err == nil {
			mediaType = strings.ToLower(strings.TrimSpace(parsedType))
		}
	}

	orig := r.Body
	preview, err := io.ReadAll(io.LimitReader(orig, limit+1))
	r.Body = replayBody{
		Reader: io.MultiReader(bytes.NewReader(preview), orig),
		Closer: orig,
	}
	if err != nil {
		return nil, mediaType, false
	}
	if int64(len(preview)) > limit {
		preview = preview[:limit]
	}
	return preview, mediaType, true
}

func collectFormBodyValues(raw string) []string {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return genericBodyValues(raw)
	}

	out := make([]string, 0, len(values)*2)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		appendUnique(&out, key)
		if sensitiveBodyField(key) {
			continue
		}
		for _, value := range values[key] {
			appendAllUnique(&out, genericBodyValues(value)...)
		}
	}
	if len(out) == 0 {
		return genericBodyValues(raw)
	}
	return out
}

func collectJSONBodyValues(body []byte) []string {
	var payload any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return genericBodyValues(string(body))
	}

	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return genericBodyValues(string(body))
	}

	out := make([]string, 0, 8)
	collectJSONStrings(payload, "", &out)
	if len(out) == 0 {
		return genericBodyValues(string(body))
	}
	return out
}

func collectJSONStrings(value any, parentKey string, out *[]string) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			appendUnique(out, key)
			collectJSONStrings(v[key], key, out)
		}
	case []any:
		for _, item := range v {
			collectJSONStrings(item, parentKey, out)
		}
	case string:
		if sensitiveBodyField(parentKey) {
			return
		}
		appendAllUnique(out, genericBodyValues(v)...)
	case json.Number:
		if sensitiveBodyField(parentKey) {
			return
		}
		appendUnique(out, v.String())
	}
}

func genericBodyValues(raw string) []string {
	if raw == "" {
		return nil
	}

	out := []string{raw}

	decoded := raw
	if strings.ContainsAny(raw, "%+") {
		if v, err := url.QueryUnescape(raw); err == nil {
			decoded = v
			appendUnique(&out, decoded)
		}
	}

	if strings.Contains(raw, "+") {
		appendUnique(&out, strings.ReplaceAll(raw, "+", " "))
	}

	if strings.Contains(decoded, "%") {
		if v, err := url.QueryUnescape(decoded); err == nil {
			appendUnique(&out, v)
		}
	}

	return out
}

func sensitiveBodyField(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case name == "":
		return false
	case strings.Contains(name, "password"):
		return true
	case strings.Contains(name, "passwd"):
		return true
	case strings.Contains(name, "passphrase"):
		return true
	case strings.Contains(name, "passcode"):
		return true
	case name == "pin":
		return true
	case strings.HasSuffix(name, "_pin"):
		return true
	case strings.HasSuffix(name, "-pin"):
		return true
	default:
		return false
	}
}

func appendAllUnique(dst *[]string, values ...string) {
	for _, value := range values {
		appendUnique(dst, value)
	}
}

func appendUnique(dst *[]string, value string) {
	if value == "" {
		return
	}
	if slices.Contains(*dst, value) {
		return
	}
	*dst = append(*dst, value)
}

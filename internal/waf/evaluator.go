package waf

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/koltyakov/expose/internal/netutil"
)

// skipHeaderNames are headers excluded from WAF pattern matching because they
// are either safe, controlled by the browser, or cause false positives.
var skipHeaderNames = []string{
	"host",
	"accept",
	"accept-language",
	"accept-encoding",
	"connection",
	"content-length",
	"content-type",
	"if-modified-since",
	"if-none-match",
	"cache-control",
	"upgrade",
	"authorization",
	"sec-websocket-key",
	"sec-websocket-version",
	"sec-websocket-extensions",
	"sec-websocket-protocol",
	"sec-fetch-dest",
	"sec-fetch-mode",
	"sec-fetch-site",
	"sec-fetch-user",
	"sec-ch-ua",
	"sec-ch-ua-mobile",
	"sec-ch-ua-platform",
}

// skipHeaders is keyed by canonical MIME header form, matching the keys
// net/http puts in Request.Header. Looking up the canonical key directly
// avoids lowercasing every header name on every request.
var skipHeaders = func() map[string]struct{} {
	m := make(map[string]struct{}, len(skipHeaderNames))
	for _, name := range skipHeaderNames {
		m[textproto.CanonicalMIMEHeaderKey(name)] = struct{}{}
	}
	return m
}()

type requestView struct {
	requestURI    scanInput
	path          scanInput
	rawQuery      scanInput
	decodedQuery  scanInput
	plusDecoded   scanInput
	doubleDecoded scanInput
	userAgent     scanInput
	headerValues  []scanInput
	bodyValues    []scanInput
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

	// r.Header keys are already in canonical MIME form, so skipHeaders is
	// keyed the same way and needs no per-header lowercasing.
	headerValues := make([]scanInput, 0, len(r.Header))
	for name, values := range r.Header {
		if _, skip := skipHeaders[name]; skip {
			continue
		}
		for _, v := range values {
			headerValues = append(headerValues, newScanInput(v))
		}
	}

	return requestView{
		requestURI:    newScanInput(r.RequestURI),
		path:          newScanInput(r.URL.Path),
		rawQuery:      newScanInput(rawQuery),
		decodedQuery:  newScanInput(decodedQuery),
		plusDecoded:   newScanInput(plusDecoded),
		doubleDecoded: newScanInput(doubleDecoded),
		userAgent:     newScanInput(r.UserAgent()),
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

		if rl.targets&targetURI != 0 && rl.matches(view.requestURI) {
			return true, rl.name
		}
		if rl.targets&targetPath != 0 && matchPathRule(rl, view.path) {
			if fw.pathRuleGuard == nil || !fw.pathRuleGuard(r, rl.name) {
				return true, rl.name
			}
		}
		if rl.targets&targetQuery != 0 && view.rawQuery.raw != "" {
			if rl.matches(view.rawQuery) ||
				rl.matches(view.decodedQuery) ||
				rl.matches(view.plusDecoded) ||
				(view.doubleDecoded.raw != view.decodedQuery.raw && rl.matches(view.doubleDecoded)) {
				return true, rl.name
			}
		}
		if rl.targets&targetUA != 0 && rl.matches(view.userAgent) {
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

func matchPathRule(rl *rule, path scanInput) bool {
	if rl.name == "sensitive-file-probe" && isWellKnownPath(path.raw) {
		return false
	}
	return rl.matches(path)
}

func isWellKnownPath(path string) bool {
	return path == "/.well-known" || strings.HasPrefix(path, "/.well-known/")
}

// matchHeaderValues inspects all non-exempt header values for a rule match.
func (fw *firewall) matchHeaderValues(rl *rule, values []scanInput) bool {
	return slices.ContainsFunc(values, rl.matches)
}

// matchBodyValues inspects normalized body fragments for a rule match.
func (fw *firewall) matchBodyValues(rl *rule, values []scanInput) bool {
	return slices.ContainsFunc(values, rl.matches)
}

// matchUserAgent reports whether any User-Agent rule matches ua.
func (fw *firewall) matchUserAgent(ua string) bool {
	in := newScanInput(ua)
	for i := range fw.rules {
		rl := &fw.rules[i]
		if rl.targets&targetUA != 0 && rl.matches(in) {
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

type replayBody struct {
	io.Reader
	io.Closer
}

// bodyScanBudgetFactor bounds how many bytes of extracted body fragments the
// rule engine may scan, as a multiple of the inspected body size.
//
// Extraction is expansive: every fragment can yield URL-decoded, plus-decoded
// and double-decoded variants, so a body at the inspection limit could
// otherwise produce several times its own size in values, each scanned by
// every rule. The budget makes worst-case CPU per request a function of the
// configured inspection limit alone, regardless of body shape.
const bodyScanBudgetFactor = 2

// valueSetLinearDedupMax is the number of fragments below which dedup uses a
// linear scan. Most bodies stay well under it, and avoiding the map keeps the
// common case allocation-free.
const valueSetLinearDedupMax = 32

// valueSet accumulates distinct body fragments under a byte budget.
//
// Dedup switches from a linear scan to a map once the set grows: bodies with
// many distinct fragments made the previous slices.Contains approach
// quadratic, which let a single request burn milliseconds of CPU.
type valueSet struct {
	values  []scanInput
	seen    map[string]struct{} // built lazily past valueSetLinearDedupMax
	budget  int
	dropped bool
}

func newValueSet(budget int) *valueSet {
	return &valueSet{budget: budget}
}

func (s *valueSet) contains(value string) bool {
	if s.seen != nil {
		_, ok := s.seen[value]
		return ok
	}
	for i := range s.values {
		if s.values[i].raw == value {
			return true
		}
	}
	return false
}

func (s *valueSet) add(value string) {
	if value == "" {
		return
	}
	if s.budget <= 0 || len(value) > s.budget {
		s.dropped = true
		return
	}
	if s.contains(value) {
		return
	}

	s.budget -= len(value)
	s.values = append(s.values, newScanInput(value))

	if s.seen != nil {
		s.seen[value] = struct{}{}
		return
	}
	if len(s.values) > valueSetLinearDedupMax {
		s.seen = make(map[string]struct{}, len(s.values)*2)
		for i := range s.values {
			s.seen[s.values[i].raw] = struct{}{}
		}
	}
}

func (s *valueSet) addAll(values ...string) {
	for _, v := range values {
		s.add(v)
	}
}

func (s *valueSet) empty() bool { return len(s.values) == 0 }

func collectBodyValues(r *http.Request, limit int64, bodyGuard func(*http.Request) bool) []scanInput {
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

	set := newValueSet(len(body) * bodyScanBudgetFactor)
	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		return nil
	case mediaType == "application/x-www-form-urlencoded":
		collectFormBodyValues(set, string(body))
	case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"):
		collectJSONBodyValues(set, body)
	case mediaType == "application/octet-stream":
		return nil
	case utf8.Valid(body):
		collectGenericValues(set, string(body))
	default:
		return nil
	}
	return set.values
}

// collectJSONTokens extracts strings and numbers from a JSON document that may
// be incomplete, which is the normal case for a body truncated at the
// inspection limit.
//
// Without this, a truncated document fails to parse and falls back to scanning
// the whole raw blob, so bodies at or over the limit were both the most
// expensive to inspect and the least precisely inspected. Streaming tokens
// keeps extraction structured right up to the truncation point.
func collectJSONTokens(set *valueSet, body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	// Track object depth and key position so that values under a sensitive
	// key are skipped exactly as they are in the whole-document path.
	var (
		inObject  []bool
		expectKey bool
		lastKey   string
		found     bool
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			// io.EOF or a truncation error: keep whatever was extracted.
			return found
		}

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				inObject = append(inObject, true)
				expectKey = true
				lastKey = ""
			case '[':
				inObject = append(inObject, false)
				expectKey = false
			case '}', ']':
				if len(inObject) > 0 {
					inObject = inObject[:len(inObject)-1]
				}
				expectKey = len(inObject) > 0 && inObject[len(inObject)-1]
			}
		case string:
			if expectKey {
				lastKey = v
				set.add(v)
				found = true
				expectKey = false
				continue
			}
			if !sensitiveBodyField(lastKey) {
				collectGenericValues(set, v)
				found = true
			}
			if len(inObject) > 0 && inObject[len(inObject)-1] {
				expectKey = true
			}
		case json.Number:
			if !sensitiveBodyField(lastKey) {
				set.add(v.String())
				found = true
			}
			if len(inObject) > 0 && inObject[len(inObject)-1] {
				expectKey = true
			}
		default:
			// bool or nil: nothing to inspect, but object keys still alternate.
			if len(inObject) > 0 && inObject[len(inObject)-1] {
				expectKey = true
			}
		}
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

func collectFormBodyValues(set *valueSet, raw string) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		collectGenericValues(set, raw)
		return
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		set.add(key)
		if sensitiveBodyField(key) {
			continue
		}
		for _, value := range values[key] {
			collectGenericValues(set, value)
		}
	}
	if set.empty() {
		collectGenericValues(set, raw)
	}
}

func collectJSONBodyValues(set *valueSet, body []byte) {
	var payload any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err == nil {
		var extra any
		if err := dec.Decode(&extra); err == io.EOF {
			collectJSONStrings(payload, "", set)
			if !set.empty() {
				return
			}
		}
	}

	// Not a single well-formed document: most often a body truncated at the
	// inspection limit. Recover what structure we can before falling back to
	// scanning the raw bytes.
	if collectJSONTokens(set, body) {
		return
	}
	collectGenericValues(set, string(body))
}

func collectJSONStrings(value any, parentKey string, set *valueSet) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			set.add(key)
			collectJSONStrings(v[key], key, set)
		}
	case []any:
		for _, item := range v {
			collectJSONStrings(item, parentKey, set)
		}
	case string:
		if sensitiveBodyField(parentKey) {
			return
		}
		collectGenericValues(set, v)
	case json.Number:
		if sensitiveBodyField(parentKey) {
			return
		}
		set.add(v.String())
	}
}

// collectGenericValues adds raw plus any decoded variants that differ from it,
// so that encoded attack payloads are inspected in decoded form too.
func collectGenericValues(set *valueSet, raw string) {
	if raw == "" {
		return
	}
	set.add(raw)

	decoded := raw
	if strings.ContainsAny(raw, "%+") {
		if v, err := url.QueryUnescape(raw); err == nil {
			decoded = v
			set.add(decoded)
		}
	}

	if strings.Contains(raw, "+") {
		set.add(strings.ReplaceAll(raw, "+", " "))
	}

	if strings.Contains(decoded, "%") {
		if v, err := url.QueryUnescape(decoded); err == nil {
			set.add(v)
		}
	}
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

package waf

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
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
	requestURI       scanInput
	decodedURI       scanInput
	doubleDecodedURI scanInput
	path             scanInput
	rawQuery         scanInput
	decodedQuery     scanInput
	plusDecoded      scanInput
	doubleDecoded    scanInput
	userAgent        scanInput
	headerValues     []scanInput
	bodyValues       []scanInput
	uriTooLong       bool // URI exceeds safety limit
	tooManyHdrs      bool // excessive header count
}

// maxURILength is the maximum URI length before the WAF considers a request
// suspicious. Very long URIs are commonly used in buffer-overflow and
// smuggling attacks. 8 KiB is the de-facto limit of most HTTP servers.
const maxURILength = 8192

// maxHeaderCount is the maximum number of non-exempt headers before the WAF
// considers a request suspicious.
const maxHeaderCount = 64

func newRequestView(r *http.Request, maxURI, maxHeaders int) requestView {
	// Preserve structural-rule precedence without decoding/folding inputs that
	// will be rejected. Header limits count values, not distinct header names.
	if len(r.RequestURI) > maxURI {
		return requestView{uriTooLong: true}
	}
	headerCount := 0
	for name, values := range r.Header {
		if _, skip := skipHeaders[name]; skip {
			continue
		}
		if len(values) > maxHeaders-headerCount {
			return requestView{tooManyHdrs: true}
		}
		headerCount += len(values)
	}
	if headerCount > maxHeaders {
		return requestView{tooManyHdrs: true}
	}

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

	// Decoded URI variants catch encoding-obfuscated attacks against
	// URI-targeted rules, e.g. %2e%2e%2f traversal sequences that contain
	// no literal ".." in the raw request line.
	decodedURI := r.RequestURI
	if strings.Contains(decodedURI, "%") {
		if d, err := url.QueryUnescape(decodedURI); err == nil {
			decodedURI = d
		}
	}

	doubleDecodedURI := decodedURI
	if strings.Contains(decodedURI, "%") {
		if dd, err := url.QueryUnescape(decodedURI); err == nil && dd != decodedURI {
			doubleDecodedURI = dd
		}
	}

	// r.Header keys are already in canonical MIME form, so skipHeaders is
	// keyed the same way and needs no per-header lowercasing.
	userAgent := newScanInput(r.UserAgent())
	headerValues := make([]scanInput, 0, headerCount)
	for name, values := range r.Header {
		if _, skip := skipHeaders[name]; skip {
			continue
		}
		for _, v := range values {
			headerValues = append(headerValues, reuseScanInput(v, userAgent))
		}
	}

	view := requestView{userAgent: userAgent, headerValues: headerValues}
	view.requestURI = newScanInput(r.RequestURI)
	view.decodedURI = reuseScanInput(decodedURI, view.requestURI)
	view.doubleDecodedURI = reuseScanInput(doubleDecodedURI, view.requestURI, view.decodedURI)
	view.path = reuseScanInput(r.URL.Path, view.requestURI, view.decodedURI, view.doubleDecodedURI)
	view.rawQuery = newScanInput(rawQuery)
	view.decodedQuery = reuseScanInput(decodedQuery, view.rawQuery)
	view.plusDecoded = reuseScanInput(plusDecoded, view.rawQuery, view.decodedQuery)
	view.doubleDecoded = reuseScanInput(doubleDecoded, view.rawQuery, view.decodedQuery, view.plusDecoded)
	return view
}

// reuseScanInput avoids folding identical variants more than once. Inputs are
// immutable, and non-ASCII variants retain the same regex fallback behavior.
func reuseScanInput(raw string, previous ...scanInput) scanInput {
	for _, in := range previous {
		if raw == in.raw {
			return in
		}
	}
	return newScanInput(raw)
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

	var bodyOverflow bool
	view.bodyValues, bodyOverflow = collectBodyValues(r, fw.bodyLimit, fw.bodyGuard)
	if bodyOverflow {
		return true, "body-scan-budget-exceeded"
	}

	for i := range fw.rules {
		rl := &fw.rules[i]

		if rl.targets&targetURI != 0 && matchURIRule(rl, view) {
			return true, rl.name
		}
		if rl.targets&targetPath != 0 && matchPathRule(rl, view.path) {
			if fw.pathRuleGuard == nil || !fw.pathRuleGuard(r, rl.name) {
				return true, rl.name
			}
		}
		if rl.targets&targetQuery != 0 && view.rawQuery.raw != "" {
			if rl.matches(view.rawQuery) ||
				(view.decodedQuery.raw != view.rawQuery.raw && rl.matches(view.decodedQuery)) ||
				(view.plusDecoded.raw != view.rawQuery.raw && view.plusDecoded.raw != view.decodedQuery.raw && rl.matches(view.plusDecoded)) ||
				(view.doubleDecoded.raw != view.rawQuery.raw && view.doubleDecoded.raw != view.decodedQuery.raw &&
					view.doubleDecoded.raw != view.plusDecoded.raw && rl.matches(view.doubleDecoded)) {
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

// matchURIRule matches a rule against the raw RequestURI and its decoded
// variants, mirroring the query handling, so that encoded payloads (fully
// or double-encoded) cannot evade URI-targeted rules.
func matchURIRule(rl *rule, view requestView) bool {
	if rl.matches(view.requestURI) {
		return true
	}
	if view.decodedURI.raw != view.requestURI.raw && rl.matches(view.decodedURI) {
		return true
	}
	return view.doubleDecodedURI.raw != view.decodedURI.raw && rl.matches(view.doubleDecodedURI)
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
// Requests exceeding the budget are rejected rather than partially inspected:
// early decoded variants must not hide later raw or encoded attacks.
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
	// A duplicate needs no additional scanning, even when the budget is full.
	if s.contains(value) {
		return
	}
	if s.budget <= 0 || len(value) > s.budget {
		s.dropped = true
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

// collectBodyValues reports overflow whenever a distinct fragment could not be
// retained. Callers must reject that request instead of trusting a partial scan.
func collectBodyValues(r *http.Request, limit int64, bodyGuard func(*http.Request) bool) ([]scanInput, bool) {
	if r == nil || r.Body == nil || r.Body == http.NoBody || limit <= 0 {
		return nil, false
	}
	if bodyGuard != nil && !bodyGuard(r) {
		return nil, false
	}

	body, mediaType, ok := previewRequestBody(r, limit)
	if !ok || len(body) == 0 {
		return nil, false
	}

	set := newValueSet(len(body) * bodyScanBudgetFactor)
	switch {
	case strings.HasPrefix(mediaType, "multipart/"):
		collectMultipartBodyValues(set, body, r.Header.Get("Content-Type"))
	case mediaType == "application/x-www-form-urlencoded":
		collectFormBodyValues(set, string(body))
	case mediaType == "application/json", strings.HasSuffix(mediaType, "+json"):
		collectJSONBodyValues(set, body)
	case utf8.Valid(body):
		collectGenericValues(set, string(body))
	default:
		return nil, false
	}
	return set.values, set.dropped
}

// collectJSONTokens extracts strings and numbers from a JSON document that may
// be incomplete, which is the normal case for a body truncated at the
// inspection limit.
//
// Without this, a truncated document fails to parse and falls back to scanning
// the whole raw blob, so bodies at or over the limit were both the most
// expensive to inspect and the least precisely inspected. Streaming tokens
// keeps extraction structured right up to the truncation point.
func collectJSONTokens(set *valueSet, body []byte) (bool, int) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()

	// Track container nesting so object keys are told apart from values:
	// keys are added verbatim, values get full decoding treatment.
	var (
		inObject  []bool
		expectKey bool
		found     bool
		offset    int
	)

	for {
		tok, err := dec.Token()
		if err != nil {
			// The decoder may consume a separator before a failed token, or
			// read ahead into its buffer. Keep the last successful token's
			// end, not the reader position or InputOffset after the error.
			return found, offset
		}
		offset = int(dec.InputOffset())

		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				inObject = append(inObject, true)
				expectKey = true
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
				set.add(v)
				found = true
				expectKey = false
				continue
			}
			collectGenericValues(set, v)
			found = true
			if len(inObject) > 0 && inObject[len(inObject)-1] {
				expectKey = true
			}
		case json.Number:
			set.add(v.String())
			found = true
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
		for _, value := range values[key] {
			collectGenericValues(set, value)
		}
	}
	if set.empty() {
		collectGenericValues(set, raw)
	}
}

// collectMultipartBodyValues parses a multipart body and scans each part's
// field name, filename, and text content against the body rules. Binary
// part content is skipped via the UTF-8 check. If the body cannot be parsed
// as multipart at all (missing or malformed boundary), the raw preview is
// scanned as generic text so boundary tricks cannot bypass inspection.
func collectMultipartBodyValues(set *valueSet, body []byte, contentType string) {
	boundary := ""
	if _, params, err := mime.ParseMediaType(contentType); err == nil {
		boundary = params["boundary"]
	}
	if boundary == "" {
		if utf8.Valid(body) {
			collectGenericValues(set, string(body))
		}
		return
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	parts := 0
	for {
		part, err := reader.NextPart()
		if err != nil {
			// io.EOF, truncation at the inspection limit, or malformed
			// content: keep whatever was extracted so far.
			break
		}
		parts++
		if name := part.FormName(); name != "" {
			set.add(name)
		}
		if filename := rawPartFilename(part); filename != "" {
			collectGenericValues(set, filename)
		}
		data, readErr := io.ReadAll(part)
		// Form fields are textual even when a client includes malformed UTF-8;
		// scan their byte string so one invalid byte cannot hide an otherwise
		// ASCII attack payload. Binary file parts remain exempt.
		if part.FileName() == "" || utf8.Valid(data) {
			collectGenericValues(set, string(data))
		}
		if readErr != nil {
			break
		}
	}
	if parts == 0 && utf8.Valid(body) {
		collectGenericValues(set, string(body))
	}
}

// rawPartFilename returns the filename parameter of a part's
// Content-Disposition header exactly as sent. Part.FileName applies
// filepath.Base, which would strip payload prefixes containing "/".
func rawPartFilename(part *multipart.Part) string {
	disp := part.Header.Get("Content-Disposition")
	if disp == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disp)
	if err != nil {
		return ""
	}
	return params["filename"]
}

func collectJSONBodyValues(set *valueSet, body []byte) {
	// Stream tokens directly instead of decoding into an any tree first.
	// The tree decode allocated a map, slice, and boxed value per node and
	// then walked (and key-sorted) the whole structure; the token stream
	// extracts the same keys, strings, and numbers in one pass. It also
	// keeps values under duplicate keys, which a map decode would collapse.
	// Incomplete documents retain their complete tokens. Wire order is safe
	// because the firewall rejects extraction budget overflow.
	found, offset := collectJSONTokens(set, body)
	if !found {
		collectJSONTailValues(set, string(body))
		collectJSONStringPrefix(set, body[offset:])
		return
	}
	// A successful key or value must not hide a malformed/truncated suffix.
	// Scanning only that suffix avoids charging complete tokens a second time
	// and keeps ordinary large documents within the existing byte budget.
	if tail := bytes.TrimSpace(body[offset:]); len(tail) > 0 {
		collectJSONTailValues(set, string(tail))
		collectJSONStringPrefix(set, tail)
	}
}

// collectJSONTailValues also recovers URL escapes before a failed escape. A
// preview can cut the final %xx sequence while an earlier encoded attack is
// wholly inside the inspection prefix. QueryUnescape of the whole suffix would
// otherwise fail and silently omit that decoded attack. Recovery stops at the
// first invalid escape and keeps the usual maximum of two decoding layers.
func collectJSONTailValues(set *valueSet, raw string) {
	collectGenericValues(set, raw)
	for range 2 {
		if !strings.Contains(raw, "%") {
			return
		}
		prefix := raw
		for i := 0; i < len(raw); i++ {
			if raw[i] != '%' {
				continue
			}
			if i+2 >= len(raw) || !isHexByte(raw[i+1]) || !isHexByte(raw[i+2]) {
				prefix = raw[:i]
				break
			}
			i += 2
		}
		// Plus-only normalization already exists for the whole raw suffix.
		// Do not charge a redundant prefix when no percent escape was decoded.
		if !strings.Contains(prefix, "%") {
			return
		}
		decoded, err := url.QueryUnescape(prefix)
		if err != nil || decoded == prefix {
			return
		}
		set.add(decoded)
		raw = decoded
	}
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// collectJSONStringPrefix decodes the valid prefix of a failed string token. It
// recovers JSON escapes before a missing quote, incomplete escape or malformed
// character without claiming that the whole remainder is valid JSON.
func collectJSONStringPrefix(set *valueSet, tail []byte) {
	// Separators can follow the last completed key/value/container token.
	value := bytes.TrimLeft(tail, ",: \t\r\n")
	if len(value) == 0 || value[0] != '"' || bytes.IndexByte(value, '\\') < 0 {
		return
	}
	end, escaped := 1, false
scan:
	for end < len(value) {
		c := value[end]
		if c == '"' || c < 0x20 {
			break
		}
		if c != '\\' {
			end++
			continue
		}
		if end+1 >= len(value) {
			break
		}
		switch value[end+1] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			end += 2
		case 'u':
			if end+6 > len(value) {
				break scan
			}
			for _, hex := range value[end+2 : end+6] {
				if !isHexByte(hex) {
					break scan
				}
			}
			end += 6
		default:
			break scan
		}
		escaped = true
	}
	if !escaped {
		return
	}
	fragment := make([]byte, end+1)
	copy(fragment, value[:end])
	fragment[end] = '"'
	var decoded string
	if json.Unmarshal(fragment, &decoded) == nil {
		collectJSONTailValues(set, decoded)
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

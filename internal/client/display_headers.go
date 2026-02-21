package client

import (
	"net/textproto"
	"strings"
)

// visitorFingerprint returns a string that identifies a unique visitor
// using the combination of client IP (X-Forwarded-For / X-Real-Ip) and
// User-Agent. Returns empty string when no identifying info is available.
func visitorFingerprint(headers map[string][]string) string {
	if headers == nil {
		return ""
	}

	xff := firstHeaderValueCI(headers, "X-Forwarded-For")
	xri := firstHeaderValueCI(headers, "X-Real-Ip")
	ua := firstHeaderValueCI(headers, "User-Agent")

	var ip string
	if xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		ip = strings.TrimSpace(first)
	}
	if ip == "" {
		ip = strings.TrimSpace(xri)
	}
	if ip == "" {
		return ""
	}

	return ip + "|" + ua
}

// firstHeaderValueCI returns the first value for key from headers.
// It prefers exact/canonical map lookups, and falls back to case-insensitive
// matching for non-canonical maps.
func firstHeaderValueCI(headers map[string][]string, key string) string {
	if headers == nil || key == "" {
		return ""
	}
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	canonical := textproto.CanonicalMIMEHeaderKey(key)
	if canonical != key {
		if vals, ok := headers[canonical]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	for k, vals := range headers {
		if len(vals) == 0 {
			continue
		}
		if strings.EqualFold(k, key) {
			return vals[0]
		}
	}
	return ""
}

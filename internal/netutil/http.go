// Package netutil provides shared HTTP/network normalization helpers.
package netutil

import (
	"net"
	"net/http"
	"net/textproto"
	"strings"
)

var hopByHopHeaderNames = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// NormalizeHost lower-cases and strips ports/trailing dots from host values.
func NormalizeHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return ""
	}

	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		host = h
	} else if strings.Count(host, ":") == 1 {
		left, right, ok := strings.Cut(host, ":")
		if ok && isDigits(right) {
			host = left
		}
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return strings.TrimSuffix(host, ".")
}

// RemoveHopByHopHeaders strips hop-by-hop headers that must not be proxied.
func RemoveHopByHopHeaders(h http.Header) {
	if len(h) == 0 {
		return
	}

	for _, connectionValue := range h.Values("Connection") {
		for _, token := range strings.Split(connectionValue, ",") {
			key := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(token))
			if key != "" {
				h.Del(key)
			}
		}
	}

	for _, key := range hopByHopHeaderNames {
		h.Del(key)
	}
}

func isDigits(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

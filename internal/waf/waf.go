// Package waf implements a lightweight Web Application Firewall middleware
// that blocks common attack patterns (SQL injection, XSS, path traversal,
// shell injection, scanner bots, etc.) before they reach the application.
package waf

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// BlockEvent carries context about a single WAF-blocked request so that
// callers can produce meaningful audit log entries.
type BlockEvent struct {
	Host       string // normalised hostname (port stripped, lowercased)
	Rule       string // name of the WAF rule that matched
	Method     string // HTTP method (GET, POST, …)
	RequestURI string // full request URI including query string
	RemoteAddr string // client IP (from X-Forwarded-For or RemoteAddr)
	UserAgent  string // User-Agent header value
}

// Config controls WAF behaviour.
type Config struct {
	Enabled bool
	// OnBlock is called (if non-nil) every time the WAF blocks a request.
	OnBlock func(BlockEvent)
}

// firewall holds pre-compiled rules and the logger.
type firewall struct {
	rules   []rule
	log     *slog.Logger
	onBlock func(BlockEvent)
}

// NewMiddleware returns an http.Handler middleware that inspects every
// incoming request against the built-in WAF ruleset. Requests that match
// a rule are rejected with 403 Forbidden. The /healthz endpoint is
// always exempt.
//
// If cfg.Enabled is false the returned middleware is a no-op passthrough.
func NewMiddleware(cfg Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !cfg.Enabled {
			return next // WAF disabled — no overhead
		}

		fw := &firewall{
			rules:   defaultRules(),
			log:     logger,
			onBlock: cfg.OnBlock,
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}
			if matched, ruleName := fw.check(r); matched {
				clientIP := clientAddr(r)
				host := normalizeHost(r.Host)
				fw.log.Warn("waf blocked request",
					"rule", ruleName,
					"method", r.Method,
					"uri", r.RequestURI,
					"remote", clientIP,
					"ua", r.UserAgent(),
				)
				if fw.onBlock != nil {
					fw.onBlock(BlockEvent{
						Host:       host,
						Rule:       ruleName,
						Method:     r.Method,
						RequestURI: r.RequestURI,
						RemoteAddr: clientIP,
						UserAgent:  r.UserAgent(),
					})
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// check tests the request against every rule and returns on the first match.
func (fw *firewall) check(r *http.Request) (matched bool, ruleName string) {
	// Pre-decode query string once for all rules. Attackers use URL encoding
	// (+ and %XX) to evade pattern matching, so we test both raw and decoded.
	rawQuery := r.URL.RawQuery
	decodedQuery, _ := url.QueryUnescape(rawQuery)
	// Also replace + with space for form-encoded queries
	plusDecoded := strings.ReplaceAll(rawQuery, "+", " ")

	for i := range fw.rules {
		rl := &fw.rules[i]

		if rl.targets&targetURI != 0 {
			if rl.pattern.MatchString(r.RequestURI) {
				return true, rl.name
			}
		}
		if rl.targets&targetPath != 0 {
			if rl.pattern.MatchString(r.URL.Path) {
				return true, rl.name
			}
		}
		if rl.targets&targetQuery != 0 && rawQuery != "" {
			if rl.pattern.MatchString(rawQuery) ||
				rl.pattern.MatchString(decodedQuery) ||
				rl.pattern.MatchString(plusDecoded) {
				return true, rl.name
			}
		}
		if rl.targets&targetUA != 0 {
			if ua := r.UserAgent(); ua != "" {
				if rl.pattern.MatchString(ua) {
					return true, rl.name
				}
			}
		}
		if rl.targets&targetHeaders != 0 {
			if fw.matchHeaders(rl, r) {
				return true, rl.name
			}
		}
	}
	return false, ""
}

// skipHeaders are headers excluded from WAF pattern matching because they
// are either safe, controlled by the browser, or cause false positives.
var skipHeaders = map[string]struct{}{
	"Host":                     {},
	"Accept":                   {},
	"Accept-Language":          {},
	"Accept-Encoding":          {},
	"Connection":               {},
	"Content-Length":           {},
	"Content-Type":             {},
	"If-Modified-Since":        {},
	"If-None-Match":            {},
	"Cache-Control":            {},
	"Upgrade":                  {},
	"Authorization":            {},
	"Sec-Websocket-Key":        {},
	"Sec-Websocket-Version":    {},
	"Sec-Websocket-Extensions": {},
	"Sec-Websocket-Protocol":   {},
	"Sec-Fetch-Dest":           {},
	"Sec-Fetch-Mode":           {},
	"Sec-Fetch-Site":           {},
	"Sec-Fetch-User":           {},
	"Sec-Ch-Ua":                {},
	"Sec-Ch-Ua-Mobile":         {},
	"Sec-Ch-Ua-Platform":       {},
}

// matchHeaders inspects all header values (excluding safe/structural headers)
// for a rule match.
func (fw *firewall) matchHeaders(rl *rule, r *http.Request) bool {
	for name, values := range r.Header {
		if _, skip := skipHeaders[name]; skip {
			continue
		}
		// Also skip headers whose canonical form differs from the map key
		// (e.g. lowercase variants) — use case-insensitive fallback.
		if _, skip := skipHeaders[strings.ToLower(name)]; skip {
			continue
		}
		for _, v := range values {
			if rl.pattern.MatchString(v) {
				return true
			}
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

// normalizeHost strips the port from a host:port string and lowercases
// the result so that block counters are keyed consistently.
func normalizeHost(host string) string {
	if i := strings.LastIndex(host, ":"); i != -1 {
		h := host[:i]
		if len(h) > 0 {
			return strings.ToLower(h)
		}
	}
	return strings.ToLower(host)
}

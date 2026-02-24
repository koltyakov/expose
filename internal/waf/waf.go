// Package waf implements a lightweight Web Application Firewall middleware
// that blocks common attack patterns (SQL injection, XSS, path traversal,
// shell injection, scanner bots, etc.) before they reach the application.
package waf

import (
	"log/slog"
	"net/http"
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
	// AuditOnly logs matched rules without blocking the request (dry-run mode).
	AuditOnly bool
	// OnBlock is called (if non-nil) every time the WAF blocks (or would
	// block, in audit mode) a request.
	OnBlock func(BlockEvent)
}

// firewall holds pre-compiled rules and the logger.
type firewall struct {
	rules     []rule
	log       *slog.Logger
	auditOnly bool
	onBlock   func(BlockEvent)
}

var forbiddenJSONBody = []byte(`{"error":"Forbidden"}` + "\n")

// NewMiddleware returns an http.Handler middleware that inspects every
// incoming request against the built-in WAF ruleset. Requests that match
// a rule are rejected with 403 Forbidden. The /healthz endpoint is
// always exempt.
//
// If cfg.Enabled is false the returned middleware is a no-op passthrough.
func NewMiddleware(cfg Config, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !cfg.Enabled {
			return next // WAF disabled - no overhead
		}

		fw := &firewall{
			rules:     defaultRules(),
			log:       logger,
			auditOnly: cfg.AuditOnly,
			onBlock:   cfg.OnBlock,
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			if matched, ruleName := fw.check(r); matched {
				clientIP := clientAddr(r)
				host := normalizeHost(r.Host)
				userAgent := r.UserAgent()

				logLevel := slog.LevelWarn
				logMsg := "waf blocked request"
				if fw.auditOnly {
					logMsg = "waf matched request (audit)"
				}

				fw.log.Log(r.Context(), logLevel, logMsg,
					"rule", ruleName,
					"method", r.Method,
					"uri", r.RequestURI,
					"remote", clientIP,
					"ua", userAgent,
				)

				if fw.onBlock != nil {
					fw.onBlock(BlockEvent{
						Host:       host,
						Rule:       ruleName,
						Method:     r.Method,
						RequestURI: r.RequestURI,
						RemoteAddr: clientIP,
						UserAgent:  userAgent,
					})
				}

				if fw.auditOnly {
					next.ServeHTTP(w, r) // let the request through
					return
				}

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("X-Frame-Options", "DENY")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write(forbiddenJSONBody)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

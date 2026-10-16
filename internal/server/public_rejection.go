package server

import (
	"net/http"

	"github.com/koltyakov/expose/internal/serviceapi"
)

const (
	rejectionRateLimit       = "rate-limit"
	rejectionLookupRateLimit = "route-lookup-rate-limit"
	rejectionConcurrency     = "concurrency-limit"
	rejectionBackpressure    = "backpressure"
)

// writePublicRejection distinguishes local admission failures from application
// errors without exposing request credentials or looking up a route in storage.
func (s *Server) writePublicRejection(w http.ResponseWriter, r *http.Request, status int, message, reason string) {
	w.Header().Set(serviceapi.ErrorHeader, reason)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	if recorder, ok := w.(*siteStatsWriter); ok {
		recorder.rejectionReason = reason
	}
	// Keys are fixed reasons, never attacker-controlled hosts or IPs. Bound log
	// volume during overload without suppressing response or history diagnostics.
	if s.log != nil && s.rejectionLogLimiter.allow(reason) {
		s.log.WarnContext(r.Context(), "public request rejected",
			"reason", reason, "status", status,
			"domain", boundedStatsText(normalizeHost(r.Host), 253),
			"method", boundedStatsText(r.Method, 32),
			"path", boundedStatsText(r.URL.EscapedPath(), 2048),
			"remote", s.clientIP(r),
		)
	}
	http.Error(w, message, status)
}

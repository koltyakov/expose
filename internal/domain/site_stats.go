package domain

import "time"

// PublishedSiteStats is an owner-only snapshot of in-memory hosting statistics.
type PublishedSiteStats struct {
	Site           PublishedSite          `json:"site"`
	Since          time.Time              `json:"since"`
	CapturedAt     time.Time              `json:"captured_at"`
	ServerVersion  string                 `json:"server_version"`
	WAFEnabled     bool                   `json:"waf_enabled"`
	WAFAuditOnly   bool                   `json:"waf_audit_only"`
	HTTPRequests   int64                  `json:"http_requests"`
	ResponseBytes  int64                  `json:"response_bytes"`
	Visitors       int                    `json:"visitors"`
	ActiveVisitors int                    `json:"active_visitors"`
	VisitorsCapped bool                   `json:"visitors_capped"`
	WAFBlocked     int64                  `json:"waf_blocked"`
	WAFAudited     int64                  `json:"waf_audited"`
	LatencyP50MS   float64                `json:"latency_p50_ms"`
	LatencyP95MS   float64                `json:"latency_p95_ms"`
	Requests       []PublishedSiteRequest `json:"requests"`
}

type PublishedSiteRequest struct {
	Time          time.Time `json:"time"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Status        int       `json:"status"`
	DurationMS    float64   `json:"duration_ms"`
	ResponseBytes int64     `json:"response_bytes"`
	WAFRule       string    `json:"waf_rule,omitempty"`
	AuditOnly     bool      `json:"audit_only,omitempty"`
}

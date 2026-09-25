package server

import (
	"crypto/sha256"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/waf"
)

const siteRecentRequests = 20
const siteLatencySamples = 1024
const siteVisitorLimit = 10000

type siteStats struct {
	mu             sync.Mutex
	since          time.Time
	httpRequests   int64
	responseBytes  int64
	blocked        int64
	audited        int64
	visitors       map[[32]byte]time.Time
	visitorsCapped bool
	requests       []domain.PublishedSiteRequest
	latencies      [siteLatencySamples]float64
	latencyCount   int
	latencyNext    int
}

func (s *Server) statsForSite(id string) *siteStats {
	if value, ok := s.siteStats.Load(id); ok {
		return value.(*siteStats)
	}
	value, _ := s.siteStats.LoadOrStore(id, &siteStats{since: time.Now().UTC(), visitors: make(map[[32]byte]time.Time)})
	return value.(*siteStats)
}

func (stats *siteStats) record(entry domain.PublishedSiteRequest, ip, userAgent string) {
	// Do not retain query values, headers, addresses, or raw user agents.
	entry.Path, _, _ = strings.Cut(entry.Path, "?")
	entry.Path = boundedStatsText(entry.Path, 2048)
	entry.Method = boundedStatsText(entry.Method, 32)
	entry.WAFRule = boundedStatsText(entry.WAFRule, 128)
	fingerprint := sha256.Sum256([]byte(ip + "\x00" + userAgent))
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if entry.WAFRule != "" {
		if entry.AuditOnly {
			stats.audited++
		} else {
			stats.blocked++
		}
	} else {
		stats.httpRequests++
		stats.responseBytes += entry.ResponseBytes
		stats.latencies[stats.latencyNext] = entry.DurationMS
		stats.latencyNext = (stats.latencyNext + 1) % siteLatencySamples
		if stats.latencyCount < siteLatencySamples {
			stats.latencyCount++
		}
	}
	if _, found := stats.visitors[fingerprint]; found || len(stats.visitors) < siteVisitorLimit {
		stats.visitors[fingerprint] = entry.Time
	} else {
		stats.visitorsCapped = true
	}
	if len(stats.requests) == siteRecentRequests {
		copy(stats.requests, stats.requests[1:])
		stats.requests[len(stats.requests)-1] = entry
	} else {
		stats.requests = append(stats.requests, entry)
	}
}

func boundedStatsText(value string, max int) string {
	if len(value) > max {
		value = value[:max]
	}
	return config.SanitizeTerminalString(value)
}

func (stats *siteStats) snapshot(now time.Time) domain.PublishedSiteStats {
	stats.mu.Lock()
	result := domain.PublishedSiteStats{
		Since: stats.since, CapturedAt: now, HTTPRequests: stats.httpRequests,
		ResponseBytes: stats.responseBytes, Visitors: len(stats.visitors), VisitorsCapped: stats.visitorsCapped,
		WAFBlocked: stats.blocked, WAFAudited: stats.audited,
		Requests: append([]domain.PublishedSiteRequest{}, stats.requests...),
	}
	for _, seen := range stats.visitors {
		if now.Sub(seen) < time.Minute {
			result.ActiveVisitors++
		}
	}
	latencies := append([]float64(nil), stats.latencies[:stats.latencyCount]...)
	stats.mu.Unlock()
	slices.Sort(latencies)
	if len(latencies) > 0 {
		result.LatencyP50MS = latencies[(len(latencies)*50+99)/100-1]
		result.LatencyP95MS = latencies[(len(latencies)*95+99)/100-1]
	}
	return result
}

func (s *Server) writeSiteStats(w http.ResponseWriter, r *http.Request, site domain.PublishedSite) {
	now := time.Now().UTC()
	if site.ExpiresAt != nil && !now.Before(*site.ExpiresAt) {
		http.NotFound(w, r)
		return
	}
	stats := s.statsForSite(site.ID).snapshot(now)
	stats.Site, stats.ServerVersion = site, s.version
	stats.WAFEnabled, stats.WAFAuditOnly = s.cfg.WAFEnabled, s.cfg.WAFAuditOnly
	writeJSON(w, http.StatusOK, stats)
}

// WAF callbacks happen before the public handler. Use the live site index so
// blocked probes never trigger an additional database lookup.
func (s *Server) recordSiteWAF(event waf.BlockEvent) {
	s.sitesMu.RLock()
	defer s.sitesMu.RUnlock()
	value, ok := s.siteHosts.Load(normalizeHost(event.Host))
	if !ok {
		return
	}
	site, ok := value.(domain.PublishedSite)
	now := time.Now().UTC()
	if !ok || (site.ExpiresAt != nil && !now.Before(*site.ExpiresAt)) {
		return
	}
	status := http.StatusForbidden
	if s.cfg.WAFAuditOnly {
		status = 0
	}
	s.statsForSite(site.ID).record(domain.PublishedSiteRequest{
		Time: now, Method: event.Method, Path: event.RequestURI, Status: status,
		WAFRule: event.Rule, AuditOnly: s.cfg.WAFAuditOnly,
	}, event.RemoteAddr, event.UserAgent)
}

type siteStatsWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *siteStatsWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *siteStatsWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	if status >= 200 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *siteStatsWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/waf"
)

const siteRecentRequests = 20
const siteLatencySamples = 1024
const siteVisitorLimit = 10000

type siteVisitorStore interface {
	ListPublishedSiteVisitors(context.Context, string) ([][32]byte, error)
	RecordPublishedSiteVisitor(context.Context, string, [32]byte, int) error
}

type siteStats struct {
	mu             sync.Mutex
	since          time.Time
	httpRequests   int64
	responseBytes  int64
	blocked        int64
	audited        int64
	visitors       map[[32]byte]time.Time
	visitorsCapped bool
	visitorsLoaded bool
	persistVisitor func([32]byte)
	requests       []domain.PublishedSiteRequest
	latencies      [siteLatencySamples]float64
	latencyCount   int
	latencyNext    int
	filesStorageID string
	fileCount      int
	fileBytes      int64
	presence       map[*websocket.Conn][32]byte
}

func (s *Server) statsForSite(id string) *siteStats {
	value, ok := s.siteStats.Load(id)
	if !ok {
		value, _ = s.siteStats.LoadOrStore(id, &siteStats{since: time.Now().UTC(), visitors: make(map[[32]byte]time.Time)})
	}
	stats := value.(*siteStats)
	if st, ok := s.store.(siteVisitorStore); ok {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		if !stats.visitorsLoaded {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			visitors, err := st.ListPublishedSiteVisitors(ctx, id)
			if err != nil {
				if s.log != nil {
					s.log.Error("load published site visitors", "site", id, "err", err)
				}
			} else {
				for _, fingerprint := range visitors {
					if _, exists := stats.visitors[fingerprint]; !exists {
						stats.visitors[fingerprint] = time.Time{}
					}
				}
				stats.visitorsLoaded = true
				stats.visitorsCapped = len(stats.visitors) >= siteVisitorLimit
			}
			stats.persistVisitor = func(fingerprint [32]byte) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := st.RecordPublishedSiteVisitor(ctx, id, fingerprint, siteVisitorLimit); err != nil && s.log != nil {
					s.log.Error("record published site visitor", "site", id, "err", err)
				}
			}
		}
	}
	return stats
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
	stats.touchVisitorLocked(fingerprint, entry.Time)
	if len(stats.requests) == siteRecentRequests {
		copy(stats.requests, stats.requests[1:])
		stats.requests[len(stats.requests)-1] = entry
	} else {
		stats.requests = append(stats.requests, entry)
	}
}

func (stats *siteStats) touchVisitorLocked(fingerprint [32]byte, now time.Time) {
	if _, found := stats.visitors[fingerprint]; found || len(stats.visitors) < siteVisitorLimit {
		if !found && stats.persistVisitor != nil {
			stats.persistVisitor(fingerprint)
		}
		stats.visitors[fingerprint] = now
	} else {
		stats.visitorsCapped = true
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
	count, size, err := s.publishedFileTotals(site)
	if err != nil {
		s.siteError(w, err)
		return
	}
	stats := s.statsForSite(site.ID).snapshot(time.Now().UTC())
	stats.FileCount, stats.FileBytes = count, size
	stats.Site, stats.ServerVersion = site, s.version
	stats.ServerTLSMode = s.serverTLSMode()
	stats.WAFEnabled, stats.WAFAuditOnly = s.cfg.WAFEnabled, s.cfg.WAFAuditOnly
	writeJSON(w, http.StatusOK, stats)
}

// The caller holds sitesMu. Immutable storage IDs let stats polls reuse file
// totals until the next full or incremental publication, including after restart.
func (s *Server) publishedFileTotals(site domain.PublishedSite) (int, int64, error) {
	tracker := s.statsForSite(site.ID)
	tracker.mu.Lock()
	if tracker.filesStorageID == site.StorageID() {
		count, size := tracker.fileCount, tracker.fileBytes
		tracker.mu.Unlock()
		return count, size, nil
	}
	tracker.mu.Unlock()
	count, size, err := publish.FileTotals(filepath.Join(s.publishDir(), site.StorageID()))
	if err != nil {
		return 0, 0, err
	}
	tracker.mu.Lock()
	tracker.filesStorageID, tracker.fileCount, tracker.fileBytes = site.StorageID(), count, size
	tracker.mu.Unlock()
	return count, size, nil
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

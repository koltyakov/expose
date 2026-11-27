package server

import (
	"context"
	"crypto/sha256"
	"io"
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
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/waf"
)

const siteRecentRequests = 20
const siteLatencySamples = 1024
const siteVisitorLimit = domain.PublishedSiteVisitorLimit

type siteVisitorStore interface {
	ListPublishedSiteVisitors(context.Context, string) ([][32]byte, error)
	RecordPublishedSiteVisitors(context.Context, []sqlite.SiteVisitor) error
}

const (
	siteVisitorQueueSize = 4096
	siteVisitorBatchSize = 256
	siteVisitorTimeout   = 5 * time.Second
)

type siteStats struct {
	mu            sync.Mutex
	since         time.Time
	httpRequests  int64
	responseBytes int64
	blocked       int64
	audited       int64
	// visitors maps a truncated fingerprint to the unix-nano time of its last
	// visit; 0 marks a visitor loaded from storage and not seen since. 24
	// bytes per entry instead of 56 for a full hash and a time.Time.
	visitors       map[visitorKey]int64
	visitorsCapped bool
	// Stored visitors load on the first request or stats poll, not for
	// every site at startup. A failed load backs off instead of retrying on
	// every request.
	visitorsLoaded  bool
	visitorsLoading bool
	visitorsRetryAt time.Time
	visitorsBackoff time.Duration
	loadVisitors    func() ([][32]byte, error)
	persistVisitor  func([32]byte) bool
	// Missing entries are queued, durable, or need no persistence. Present
	// entries could not be queued, or their batch failed to commit, and are
	// queued again on the next visit. Keys are a subset of visitors.
	visitorWrites  map[visitorKey]bool
	requests       []domain.PublishedSiteRequest
	latencies      [siteLatencySamples]float64
	latencyCount   int
	latencyNext    int
	filesStorageID string
	fileCount      int
	fileBytes      int64
	presence       map[*websocket.Conn]sitePresence
}

// visitorKey is the first half of a visitor's SHA-256 fingerprint: ample to
// tell up to siteVisitorLimit visitors of one site apart.
type visitorKey [16]byte

func visitorKeyOf(fingerprint [32]byte) visitorKey {
	return visitorKey(fingerprint[:16])
}

const (
	siteVisitorLoadTimeout    = 5 * time.Second
	siteVisitorLoadMinBackoff = 30 * time.Second
	siteVisitorLoadMaxBackoff = 10 * time.Minute
)

// statsForSite returns the site's stats, creating them without touching the
// store; stored visitors load later (see loadStoredVisitors).
func (s *Server) statsForSite(id string) *siteStats {
	if value, ok := s.siteStats.Load(id); ok {
		return value.(*siteStats)
	}
	stats := &siteStats{since: time.Now().UTC(), visitors: make(map[visitorKey]int64)}
	if st, ok := s.store.(siteVisitorStore); ok {
		stats.loadVisitors = func() ([][32]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), siteVisitorLoadTimeout)
			defer cancel()
			visitors, err := st.ListPublishedSiteVisitors(ctx, id)
			if err != nil && s.log != nil {
				s.log.Error("load published site visitors", "site", id, "err", err)
			}
			return visitors, err
		}
		stats.persistVisitor = func(fingerprint [32]byte) bool {
			return s.queueSiteVisitor(sqlite.SiteVisitor{SiteID: id, Fingerprint: fingerprint})
		}
	}
	value, _ := s.siteStats.LoadOrStore(id, stats)
	return value.(*siteStats)
}

// beginVisitorLoadLocked reports whether the caller should load stored
// visitors now, and marks the load as running.
func (stats *siteStats) beginVisitorLoadLocked(now time.Time) bool {
	if stats.loadVisitors == nil || stats.visitorsLoaded || stats.visitorsLoading || now.Before(stats.visitorsRetryAt) {
		return false
	}
	stats.visitorsLoading = true
	return true
}

func (stats *siteStats) finishVisitorLoadLocked(stored [][32]byte, err error, now time.Time) {
	stats.visitorsLoading = false
	if err != nil {
		stats.visitorsBackoff = min(max(2*stats.visitorsBackoff, siteVisitorLoadMinBackoff), siteVisitorLoadMaxBackoff)
		stats.visitorsRetryAt = now.Add(stats.visitorsBackoff)
		return
	}
	// Stored identities take priority over provisional ones: visitors first
	// seen since startup, not yet known to be durable. Members keep their
	// last-seen time. When both do not fit, provisional visitors and their
	// pending writes are dropped; the store would refuse them at the cap.
	stored = stored[:min(len(stored), siteVisitorLimit)]
	missing := 0
	for _, fingerprint := range stored {
		if _, exists := stats.visitors[visitorKeyOf(fingerprint)]; !exists {
			missing++
		}
	}
	if over := len(stats.visitors) + missing - siteVisitorLimit; over > 0 {
		durable := make(map[visitorKey]struct{}, len(stored))
		for _, fingerprint := range stored {
			durable[visitorKeyOf(fingerprint)] = struct{}{}
		}
		// len(stored) <= siteVisitorLimit, so there are at least over
		// provisional visitors.
		for key := range stats.visitors {
			if over == 0 {
				break
			}
			if _, member := durable[key]; !member {
				delete(stats.visitors, key)
				delete(stats.visitorWrites, key)
				over--
			}
		}
		stats.visitorsCapped = true
	}
	for _, fingerprint := range stored {
		key := visitorKeyOf(fingerprint)
		delete(stats.visitorWrites, key) // already durable
		if _, exists := stats.visitors[key]; !exists {
			stats.visitors[key] = 0
		}
	}
	stats.visitorsLoaded = true
	stats.visitorsCapped = stats.visitorsCapped || len(stats.visitors) >= siteVisitorLimit
}

// loadStoredVisitors loads stored visitors before a stats poll reports them.
// It does not wait for a load a request already started.
func (stats *siteStats) loadStoredVisitors() {
	stats.mu.Lock()
	start := stats.beginVisitorLoadLocked(time.Now())
	stats.mu.Unlock()
	if !start {
		return
	}
	stored, err := stats.loadVisitors()
	stats.mu.Lock()
	stats.finishVisitorLoadLocked(stored, err, time.Now())
	stats.mu.Unlock()
}

func (stats *siteStats) record(entry domain.PublishedSiteRequest, ip, userAgent string) {
	// Do not retain query values, headers, addresses, or raw user agents.
	entry.Path, _, _ = strings.Cut(entry.Path, "?")
	entry.Path = boundedStatsText(entry.Path, 2048)
	entry.Method = boundedStatsText(entry.Method, 32)
	entry.WAFRule = boundedStatsText(entry.WAFRule, 128)
	entry.RejectionReason = boundedStatsText(entry.RejectionReason, 64)
	fingerprint := sha256.Sum256([]byte(ip + "\x00" + userAgent))
	stats.mu.Lock()
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
	stats.mu.Unlock()
}

// touchVisitorLocked records a visit. A new visitor is handed to the
// non-blocking persistence queue; the request never waits on SQLite. The
// first visit after a restart loads stored visitors in the background.
func (stats *siteStats) touchVisitorLocked(fingerprint [32]byte, now time.Time) {
	if stats.beginVisitorLoadLocked(time.Now()) {
		load := stats.loadVisitors
		go func() {
			stored, err := load()
			stats.mu.Lock()
			stats.finishVisitorLoadLocked(stored, err, time.Now())
			stats.mu.Unlock()
		}()
	}
	key := visitorKeyOf(fingerprint)
	if _, found := stats.visitors[key]; found || len(stats.visitors) < siteVisitorLimit {
		if !found && stats.persistVisitor != nil {
			if stats.visitorWrites == nil {
				stats.visitorWrites = make(map[visitorKey]bool)
			}
			stats.visitorWrites[key] = true
		}
		stats.visitors[key] = now.UnixNano()
	} else {
		stats.visitorsCapped = true
	}
	if _, pending := stats.visitorWrites[key]; pending && stats.persistVisitor(fingerprint) {
		delete(stats.visitorWrites, key)
	}
}

// queueSiteVisitor hands a new visitor to the batch writer without blocking.
// False means the queue is full; the visit retries on the next request.
func (s *Server) queueSiteVisitor(v sqlite.SiteVisitor) bool {
	select {
	case s.siteVisitors <- v:
		return true
	default:
		s.siteVisitorDrops.Add(1)
		return false
	}
}

// runSiteVisitorWriter batch-inserts queued visitors until ctx is cancelled,
// then flushes what is left and closes done.
func (s *Server) runSiteVisitorWriter(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	batch := make([]sqlite.SiteVisitor, 0, siteVisitorBatchSize)
	for {
		select {
		case <-ctx.Done():
			s.flushSiteVisitors(context.Background())
			return
		case v := <-s.siteVisitors:
			batch = append(batch[:0], v)
			batch = s.drainSiteVisitors(batch)
			s.writeSiteVisitors(ctx, batch)
		}
	}
}

func (s *Server) drainSiteVisitors(batch []sqlite.SiteVisitor) []sqlite.SiteVisitor {
	for len(batch) < siteVisitorBatchSize {
		select {
		case v := <-s.siteVisitors:
			batch = append(batch, v)
		default:
			return batch
		}
	}
	return batch
}

// flushSiteVisitors writes every queued visitor. Shutdown calls it once no
// more requests can arrive.
func (s *Server) flushSiteVisitors(ctx context.Context) {
	batch := make([]sqlite.SiteVisitor, 0, siteVisitorBatchSize)
	for {
		batch = s.drainSiteVisitors(batch[:0])
		if len(batch) == 0 {
			return
		}
		s.writeSiteVisitors(ctx, batch)
	}
}

func (s *Server) writeSiteVisitors(ctx context.Context, batch []sqlite.SiteVisitor) {
	st, ok := s.store.(siteVisitorStore)
	if !ok || len(batch) == 0 {
		return
	}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), siteVisitorTimeout)
	defer cancel()
	if err := st.RecordPublishedSiteVisitors(writeCtx, batch); err != nil {
		if s.log != nil {
			s.log.Error("record published site visitors; retrying on next visit", "visitors", len(batch), "err", err)
		}
		s.retrySiteVisitorsOnNextVisit(batch)
	}
}

// retrySiteVisitorsOnNextVisit marks the visitors of a batch that failed to
// commit as pending, so each is queued again on its next request or presence
// heartbeat. It never creates stats: a site deleted since its visitors were
// queued has none, and its visitors are dropped rather than resurrected.
func (s *Server) retrySiteVisitorsOnNextVisit(batch []sqlite.SiteVisitor) {
	for _, v := range batch {
		if value, ok := s.siteStats.Load(v.SiteID); ok {
			value.(*siteStats).markVisitorWritePending(v.Fingerprint)
		}
	}
}

func (stats *siteStats) markVisitorWritePending(fingerprint [32]byte) {
	key := visitorKeyOf(fingerprint)
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if _, tracked := stats.visitors[key]; !tracked || stats.persistVisitor == nil {
		return
	}
	if stats.visitorWrites == nil {
		stats.visitorWrites = make(map[visitorKey]bool)
	}
	stats.visitorWrites[key] = true
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
	activeSince := now.Add(-time.Minute).UnixNano()
	for _, seen := range stats.visitors {
		if seen > activeSince {
			result.ActiveVisitors++
		}
	}
	// Online sockets are separate from recent visitor activity. Closing or
	// hiding a tab must not leave its socket online for another minute.
	for _, connection := range stats.presence {
		if now.Sub(connection.seen) < sitePresenceTimeout {
			result.ActiveSockets++
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

// writeSiteStats is called with sitesMu held for a published site; release
// drops it. The tracker is resolved and the revision pinned under the lock,
// so the cold file walk and stored-visitor load run unlocked against one
// immutable revision, and a concurrent deletion cannot resurrect its stats.
func (s *Server) writeSiteStats(w http.ResponseWriter, r *http.Request, site domain.PublishedSite, release func()) {
	now := time.Now().UTC()
	if site.ExpiresAt != nil && !now.Before(*site.ExpiresAt) {
		http.NotFound(w, r)
		return
	}
	tracker := s.statsForSite(site.ID)
	unpin := s.pinSiteDir(filepath.Join(s.publishDir(), site.StorageID()))
	release()
	count, size, err := s.pinnedFileTotals(tracker, site)
	unpin()
	if err != nil {
		s.siteError(w, err)
		return
	}
	tracker.loadStoredVisitors()
	stats := tracker.snapshot(time.Now().UTC())
	stats.FileCount, stats.FileBytes = count, size
	stats.Site, stats.ServerVersion = withSiteURL(r, site), s.version
	stats.ServerTLSMode = s.serverTLSMode()
	stats.WAFEnabled, stats.WAFAuditOnly = s.cfg.WAFEnabled, s.cfg.WAFAuditOnly
	writeJSON(w, http.StatusOK, stats)
}

// siteFileTotals walks a revision; tests replace it to hold the walk open.
var siteFileTotals = publish.FileTotals

// pinnedFileTotals returns the totals of site's revision, which the caller
// has pinned. Immutable storage IDs let stats polls reuse them until the next
// full or incremental publication; after a restart they come from a cached
// manifest when there is one, otherwise from one directory walk.
func (s *Server) pinnedFileTotals(tracker *siteStats, site domain.PublishedSite) (int, int64, error) {
	id := site.StorageID()
	tracker.mu.Lock()
	if tracker.filesStorageID == id {
		count, size := tracker.fileCount, tracker.fileBytes
		tracker.mu.Unlock()
		return count, size, nil
	}
	tracker.mu.Unlock()
	count, size, ok := s.siteManifests.fileTotals(id)
	if !ok {
		var err error
		count, size, err = siteFileTotals(filepath.Join(s.publishDir(), id))
		if err != nil {
			return 0, 0, err
		}
	}
	// A revision replaced during the walk keeps the totals primed for its
	// successor.
	s.unlessSiteDirRetired(filepath.Join(s.publishDir(), id), func() {
		tracker.primeFileTotals(id, count, size)
	})
	return count, size, nil
}

// primeFileTotals records the file totals of the revision id.
func (stats *siteStats) primeFileTotals(id string, count int, size int64) {
	stats.mu.Lock()
	stats.filesStorageID, stats.fileCount, stats.fileBytes = id, count, size
	stats.mu.Unlock()
}

// WAF callbacks happen before the public handler. Use the live site index so
// blocked probes never trigger an additional database lookup.
func (s *Server) recordSiteWAF(event waf.BlockEvent) {
	// Most blocks target hosts that are not published sites; skip the lock.
	if _, ok := s.siteHosts.Load(normalizeHost(event.Host)); !ok {
		return
	}
	s.sitesMu.RLock()
	value, ok := s.siteHosts.Load(normalizeHost(event.Host))
	if !ok {
		s.sitesMu.RUnlock()
		return
	}
	site, ok := value.(domain.PublishedSite)
	now := time.Now().UTC()
	if !ok || (site.ExpiresAt != nil && !now.Before(*site.ExpiresAt)) {
		s.sitesMu.RUnlock()
		return
	}
	status := http.StatusForbidden
	if s.cfg.WAFAuditOnly {
		status = 0
	}
	stats := s.statsForSite(site.ID)
	s.sitesMu.RUnlock()
	stats.record(domain.PublishedSiteRequest{
		Time: now, Method: event.Method, Path: event.RequestURI, Status: status,
		WAFRule: event.Rule, AuditOnly: s.cfg.WAFAuditOnly,
	}, event.RemoteAddr, event.UserAgent)
}

type siteStatsWriter struct {
	http.ResponseWriter
	status          int
	bytes           int64
	rejectionReason string
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

// ReadFrom keeps the response's optimized copy path (sendfile on HTTP/1.1)
// visible through the stats wrapper; without it publication bodies fell back
// to a buffered io.Copy with a fresh buffer per response.
func (w *siteStatsWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	var (
		n   int64
		err error
	)
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = readerFrom.ReadFrom(r)
	} else {
		n, err = publish.CopyBuffered(struct{ io.Writer }{w.ResponseWriter}, r)
	}
	w.bytes += n
	return n, err
}

func (w *siteStatsWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

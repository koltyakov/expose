package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

type siteStore interface {
	CreatePublishedSite(context.Context, domain.PublishedSite) error
	ReplacePublishedSite(context.Context, domain.PublishedSite) error
	FindPublishedSite(context.Context, string) (domain.PublishedSite, error)
	ListPublishedSites(context.Context, string) ([]domain.PublishedSite, error)
	DeletePublishedSite(context.Context, string, string) error
}

func (s *Server) publishDir() string {
	if s.cfg.PublishDir != "" {
		return s.cfg.PublishDir
	}
	return s.cfg.DBPath + ".sites"
}

func (s *Server) publishedHostname(label string) (string, error) {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return "", fmt.Errorf("domain is required")
	}
	if err := config.ValidateTunnelSubdomain(label); err != nil {
		return "", err
	}
	return label + "." + normalizeHost(s.cfg.BaseDomain), nil
}

func (s *Server) handleSites(w http.ResponseWriter, r *http.Request) {
	if !s.allowPreAuthRequest(w, r) {
		return
	}
	key, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	st, ok := s.store.(siteStore)
	if !ok {
		http.Error(w, "publishing unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.regLimiter != nil && r.Method != http.MethodGet && !s.regLimiter.allow(key) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/sites")
	id = strings.TrimPrefix(id, "/")
	filesRequest := id == "files" && (r.URL.Query().Has("domain") || r.URL.Query().Has("source_id"))
	statsRequest := strings.HasSuffix(id, "/stats")
	if statsRequest {
		id = strings.TrimSuffix(id, "/stats")
	}
	if strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if (statsRequest && id == "") || ((statsRequest || filesRequest) && r.Method != http.MethodGet) {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost && id == "" {
		s.uploadSite(w, r, st, key)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet {
		s.sitesMu.RLock()
		defer s.sitesMu.RUnlock()
	} else {
		s.sitesMu.Lock()
		defer s.sitesMu.Unlock()
	}
	sites, err := st.ListPublishedSites(r.Context(), key)
	if err != nil {
		s.siteError(w, err)
		return
	}
	if filesRequest {
		s.writeSiteFiles(w, r, sites)
		return
	}
	if r.Method == http.MethodGet && id == "" {
		writeJSON(w, http.StatusOK, sites)
		return
	}
	hostname, _ := s.publishedHostname(id)
	for _, site := range sites {
		if site.ID != id && site.Hostname != hostname {
			continue
		}
		switch r.Method {
		case http.MethodGet:
			if statsRequest {
				s.writeSiteStats(w, r, site)
			} else {
				writeJSON(w, http.StatusOK, site)
			}
		case http.MethodDelete:
			if err := s.deleteSite(r.Context(), st, site); err != nil {
				s.siteError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	http.NotFound(w, r)
}

func (s *Server) uploadSite(w http.ResponseWriter, r *http.Request, st siteStore, key string) {
	sourceID, err := siteSourceID(r.URL.Query().Get("source_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	incremental := false
	if raw := r.URL.Query().Get("incremental"); raw != "" {
		incremental, err = strconv.ParseBool(raw)
		if err != nil {
			http.Error(w, "incremental must be a boolean", http.StatusBadRequest)
			return
		}
	}
	if incremental && r.Header.Get("If-Match") == "" {
		http.Error(w, "incremental publishing requires If-Match from the file listing", http.StatusPreconditionRequired)
		return
	}
	if incremental && sourceID == "" && r.URL.Query().Get("domain") == "" {
		http.Error(w, "incremental publishing requires domain or source_id", http.StatusBadRequest)
		return
	}
	ttl := 7 * 24 * time.Hour
	if raw := r.URL.Query().Get("ttl"); raw != "" {
		var err error
		ttl, err = time.ParseDuration(raw)
		if err != nil || ttl <= 0 {
			http.Error(w, "ttl must be a positive duration", http.StatusBadRequest)
			return
		}
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		s.siteError(w, err)
		return
	}
	id := "site_" + hex.EncodeToString(random[:])
	label := r.URL.Query().Get("domain")
	if label == "" {
		label = hex.EncodeToString(random[:6])
	}
	host, err := s.publishedHostname(label)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(s.publishDir(), 0700); err != nil {
		s.siteError(w, err)
		return
	}
	dir, err := os.MkdirTemp(s.publishDir(), ".upload-")
	if err != nil {
		s.siteError(w, err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	r.Body = http.MaxBytesReader(w, r.Body, publish.MaxArchiveBytes)
	maxBytes := s.cfg.PublishMaxBytes
	if maxBytes <= 0 {
		maxBytes = config.DefaultPublishMaxBytes
	}
	var manifest []domain.PublishedFile
	if incremental {
		manifest, err = publish.ExtractDeltaWithLimit(r.Body, dir, maxBytes)
	} else {
		err = publish.ExtractWithLimit(r.Body, dir, maxBytes)
	}
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) || errors.Is(err, publish.ErrSiteTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, "invalid site archive: "+err.Error(), status)
		return
	}
	site := domain.PublishedSite{ID: id, ContentID: id, APIKeyID: key, SourceID: sourceID, Hostname: host, CreatedAt: time.Now().UTC()}
	if ttl > 0 {
		expires := site.CreatedAt.Add(ttl)
		site.ExpiresAt = &expires
	}
	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	sites, err := st.ListPublishedSites(r.Context(), key)
	if err != nil {
		s.siteError(w, err)
		return
	}
	previous, err := matchingPublishedSite(sites, host, sourceID, r.URL.Query().Get("domain") != "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if expected := r.URL.Query().Get("site_id"); expected != "" && (previous == nil || previous.ID != expected) {
		http.Error(w, "watched publication no longer exists", http.StatusNotFound)
		return
	}
	if incremental {
		if r.Header.Get("If-Match") != publishedSiteRevision(previous) {
			http.Error(w, "publication changed since file listing; retry incremental publishing", http.StatusPreconditionFailed)
			return
		}
		baseDir := ""
		if previous != nil {
			baseDir = filepath.Join(s.publishDir(), previous.StorageID())
		}
		if err := publish.CompleteDelta(baseDir, dir, manifest, maxBytes); err != nil {
			http.Error(w, "invalid incremental site: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if previous != nil {
		site.ID = previous.ID
		site.Hostname = previous.Hostname
		site.CreatedAt = previous.CreatedAt
		if site.SourceID == "" {
			site.SourceID = previous.SourceID
		}
	}
	final := filepath.Join(s.publishDir(), id)
	if err := os.Rename(dir, final); err != nil {
		s.siteError(w, err)
		return
	}
	if previous != nil {
		err = st.ReplacePublishedSite(r.Context(), site)
	} else {
		err = st.CreatePublishedSite(r.Context(), site)
	}
	if err != nil {
		_ = os.RemoveAll(final)
		if isHostnameInUseError(err) {
			http.Error(w, s.hostnameConflict(r.Context(), key, site.Hostname).Error(), http.StatusConflict)
			return
		}
		s.siteError(w, err)
		return
	}
	s.siteHosts.Store(site.Hostname, site)
	s.statsForSite(site.ID)
	status := http.StatusCreated
	if previous != nil {
		status = http.StatusOK
		if err := os.RemoveAll(filepath.Join(s.publishDir(), previous.StorageID())); err != nil && s.log != nil {
			s.log.Warn("remove replaced site files", "site", site.ID, "err", err)
		}
	}
	writeJSON(w, status, site)
}

func siteSourceID(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid source_id")
	}
	return strings.ToLower(raw), nil
}

func matchingPublishedSite(sites []domain.PublishedSite, host, sourceID string, byDomain bool) (*domain.PublishedSite, error) {
	var previous *domain.PublishedSite
	for _, existing := range sites {
		match := existing.Hostname == host
		if !byDomain {
			match = sourceID != "" && existing.SourceID == sourceID
		}
		if !match {
			continue
		}
		if previous != nil {
			return nil, fmt.Errorf("multiple publications match this folder; select one with --domain")
		}
		previous = &existing
	}
	return previous, nil
}

func publishedSiteRevision(site *domain.PublishedSite) string {
	if site == nil {
		return `"new"`
	}
	return strconv.Quote(site.StorageID())
}

// The caller holds sitesMu so the manifest and revision describe one snapshot.
func (s *Server) writeSiteFiles(w http.ResponseWriter, r *http.Request, sites []domain.PublishedSite) {
	sourceID, err := siteSourceID(r.URL.Query().Get("source_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	label := r.URL.Query().Get("domain")
	host := ""
	if label != "" {
		host, err = s.publishedHostname(label)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if sourceID == "" {
		http.Error(w, "provide domain or source_id", http.StatusBadRequest)
		return
	}
	site, err := matchingPublishedSite(sites, host, sourceID, label != "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	files := []domain.PublishedFile{}
	if site != nil {
		files, err = publish.Manifest(filepath.Join(s.publishDir(), site.StorageID()))
		if err != nil {
			s.siteError(w, err)
			return
		}
	}
	w.Header().Set("ETag", publishedSiteRevision(site))
	writeJSON(w, http.StatusOK, files)
}

func (s *Server) siteError(w http.ResponseWriter, err error) {
	if errors.Is(err, sqlite.ErrHostnameInUse) {
		http.Error(w, "hostname already in use", http.StatusConflict)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	if s.log != nil {
		s.log.Error("published site operation failed", "err", err)
	}
	http.Error(w, "published site operation failed", http.StatusInternalServerError)
}

func (s *Server) servePublishedSite(w http.ResponseWriter, r *http.Request, host string) bool {
	if _, known := s.siteHosts.Load(host); !known {
		return false
	}
	st, ok := s.store.(siteStore)
	if !ok {
		return false
	}
	s.sitesMu.RLock()
	defer s.sitesMu.RUnlock()
	site, err := st.FindPublishedSite(r.Context(), host)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		s.siteError(w, err)
		return true
	}
	started := time.Now()
	recorder := &siteStatsWriter{ResponseWriter: w}
	w = recorder
	defer func() {
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		s.statsForSite(site.ID).record(domain.PublishedSiteRequest{
			Time: started.UTC(), Method: r.Method, Path: r.URL.Path, Status: status,
			DurationMS: float64(time.Since(started)) / float64(time.Millisecond), ResponseBytes: recorder.bytes,
		}, s.clientIP(r), r.UserAgent())
	}()
	route := domain.TunnelRoute{Domain: domain.Domain{Hostname: host}}
	if !s.allowPublicRequest(route, r) {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return true
	}
	publish.Serve(w, r, filepath.Join(s.publishDir(), site.StorageID()))
	return true
}

func (s *Server) deleteSite(ctx context.Context, st siteStore, site domain.PublishedSite) error {
	if err := os.RemoveAll(filepath.Join(s.publishDir(), site.StorageID())); err != nil {
		return err
	}
	if err := st.DeletePublishedSite(ctx, site.APIKeyID, site.ID); err != nil {
		return err
	}
	s.siteHosts.Delete(site.Hostname)
	s.siteStats.Delete(site.ID)
	return nil
}

func (s *Server) cleanupPublishedSites(ctx context.Context) error {
	st, ok := s.store.(siteStore)
	if !ok {
		return nil
	}
	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	sites, err := st.ListPublishedSites(ctx, "")
	if err != nil {
		return err
	}
	known := make(map[string]bool, len(sites))
	for _, site := range sites {
		known[site.StorageID()] = true
		if site.ExpiresAt == nil || time.Now().Before(*site.ExpiresAt) {
			s.siteHosts.Store(site.Hostname, site)
			s.statsForSite(site.ID)
			continue
		}
		if err := s.deleteSite(ctx, st, site); err != nil {
			s.log.Error("delete expired site", "site", site.ID, "err", err)
		}
	}
	// Recover archives abandoned by a process crash. Recent staging directories
	// may belong to uploads still in progress, so leave those alone.
	entries, err := os.ReadDir(s.publishDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if known[entry.Name()] || (!strings.HasPrefix(entry.Name(), "site_") && !strings.HasPrefix(entry.Name(), ".upload-")) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if time.Since(info.ModTime()) < 24*time.Hour {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.publishDir(), entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

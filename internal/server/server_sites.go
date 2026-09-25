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
	statsRequest := strings.HasSuffix(id, "/stats")
	if statsRequest {
		id = strings.TrimSuffix(id, "/stats")
	}
	if strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if statsRequest && (id == "" || r.Method != http.MethodGet) {
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
	s.sitesMu.Lock()
	defer s.sitesMu.Unlock()
	sites, err := st.ListPublishedSites(r.Context(), key)
	if err != nil {
		s.siteError(w, err)
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
	sourceID := r.URL.Query().Get("source_id")
	if sourceID != "" {
		decoded, err := hex.DecodeString(sourceID)
		if err != nil || len(decoded) != 32 {
			http.Error(w, "invalid source_id", http.StatusBadRequest)
			return
		}
		sourceID = strings.ToLower(sourceID)
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
	if err := publish.ExtractWithLimit(r.Body, dir, maxBytes); err != nil {
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
	var previous *domain.PublishedSite
	for _, existing := range sites {
		match := existing.Hostname == host
		if r.URL.Query().Get("domain") == "" {
			match = sourceID != "" && existing.SourceID == sourceID
		}
		if !match {
			continue
		}
		if previous != nil {
			http.Error(w, "multiple publications match this folder; select one with --domain", http.StatusConflict)
			return
		}
		previous = &existing
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

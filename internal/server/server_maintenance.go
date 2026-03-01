package server

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func (s *Server) queueDomainTouch(domainID string) {
	domainID = strings.TrimSpace(domainID)
	if domainID == "" || s.domainTouches == nil {
		return
	}
	if !s.reserveDomainTouch(domainID) {
		return
	}
	select {
	case s.domainTouches <- domainID:
	default:
		s.completeDomainTouch(domainID)
	}
}

func (s *Server) runDomainTouchWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case domainID := <-s.domainTouches:
			touchCtx, cancel := context.WithTimeout(ctx, domainTouchTimeout)
			err := s.store.TouchDomain(touchCtx, domainID)
			cancel()
			s.completeDomainTouch(domainID)
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.log.Warn("failed to update domain last seen", "domain_id", domainID, "err", err)
			}
		}
	}
}

func (s *Server) reserveDomainTouch(domainID string) bool {
	s.domainTouchMu.Lock()
	defer s.domainTouchMu.Unlock()
	if s.domainTouched == nil {
		s.domainTouched = make(map[string]struct{})
	}
	if _, exists := s.domainTouched[domainID]; exists {
		return false
	}
	s.domainTouched[domainID] = struct{}{}
	return true
}

func (s *Server) completeDomainTouch(domainID string) {
	s.domainTouchMu.Lock()
	delete(s.domainTouched, domainID)
	s.domainTouchMu.Unlock()
}

func (s *Server) runJanitor(ctx context.Context) {
	heartbeatTicker := time.NewTicker(s.cfg.HeartbeatCheckInterval)
	cleanupTicker := time.NewTicker(s.cfg.CleanupInterval)
	bucketTicker := time.NewTicker(regCleanupAge)
	defer heartbeatTicker.Stop()
	defer cleanupTicker.Stop()
	defer bucketTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			s.expireStaleSessions()
		case <-cleanupTicker.C:
			s.cleanupStaleTemporaryResources(ctx)
			s.routes.cleanup()
			s.cleanupStaleWAFCounters()
		case <-bucketTicker.C:
			s.regLimiter.cleanup()
		}
	}
}

func (s *Server) expireStaleSessions() {
	now := time.Now()

	s.hub.mu.RLock()
	sessions := make([]*session, 0, len(s.hub.sessions))
	for _, sess := range s.hub.sessions {
		sessions = append(sessions, sess)
	}
	s.hub.mu.RUnlock()

	for _, sess := range sessions {
		lastSeen := sess.lastSeen()
		if now.Sub(lastSeen) <= s.cfg.ClientPingTimeout {
			continue
		}
		if !sess.closing.CompareAndSwap(false, true) {
			continue
		}

		s.log.Warn("client heartbeat timeout", "tunnel_id", sess.tunnelID, "last_seen", lastSeen.UTC().Format(time.RFC3339))
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		hostname, closed, err := s.store.CloseTemporaryTunnel(closeCtx, sess.tunnelID)
		closeCancel()
		if err != nil {
			s.log.Error("failed to close stale temporary tunnel", "tunnel_id", sess.tunnelID, "err", err)
		}
		if closed {
			removed, err := removeTunnelCertCache(s.cfg.CertCacheDir, hostname)
			if err != nil {
				s.log.Error("failed to remove certificate cache", "hostname", hostname, "err", err)
			} else if removed > 0 {
				s.log.Info("temporary tunnel certificate cache removed", "hostname", hostname, "files", removed)
			}
		}
		_ = sess.conn.Close()
	}
}

func (s *Server) cleanupStaleTemporaryResources(ctx context.Context) {
	hosts, err := s.store.PurgeInactiveTemporaryDomains(ctx, time.Now().Add(-s.cfg.TempRetention), 100)
	if err != nil {
		s.log.Error("temporary domain cleanup failed", "err", err)
	} else if len(hosts) > 0 {
		removedFiles, failedFiles, err := removeTunnelCertCacheBatch(s.cfg.CertCacheDir, hosts)
		if err != nil {
			s.log.Error("failed to remove certificate cache during cleanup", "err", err)
		} else {
			s.log.Info("stale temporary domains cleaned", "domains", len(hosts), "cert_files", removedFiles, "cert_failures", failedFiles)
		}
	}

	now := time.Now().UTC()
	purged, err := s.store.PurgeStaleConnectTokens(ctx, now, now.Add(-usedTokenRetention), tokenPurgeBatchLimit)
	if err != nil {
		s.log.Error("connect token cleanup failed", "err", err)
	} else if purged > 0 {
		s.log.Info("stale connect tokens cleaned", "tokens", purged)
	}
}

func removeTunnelCertCache(cacheDir, hostname string) (int, error) {
	if strings.TrimSpace(cacheDir) == "" || strings.TrimSpace(hostname) == "" {
		return 0, nil
	}
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name != hostname && !strings.HasPrefix(name, hostname+"+") {
			continue
		}
		path := filepath.Join(cacheDir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func removeTunnelCertCacheBatch(cacheDir string, hosts []string) (int, int, error) {
	if strings.TrimSpace(cacheDir) == "" || len(hosts) == 0 {
		return 0, 0, nil
	}

	hostSet := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		hostSet[host] = struct{}{}
	}
	if len(hostSet) == 0 {
		return 0, 0, nil
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, err
	}

	removed := 0
	failed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !shouldDeleteCertCacheEntry(name, hostSet) {
			continue
		}
		path := filepath.Join(cacheDir, name)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			failed++
			continue
		}
		removed++
	}

	return removed, failed, nil
}

func shouldDeleteCertCacheEntry(name string, hostSet map[string]struct{}) bool {
	if _, ok := hostSet[name]; ok {
		return true
	}
	if idx := strings.IndexByte(name, '+'); idx > 0 {
		_, ok := hostSet[name[:idx]]
		return ok
	}
	return false
}

func (s *Server) cleanupStaleWAFCounters() {
	retention := wafCounterRetentionFor(s.cfg)
	cutoffUnix := time.Now().Add(-retention).UnixNano()
	s.wafBlocks.Range(func(key, value any) bool {
		counter, ok := value.(*wafCounter)
		if !ok {
			s.wafBlocks.Delete(key)
			return true
		}
		if counter.lastSeenUnixNano.Load() < cutoffUnix {
			s.wafBlocks.Delete(key)
		}
		return true
	})
}

func isHostnameInUseError(err error) bool {
	return errors.Is(err, sqlite.ErrHostnameInUse)
}

func (s *Server) trySwapInactiveClientSession(ctx context.Context, keyID, subdomain, clientMachineID string) (domain.Domain, domain.Tunnel, bool, error) {
	subdomain = normalizeHost(subdomain)
	clientMachineID = strings.TrimSpace(clientMachineID)
	if subdomain == "" || clientMachineID == "" {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	host := subdomain + "." + normalizeHost(s.cfg.BaseDomain)
	route, err := s.store.FindRouteByHost(ctx, host)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, false, err
	}
	if route.Domain.APIKeyID != keyID {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	existingMachineID := strings.TrimSpace(route.Tunnel.ClientMeta)
	if existingMachineID != "" && existingMachineID != clientMachineID {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}
	if s.isSessionCurrentlyActive(route.Tunnel.ID) {
		return domain.Domain{}, domain.Tunnel{}, false, nil
	}

	tunnelRec, err := s.store.SwapTunnelSession(ctx, route.Domain.ID, keyID, clientMachineID)
	if err != nil {
		return domain.Domain{}, domain.Tunnel{}, false, err
	}
	s.log.Info("inactive tunnel session swapped",
		"hostname", route.Domain.Hostname,
		"old_tunnel_id", route.Tunnel.ID,
		"new_tunnel_id", tunnelRec.ID)
	return route.Domain, tunnelRec, true, nil
}

func (s *Server) isSessionCurrentlyActive(tunnelID string) bool {
	s.hub.mu.RLock()
	sess := s.hub.sessions[tunnelID]
	s.hub.mu.RUnlock()
	if sess == nil {
		return false
	}
	if sess.closing.Load() {
		return false
	}
	if time.Since(sess.lastSeen()) <= s.cfg.ClientPingTimeout {
		return true
	}
	if sess.closing.CompareAndSwap(false, true) {
		_ = sess.conn.Close()
	}
	return false
}

package server

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/koltyakov/expose/internal/store/sqlite"
)

func (s *Server) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		activeSessions := 0
		pendingHTTP := int64(0)
		openWebSockets := int64(0)
		if s.hub != nil {
			s.hub.mu.RLock()
			activeSessions = len(s.hub.sessions)
			for _, sess := range s.hub.sessions {
				if sess != nil {
					pendingHTTP += sess.pendingCount.Load()
					openWebSockets += sess.webSocketCount.Load()
				}
			}
			s.hub.mu.RUnlock()
		}

		storeStats := sqlite.OperationalStats{}
		if s.store != nil {
			storeStats = s.store.OperationalStats()
		}
		metric := func(name string, value any) {
			_, _ = fmt.Fprintf(w, "%s %v\n", name, value)
		}
		metric("expose_active_tunnel_sessions", activeSessions)
		metric("expose_pending_http_requests", pendingHTTP)
		metric("expose_open_websockets", openWebSockets)
		hosts := make([]string, 0, len(s.bypasses))
		for host := range s.bypasses {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			b := s.bypasses[host]
			b.mu.Lock()
			httpPending, upgradePending, active := b.httpPending, b.upgradePending, len(b.upgrades)
			b.mu.Unlock()
			for _, class := range []struct {
				name        string
				used, limit int
			}{
				{"http", httpPending, b.limits.http}, {"upgrade", upgradePending, b.limits.upgrades},
				{"total", httpPending + upgradePending, b.limits.total},
			} {
				_, _ = fmt.Fprintf(w, "expose_bypass_in_flight{route=%q,class=%q} %d\nexpose_bypass_limit{route=%q,class=%q} %d\n", host, class.name, class.used, host, class.name, class.limit)
			}
			_, _ = fmt.Fprintf(w, "expose_bypass_active_upgrades{route=%q} %d\nexpose_bypass_upgrade_handshakes{route=%q} %d\n", host, active, host, max(0, upgradePending-active))
			for i, reason := range []string{"total", "http", "upgrade", "shutdown"} {
				_, _ = fmt.Fprintf(w, "expose_bypass_rejections_total{route=%q,reason=%q} %d\n", host, reason, b.rejects[i].Load())
			}
			_, _ = fmt.Fprintf(w, "expose_bypass_header_requests_total{route=%q} %d\nexpose_bypass_header_duration_seconds_total{route=%q} %g\n", host, b.headerCount.Load(), host, float64(b.headerNanos.Load())/1e9)
			_, _ = fmt.Fprintf(w, "expose_bypass_upgrades_total{route=%q} %d\nexpose_bypass_upgrade_duration_seconds_total{route=%q} %g\n", host, b.upgradeCount.Load(), host, float64(b.upgradeNanos.Load())/1e9)
			_, _ = fmt.Fprintf(w, "expose_bypass_upgrade_completions_total{route=%q} %d\n", host, b.upgradeCompleted.Load())
		}
		metric("expose_tunnel_connections_total", s.connectionsTotal.Load())
		metric("expose_response_queue_bytes", s.queuedResponses.used.Load())
		metric("expose_response_queue_limit_bytes", s.queuedResponses.limit)
		metric("expose_response_queue_rejects_total", s.responseQueueRejects.Load())
		metric("expose_route_cache_entries", s.routes.size())
		metric("expose_live_route_entries", s.liveRoutes.size())
		metric("expose_route_cache_hits_total", s.routeCacheHits.Load())
		metric("expose_route_cache_misses_total", s.routeCacheMisses.Load())
		metric("expose_route_store_loads_total", s.routeStoreLoads.Load())
		metric("expose_disconnect_queue_depth", len(s.disconnects))
		metric("expose_domain_touch_queue_depth", len(s.domainTouches))
		metric("expose_waf_audit_queue_depth", len(s.wafAuditQueue))
		metric("expose_disconnect_drops_total", s.disconnectDrops.Load())
		metric("expose_domain_touch_drops_total", s.domainTouchDrops.Load())
		metric("expose_waf_audit_drops_total", s.wafAuditDrops.Load())
		metric("expose_shutdown_duration_seconds", float64(s.shutdownNanos.Load())/1e9)
		metric("expose_sqlite_open_connections", storeStats.OpenConnections)
		metric("expose_sqlite_in_use_connections", storeStats.InUseConnections)
		metric("expose_sqlite_idle_connections", storeStats.IdleConnections)
		metric("expose_sqlite_write_queue_depth", storeStats.WriteQueueDepth)
		metric("expose_sqlite_touch_queue_depth", storeStats.TouchQueueDepth)
		metric("expose_sqlite_write_operations_total", storeStats.OperationCount)
		metric("expose_sqlite_write_duration_seconds_total", float64(storeStats.OperationNanos)/1e9)
		metric("expose_sqlite_write_duration_seconds_max", float64(storeStats.OperationMaxNanos)/1e9)
	}
}

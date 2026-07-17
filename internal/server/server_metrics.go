package server

import (
	"fmt"
	"net/http"

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
		metric("expose_tunnel_connections_total", s.connectionsTotal.Load())
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

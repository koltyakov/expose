package server

import (
	"context"
	"strings"
	"time"
)

func (s *Server) queueTunnelDisconnect(tunnelID string) {
	tunnelID = strings.TrimSpace(tunnelID)
	if tunnelID == "" {
		return
	}

	if !s.reserveDisconnectTunnel(tunnelID) {
		return
	}

	select {
	case s.disconnects <- tunnelID:
	default:
		s.completeDisconnectTunnel(tunnelID)
		s.disconnectDrops.Add(1)
		s.markTunnelDisconnectedNow(s.serverContext(), tunnelID)
	}
}

func (s *Server) reserveDisconnectTunnel(tunnelID string) bool {
	s.disconnectMu.Lock()
	defer s.disconnectMu.Unlock()
	if s.disconnectQ == nil {
		s.disconnectQ = make(map[string]struct{})
	}
	if _, exists := s.disconnectQ[tunnelID]; exists {
		return false
	}
	s.disconnectQ[tunnelID] = struct{}{}
	return true
}

func (s *Server) completeDisconnectTunnel(tunnelID string) {
	s.disconnectMu.Lock()
	delete(s.disconnectQ, tunnelID)
	s.disconnectMu.Unlock()
}

func (s *Server) completeDisconnectBatch(tunnelIDs []string) {
	if len(tunnelIDs) == 0 {
		return
	}
	s.disconnectMu.Lock()
	for _, id := range tunnelIDs {
		delete(s.disconnectQ, id)
	}
	s.disconnectMu.Unlock()
}

func (s *Server) runDisconnectWorker(ctx context.Context) {
	s.disconnectWg.Add(1)
	defer s.disconnectWg.Done()

	// The flush timer is armed only while a batch is pending, so an idle
	// server does not wake every disconnectFlushInterval.
	timer := time.NewTimer(disconnectFlushInterval)
	timer.Stop()
	defer timer.Stop()
	var flushC <-chan time.Time

	// ctx only signals shutdown. Store writes use storeCtx so the final drain,
	// which runs after cancellation, can still record disconnects; during that
	// drain storeCtx carries one overall deadline so a stalled database cannot
	// hold shutdown for a timeout per tunnel.
	storeCtx := context.WithoutCancel(ctx)

	batch := make([]string, 0, disconnectBatchSize)
	flush := func() {
		timer.Stop()
		flushC = nil
		if len(batch) == 0 {
			return
		}
		toFlush := make([]string, len(batch))
		copy(toFlush, batch)
		batch = batch[:0]

		s.routeLifecycleMu.Lock()
		candidates := make([]string, 0, len(toFlush))
		for _, tunnelID := range toFlush {
			if !s.activeTunnels.isConnected(tunnelID) {
				candidates = append(candidates, tunnelID)
			}
		}
		if len(candidates) == 0 {
			s.completeDisconnectBatch(toFlush)
			s.routeLifecycleMu.Unlock()
			return
		}

		disconnectCtx, cancel := context.WithTimeout(storeCtx, disconnectTimeout)
		err := s.store.SetTunnelsDisconnected(disconnectCtx, candidates)
		cancel()
		if err != nil {
			s.log.Error("failed to mark tunnel batch disconnected", "count", len(candidates), "err", err)
			for _, tunnelID := range candidates {
				s.markTunnelDisconnectedNowLocked(storeCtx, tunnelID)
			}
		}
		s.completeDisconnectBatch(toFlush)
		s.routeLifecycleMu.Unlock()
	}

	for {
		select {
		case <-ctx.Done():
			drainCtx, cancelDrain := context.WithTimeout(storeCtx, disconnectTimeout)
			defer cancelDrain()
			storeCtx = drainCtx
			drain := true
			for drain {
				select {
				case tunnelID := <-s.disconnects:
					batch = append(batch, tunnelID)
					if len(batch) >= disconnectBatchSize {
						flush()
					}
				default:
					drain = false
				}
			}
			flush()
			return
		case tunnelID := <-s.disconnects:
			batch = append(batch, tunnelID)
			if len(batch) >= disconnectBatchSize {
				flush()
			} else if flushC == nil {
				timer.Reset(disconnectFlushInterval)
				flushC = timer.C
			}
		case <-flushC:
			flushC = nil
			flush()
		}
	}
}

func (s *Server) markTunnelDisconnectedNow(ctx context.Context, tunnelID string) {
	s.routeLifecycleMu.Lock()
	defer s.routeLifecycleMu.Unlock()
	if s.activeTunnels.isConnected(tunnelID) {
		return
	}
	s.markTunnelDisconnectedNowLocked(ctx, tunnelID)
}

func (s *Server) markTunnelDisconnectedNowLocked(ctx context.Context, tunnelID string) {
	s.activeTunnels.markDisconnected(tunnelID)
	disconnectCtx, cancel := context.WithTimeout(contextOrBackground(ctx), disconnectTimeout)
	err := s.store.SetTunnelDisconnected(disconnectCtx, tunnelID)
	cancel()
	if err != nil {
		s.log.Error("failed to mark tunnel disconnected", "tunnel_id", tunnelID, "err", err)
	}
}

func (s *Server) serverContext() context.Context {
	if s == nil {
		return context.Background()
	}
	if ctx, ok := s.runtimeCtx.Load().(context.Context); ok && ctx != nil {
		return ctx
	}
	return context.Background()
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

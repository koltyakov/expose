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

	ticker := time.NewTicker(disconnectFlushInterval)
	defer ticker.Stop()

	batch := make([]string, 0, disconnectBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		toFlush := make([]string, len(batch))
		copy(toFlush, batch)
		batch = batch[:0]

		disconnectCtx, cancel := context.WithTimeout(ctx, disconnectTimeout)
		err := s.store.SetTunnelsDisconnected(disconnectCtx, toFlush)
		cancel()
		if err != nil {
			s.log.Error("failed to mark tunnel batch disconnected", "count", len(toFlush), "err", err)
			for _, tunnelID := range toFlush {
				s.markTunnelDisconnectedNow(ctx, tunnelID)
			}
			s.completeDisconnectBatch(toFlush)
			return
		}
		s.completeDisconnectBatch(toFlush)
	}

	for {
		select {
		case <-ctx.Done():
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
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *Server) markTunnelDisconnectedNow(ctx context.Context, tunnelID string) {
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

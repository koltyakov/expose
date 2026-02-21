package server

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/waf"
)

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	tunnelID, err := s.store.ConsumeConnectToken(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error("websocket upgrade failed", "err", err)
		return
	}

	if err := s.store.SetTunnelConnected(r.Context(), tunnelID); err != nil {
		_ = conn.Close()
		s.log.Error("failed to mark tunnel connected", "tunnel_id", tunnelID, "err", err)
		return
	}
	// Evict any stale cached route entry so the next public request reflects
	// the newly connected state.
	s.routes.deleteByTunnelID(tunnelID)

	sess := &session{
		tunnelID:  tunnelID,
		conn:      conn,
		pending:   make(map[string]chan tunnelproto.Message),
		wsPending: make(map[string]chan tunnelproto.Message),
	}
	wsReadLimit := s.cfg.MaxBodyBytes * 2
	if wsReadLimit < minWSReadLimit {
		wsReadLimit = minWSReadLimit
	}
	sess.conn.SetReadLimit(wsReadLimit)
	sess.touch(time.Now())
	s.hub.mu.Lock()
	s.hub.sessions[tunnelID] = sess
	s.hub.mu.Unlock()
	s.log.Info("tunnel connected", "tunnel_id", tunnelID)

	s.hub.wg.Add(1)
	go func() {
		defer s.hub.wg.Done()
		s.readLoop(sess)
	}()
}

func (s *Server) readLoop(sess *session) {
	defer func() {
		_ = sess.conn.Close()
		sess.closePending()
		sess.closeWSPending()
		s.hub.mu.Lock()
		delete(s.hub.sessions, sess.tunnelID)
		s.hub.mu.Unlock()
		s.routes.deleteByTunnelID(sess.tunnelID)
		disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := s.store.SetTunnelDisconnected(disconnectCtx, sess.tunnelID); err != nil {
			s.log.Error("failed to mark tunnel disconnected", "tunnel_id", sess.tunnelID, "err", err)
		}
		disconnectCancel()
		s.log.Info("tunnel disconnected", "tunnel_id", sess.tunnelID)
	}()

	for {
		var msg tunnelproto.Message
		if err := tunnelproto.ReadWSMessage(sess.conn, &msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				s.log.Warn("tunnel read error", "tunnel_id", sess.tunnelID, "err", err)
			}
			return
		}
		sess.touch(time.Now())

		switch msg.Kind {
		case tunnelproto.KindResponse:
			if msg.Response == nil {
				continue
			}
			if msg.Response.Streamed {
				// Streamed: send header message but keep pending entry open
				// for subsequent body chunks.
				if ch, ok := sess.pendingLoad(msg.Response.ID); ok {
					select {
					case ch <- msg:
					default:
					}
				}
			} else {
				if v, ok := sess.pendingLoadAndDelete(msg.Response.ID); ok {
					sess.releasePending()
					select {
					case v <- msg:
					default:
					}
					close(v)
				}
			}
		case tunnelproto.KindRespBody:
			if msg.BodyChunk == nil {
				continue
			}
			if ch, ok := sess.pendingLoad(msg.BodyChunk.ID); ok {
				if !sess.streamSend(ch, msg, streamBodySendTimeout) {
					s.log.Warn("stream consumer too slow, aborting",
						"tunnel_id", sess.tunnelID, "req_id", msg.BodyChunk.ID)
					if sess.pendingDelete(msg.BodyChunk.ID) {
						sess.releasePending()
						close(ch)
					}
				}
			}
		case tunnelproto.KindRespBodyEnd:
			if msg.BodyChunk == nil {
				continue
			}
			if v, ok := sess.pendingLoadAndDelete(msg.BodyChunk.ID); ok {
				sess.releasePending()
				select {
				case v <- msg:
				default:
				}
				close(v)
			}
		case tunnelproto.KindWSOpenAck:
			if msg.WSOpenAck == nil {
				continue
			}
			if !sess.wsPendingSend(msg.WSOpenAck.ID, msg, wsControlDispatchWait) {
				s.log.Debug("dropped websocket open ack due stalled stream consumer", "tunnel_id", sess.tunnelID, "stream_id", msg.WSOpenAck.ID)
			}
		case tunnelproto.KindWSData:
			if msg.WSData == nil {
				continue
			}
			if !sess.wsPendingSend(msg.WSData.ID, msg, wsDataDispatchWait) {
				s.log.Warn("closing tunnel due websocket stream backpressure", "tunnel_id", sess.tunnelID, "stream_id", msg.WSData.ID)
				return
			}
		case tunnelproto.KindWSClose:
			if msg.WSClose == nil {
				continue
			}
			if !sess.wsPendingSend(msg.WSClose.ID, msg, wsControlDispatchWait) {
				s.log.Debug("dropped websocket close signal due stalled stream consumer", "tunnel_id", sess.tunnelID, "stream_id", msg.WSClose.ID)
			}
		case tunnelproto.KindPing:
			pong := tunnelproto.Message{Kind: tunnelproto.KindPong}
			if s.cfg.WAFEnabled {
				if total := s.wafBlocksForTunnel(sess.tunnelID); total > 0 {
					pong.Stats = &tunnelproto.Stats{WAFBlocked: total}
				}
			}
			_ = sess.writeJSON(pong)
		}
	}
}

func (s *Server) authenticate(r *http.Request) (string, bool) {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return "", false
	}
	key := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if key == "" {
		return "", false
	}
	h := auth.HashAPIKey(key, s.cfg.APIKeyPepper)
	keyID, err := s.store.ResolveAPIKeyID(r.Context(), h)
	if err != nil {
		return "", false
	}
	return keyID, true
}

func isAuthorizedBasicPassword(r *http.Request, expectedUser, hash string) bool {
	user, password, ok := r.BasicAuth()
	if !ok {
		return false
	}
	if user != expectedUser {
		return false
	}
	return auth.VerifyPasswordHash(hash, password)
}

func writeBasicAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="expose", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (s *session) writeJSON(msg tunnelproto.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		_ = s.conn.Close()
		return err
	}
	defer func() { _ = s.conn.SetWriteDeadline(time.Time{}) }()
	err := s.conn.WriteJSON(msg)
	if err != nil {
		_ = s.conn.Close()
	}
	return err
}

func (s *session) writeBinaryFrame(frameKind byte, id string, wsMessageType int, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout)); err != nil {
		_ = s.conn.Close()
		return err
	}
	defer func() { _ = s.conn.SetWriteDeadline(time.Time{}) }()

	w, err := s.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		_ = s.conn.Close()
		return err
	}
	if err := tunnelproto.WriteBinaryFrame(w, frameKind, id, wsMessageType, payload); err != nil {
		_ = w.Close()
		_ = s.conn.Close()
		return err
	}
	if err := w.Close(); err != nil {
		_ = s.conn.Close()
		return err
	}
	return nil
}

func (s *session) writeWSData(streamID string, messageType int, payload []byte) error {
	return s.writeBinaryFrame(tunnelproto.BinaryFrameWSData, streamID, messageType, payload)
}

func (s *session) touch(t time.Time) {
	s.lastSeenUnixNano.Store(t.UnixNano())
}

func (s *session) lastSeen() time.Time {
	n := s.lastSeenUnixNano.Load()
	if n == 0 {
		return time.Unix(0, 0)
	}
	return time.Unix(0, n)
}

func (s *session) closePending() {
	s.pendingMu.Lock()
	for k, ch := range s.pending {
		delete(s.pending, k)
		s.pendingCount.Add(-1)
		close(ch)
	}
	s.pendingMu.Unlock()
}

func (s *session) pendingStore(id string, ch chan tunnelproto.Message) {
	s.pendingMu.Lock()
	s.pending[id] = ch
	s.pendingMu.Unlock()
}

func (s *session) pendingLoad(id string) (chan tunnelproto.Message, bool) {
	s.pendingMu.RLock()
	ch, ok := s.pending[id]
	s.pendingMu.RUnlock()
	return ch, ok
}

func (s *session) pendingLoadAndDelete(id string) (chan tunnelproto.Message, bool) {
	s.pendingMu.Lock()
	ch, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.pendingMu.Unlock()
	return ch, ok
}

func (s *session) pendingDelete(id string) bool {
	s.pendingMu.Lock()
	_, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.pendingMu.Unlock()
	return ok
}

func (s *session) wsPendingStore(id string, ch chan tunnelproto.Message) {
	s.wsMu.Lock()
	s.wsPending[id] = ch
	s.wsMu.Unlock()
}

func (s *session) wsPendingLoad(id string) (chan tunnelproto.Message, bool) {
	s.wsMu.RLock()
	ch, ok := s.wsPending[id]
	s.wsMu.RUnlock()
	return ch, ok
}

func (s *session) wsPendingSend(id string, msg tunnelproto.Message, wait time.Duration) bool {
	ch, ok := s.wsPendingLoad(id)
	if !ok {
		return true
	}

	select {
	case ch <- msg:
		return true
	default:
	}

	if wait <= 0 {
		return false
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ch <- msg:
		return true
	case <-timer.C:
		return false
	}
}

func (s *session) wsPendingDelete(id string) {
	s.wsMu.Lock()
	delete(s.wsPending, id)
	s.wsMu.Unlock()
}

func (s *session) closeWSPending() {
	s.wsMu.Lock()
	for id, ch := range s.wsPending {
		delete(s.wsPending, id)
		close(ch)
	}
	s.wsMu.Unlock()
}

// recordWAFBlock increments the WAF-blocked counter for the given hostname
// and emits a structured audit log entry that identifies the protected
// tunnel endpoint.
func (s *Server) recordWAFBlock(evt waf.BlockEvent) {
	val, _ := s.wafBlocks.LoadOrStore(evt.Host, &atomic.Int64{})
	count := val.(*atomic.Int64).Add(1)

	event := wafAuditEvent{
		event:       evt,
		totalBlocks: count,
	}
	if s.wafAuditQueue != nil {
		select {
		case s.wafAuditQueue <- event:
		default:
		}
		return
	}

	s.logWAFAuditEvent(context.Background(), event)
}

func (s *Server) runWAFAuditWorker(ctx context.Context) {
	if s.wafAuditQueue == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-s.wafAuditQueue:
			s.logWAFAuditEvent(ctx, evt)
		}
	}
}

func (s *Server) logWAFAuditEvent(parentCtx context.Context, audit wafAuditEvent) {
	tunnelID := "unknown"
	domainName := audit.event.Host
	route, ok := s.routes.get(audit.event.Host)
	if !ok && s.store != nil {
		lookupCtx, cancel := context.WithTimeout(parentCtx, wafAuditLookupTimeout)
		r, err := s.store.FindRouteByHost(lookupCtx, audit.event.Host)
		cancel()
		if err == nil {
			route = r
			ok = true
		}
	}
	if ok {
		tunnelID = route.Tunnel.ID
		domainName = route.Domain.Hostname
	}

	if s.log == nil {
		return
	}
	s.log.Warn("waf audit: request blocked",
		"rule", audit.event.Rule,
		"tunnel_id", tunnelID,
		"domain", domainName,
		"method", audit.event.Method,
		"uri", audit.event.RequestURI,
		"remote", audit.event.RemoteAddr,
		"ua", audit.event.UserAgent,
		"total_blocks", audit.totalBlocks,
	)
}

// wafBlocksForTunnel returns the total number of WAF-blocked requests for
// all hostnames associated with the given tunnel.
func (s *Server) wafBlocksForTunnel(tunnelID string) int64 {
	s.routes.mu.RLock()
	hosts := s.routes.hostsByTunnel[tunnelID]
	// Copy the set while holding the lock.
	hostnames := make([]string, 0, len(hosts))
	for h := range hosts {
		hostnames = append(hostnames, h)
	}
	s.routes.mu.RUnlock()

	var total int64
	for _, h := range hostnames {
		if val, ok := s.wafBlocks.Load(h); ok {
			total += val.(*atomic.Int64).Load()
		}
	}
	return total
}

func (s *session) tryAcquirePending(limit int64) bool {
	if limit <= 0 {
		return true
	}
	next := s.pendingCount.Add(1)
	if next <= limit {
		return true
	}
	s.pendingCount.Add(-1)
	return false
}

func (s *session) releasePending() {
	s.pendingCount.Add(-1)
}

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
	"github.com/koltyakov/expose/internal/waf"
)

type http3ConnContextKey struct{}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	tunnelID, ok := s.consumeConnectToken(w, r)
	if !ok {
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error("websocket upgrade failed", "err", err)
		return
	}
	transport := tunneltransport.NewWebSocketTransport(conn)
	writer := tunneltransport.NewWebSocketWritePump(conn, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize)

	if err := s.store.TrySetTunnelConnected(r.Context(), tunnelID); err != nil {
		if errors.Is(err, domain.ErrTunnelLimitReached) {
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.ClosePolicyViolation, domain.ErrTunnelLimitReached.Error()),
				time.Now().Add(5*time.Second),
			)
			_ = conn.Close()
			s.log.Warn("refused tunnel connect: active tunnel limit reached", "tunnel_id", tunnelID)
			return
		}
		_ = conn.Close()
		s.log.Error("failed to mark tunnel connected", "tunnel_id", tunnelID, "err", err)
		return
	}
	s.activateSession(tunnelID, conn, transport, writer)
}

func (s *Server) handleConnectH3(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tunnelID, ok := s.consumeConnectToken(w, r)
	if !ok {
		return
	}
	httpStreamer, ok := w.(http3.HTTPStreamer)
	if !ok {
		http.Error(w, "http3 stream takeover unavailable", http.StatusInternalServerError)
		return
	}
	if err := s.store.TrySetTunnelConnected(r.Context(), tunnelID); err != nil {
		if errors.Is(err, domain.ErrTunnelLimitReached) {
			http.Error(w, domain.ErrTunnelLimitReached.Error(), http.StatusTooManyRequests)
			s.log.Warn("refused http3 tunnel connect: active tunnel limit reached", "tunnel_id", tunnelID)
			return
		}
		s.log.Error("failed to mark tunnel connected", "tunnel_id", tunnelID, "err", err)
		http.Error(w, "failed to mark tunnel connected", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	stream := httpStreamer.HTTPStream()
	var conn *quic.Conn
	if v := r.Context().Value(http3ConnContextKey{}); v != nil {
		if qc, ok := v.(*quic.Conn); ok {
			conn = qc
		}
	}
	closeFn := func() error {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		err := stream.Close()
		if conn != nil {
			_ = conn.CloseWithError(0, "")
		}
		return err
	}
	transport := tunneltransport.NewStreamTransport("quic", stream, closeFn)
	writer := tunneltransport.NewStreamWritePump(stream, wsWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() {
		_ = closeFn()
	})
	s.activateSession(tunnelID, nil, transport, writer)
}

func (s *Server) consumeConnectToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return "", false
	}
	tunnelID, err := s.store.ConsumeConnectToken(r.Context(), token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return "", false
	}
	return tunnelID, true
}

func (s *Server) activateSession(tunnelID string, conn *websocket.Conn, transport tunneltransport.Transport, writer *tunneltransport.WritePump) {
	s.routes.deleteByTunnelID(tunnelID)

	sess := &session{
		tunnelID:      tunnelID,
		conn:          conn,
		transport:     transport,
		writer:        writer,
		transportName: tunneltransport.NameOf(transport),
		pending:       make(map[string]chan tunnelproto.Message),
		wsPending:     make(map[string]chan tunnelproto.Message),
	}
	wsReadLimit := max(s.cfg.MaxBodyBytes*2, minWSReadLimit)
	sess.transport.SetReadLimit(wsReadLimit)
	sess.touch(time.Now())
	prev := s.replaceSession(tunnelID, sess)
	if prev != nil && prev != sess {
		s.log.Warn("replacing existing tunnel session", "tunnel_id", tunnelID, "transport", prev.transportName)
		if prev.transport != nil {
			_ = prev.transport.Close()
		}
	}
	s.log.Info("tunnel connected", "tunnel_id", tunnelID, "transport", sess.transportName)

	s.hub.wg.Add(1)
	go func() {
		defer s.hub.wg.Done()
		s.readLoop(sess)
	}()
}

func (s *Server) readLoop(sess *session) {
	defer func() {
		if sess.transport != nil {
			_ = sess.transport.Close()
		} else if sess.conn != nil {
			_ = sess.conn.Close()
		}
		if sess.writer != nil {
			sess.writer.Close()
		}
		sess.closePending()
		sess.closeWSPending()
		if s.removeSessionIfCurrent(sess) {
			s.routes.deleteByTunnelID(sess.tunnelID)
			disconnectCtx, disconnectCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.store.SetTunnelDisconnected(disconnectCtx, sess.tunnelID); err != nil {
				s.log.Error("failed to mark tunnel disconnected", "tunnel_id", sess.tunnelID, "err", err)
			}
			disconnectCancel()
			s.log.Info("tunnel disconnected", "tunnel_id", sess.tunnelID, "transport", sess.transportName)
		} else {
			s.log.Debug("stale tunnel session closed", "tunnel_id", sess.tunnelID)
		}
	}()

	for {
		var msg tunnelproto.Message
		if err := sess.transport.ReadMessage(&msg); err != nil {
			if sess.transportName == "ws" && websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
				s.log.Warn("tunnel read error", "tunnel_id", sess.tunnelID, "transport", sess.transportName, "err", err)
				return
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
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
						_ = sess.cancelRequest(msg.BodyChunk.ID)
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

func (s *session) writeJSON(msg tunnelproto.Message) error {
	if s.writer == nil {
		return tunneltransport.ErrWritePumpClosed
	}
	return s.writer.WriteJSON(msg)
}

func (s *session) writeBinaryFrame(frameKind byte, id string, wsMessageType int, payload []byte) error {
	if s.writer == nil {
		return tunneltransport.ErrWritePumpClosed
	}
	return s.writer.WriteBinaryFrame(frameKind, id, wsMessageType, payload)
}

func (s *session) writeWSData(streamID string, messageType int, payload []byte) error {
	return s.writeBinaryFrame(tunnelproto.BinaryFrameWSData, streamID, messageType, payload)
}

func (s *session) cancelRequest(id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	if s.writer == nil {
		return nil
	}
	return s.writeJSON(tunnelproto.Message{
		Kind:      tunnelproto.KindReqCancel,
		ReqCancel: &tunnelproto.RequestCancel{ID: id},
	})
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
	nowUnix := time.Now().UnixNano()
	val, _ := s.wafBlocks.LoadOrStore(evt.Host, &wafCounter{})
	counter := val.(*wafCounter)
	counter.lastSeenUnixNano.Store(nowUnix)
	count := counter.total.Add(1)

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
	route, found, cached := s.routes.lookup(audit.event.Host)
	ok := cached && found
	if !cached && s.store != nil {
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
			total += val.(*wafCounter).total.Load()
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

func (s *Server) replaceSession(tunnelID string, next *session) *session {
	s.hub.mu.Lock()
	prev := s.hub.sessions[tunnelID]
	s.hub.sessions[tunnelID] = next
	s.hub.mu.Unlock()
	return prev
}

func (s *Server) removeSessionIfCurrent(sess *session) bool {
	s.hub.mu.Lock()
	current, ok := s.hub.sessions[sess.tunnelID]
	if !ok || current != sess {
		s.hub.mu.Unlock()
		return false
	}
	delete(s.hub.sessions, sess.tunnelID)
	s.hub.mu.Unlock()
	return true
}

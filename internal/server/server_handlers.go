package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	keyID, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.regLimiter.allow(keyID) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded", ErrorCode: errCodeRateLimit})
		return
	}

	active, err := s.store.ActiveTunnelCountByKey(r.Context(), keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if active >= s.cfg.MaxActivePerKey {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "active tunnel limit reached", ErrorCode: errCodeTunnelLimit})
		return
	}

	prepared, ok := s.parseAndValidateRegisterRequest(w, r)
	if !ok {
		return
	}

	domainRec, tunnelRec, err := s.allocateRegisterRoute(r.Context(), keyID, prepared)
	if err != nil {
		if errors.Is(err, errRegisterSwapInactive) {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if isHostnameInUseError(err) {
			writeJSON(w, http.StatusConflict, errorResponse{Error: err.Error(), ErrorCode: errCodeHostnameInUse})
		} else {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}

	if err = s.store.SetTunnelAccessCredentials(r.Context(), tunnelRec.ID, prepared.accessUser, prepared.passwordHash); err != nil {
		http.Error(w, "failed to persist tunnel auth settings", http.StatusInternalServerError)
		return
	}

	token, err := s.store.CreateConnectToken(r.Context(), tunnelRec.ID, s.cfg.ConnectTokenTTL)
	if err != nil {
		http.Error(w, "failed to create connect token", http.StatusInternalServerError)
		return
	}

	publicURL, wsURL := s.registerURLs(r.Host, domainRec.Hostname, token)

	resp := registerResponse{
		TunnelID:      tunnelRec.ID,
		PublicURL:     publicURL,
		WSURL:         wsURL,
		ServerTLSMode: s.serverTLSMode(),
		ServerVersion: s.version,
		WAFEnabled:    s.cfg.WAFEnabled,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
		http.NotFound(w, r)
		return
	}

	host := normalizeHost(r.Host)
	route, err := s.resolvePublicRoute(r.Context(), host)
	if err != nil {
		status, msg := publicRouteLookupErrorStatus(err)
		http.Error(w, msg, status)
		return
	}

	sess, status, msg, ok := s.resolvePublicSession(route)
	if !ok {
		http.Error(w, msg, status)
		return
	}

	if !s.authorizePublicRequest(w, r, route) {
		return
	}

	if websocket.IsWebSocketUpgrade(r) {
		s.handlePublicWebSocket(w, r, route, sess)
		return
	}

	s.proxyPublicHTTP(w, r, route, sess)
}

func (s *Server) handlePublicWebSocket(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	streamID := s.nextWSStreamID()
	streamCh := make(chan tunnelproto.Message, 64)
	sess.wsPendingStore(streamID, streamCh)
	defer sess.wsPendingDelete(streamID)

	headers := tunnelproto.CloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	injectForwardedProxyHeaders(headers, r)
	injectForwardedFor(headers, r.RemoteAddr)
	openMsg := tunnelproto.Message{
		Kind: tunnelproto.KindWSOpen,
		WSOpen: &tunnelproto.WSOpen{
			ID:      streamID,
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   r.URL.RawQuery,
			Headers: headers,
		},
	}
	if err := sess.writeJSON(openMsg); err != nil {
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	timer := time.NewTimer(s.cfg.RequestTimeout)
	stopTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	defer stopTimer()

	ack, status, msg := s.waitForPublicWSOpenAck(r, timer, streamCh)
	if status != 0 {
		if msg != "" {
			http.Error(w, msg, status)
		}
		return
	}
	stopTimer()

	if !ack.OK {
		status, message := publicWSOpenFailure(ack)
		http.Error(w, message, status)
		return
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	if p := strings.TrimSpace(ack.Subprotocol); p != "" {
		upgrader.Subprotocols = []string{p}
	}
	publicConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSClose, WSClose: &tunnelproto.WSClose{ID: streamID, Code: websocket.CloseGoingAway, Text: "public upgrade failed"}})
		return
	}
	defer func() {
		_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSClose, WSClose: &tunnelproto.WSClose{ID: streamID, Code: websocket.CloseNormalClosure}})
	}()
	defer func() { _ = publicConn.Close() }()

	s.queueDomainTouch(route.Domain.ID)

	readDone := make(chan struct{})
	writeDone := make(chan struct{})
	relayStop := make(chan struct{})
	defer close(relayStop)

	s.startPublicWSReadRelay(streamID, sess, publicConn, readDone)
	s.startPublicWSWriteRelay(r, streamID, publicConn, streamCh, relayStop, writeDone)

	select {
	case <-r.Context().Done():
	case <-readDone:
	case <-writeDone:
	}
}

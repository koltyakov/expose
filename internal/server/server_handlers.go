package server

import (
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/timerpool"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.allowPreAuthRequest(w, r) {
		return
	}
	keyID, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.regLimiter.allow(keyID) {
		writeJSON(w, http.StatusTooManyRequests, domain.ErrorResponse{Error: "rate limit exceeded", ErrorCode: errCodeRateLimit})
		return
	}

	prepared, ok := s.parseAndValidateRegisterRequest(w, r)
	if !ok {
		return
	}
	resumeTunnelID := r.Header.Get(domain.RegisterResumeTunnelHeader)
	if err := s.prepareRegisterPasswordHash(r.Context(), keyID, resumeTunnelID, &prepared); err != nil {
		http.Error(w, "failed to hash password", http.StatusInternalServerError)
		return
	}
	s.routeLifecycleMu.Lock()
	lifecycleLocked := true
	defer func() {
		if lifecycleLocked {
			s.routeLifecycleMu.Unlock()
		}
	}()

	domainRec, tunnelRec, resumed, err := s.tryResumeRegisterRoute(
		r.Context(),
		keyID,
		prepared,
		resumeTunnelID,
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !resumed {
		keyLimit, err := s.activeTunnels.limitFor(r.Context(), s.store, keyID)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		active := s.activeTunnels.activeCount(keyID)
		if keyLimit >= 0 && active >= keyLimit {
			writeJSON(w, http.StatusTooManyRequests, domain.ErrorResponse{Error: "active tunnel limit reached", ErrorCode: errCodeTunnelLimit})
			return
		}

		domainRec, tunnelRec, err = s.allocateRegisterRoute(r.Context(), keyID, prepared)
		if err != nil {
			if isHostnameInUseError(err) {
				writeJSON(w, http.StatusConflict, domain.ErrorResponse{Error: err.Error(), ErrorCode: errCodeHostnameInUse})
			} else {
				http.Error(w, err.Error(), http.StatusConflict)
			}
			return
		}
	}
	if err = s.store.SetTunnelAccessCredentials(r.Context(), tunnelRec.ID, prepared.accessUser, prepared.accessMode, prepared.passwordHash); err != nil {
		http.Error(w, "failed to persist tunnel auth settings", http.StatusInternalServerError)
		return
	}
	tunnelRec.AccessUser = prepared.accessUser
	tunnelRec.AccessMode = prepared.accessMode
	tunnelRec.AccessPasswordHash = prepared.passwordHash
	tunnelRec.WAFPathRules = nil
	if len(prepared.request.WAFIgnorePaths) > 0 {
		tunnelRec.WAFPathRules = &domain.WAFPathRules{IgnorePaths: append([]string(nil), prepared.request.WAFIgnorePaths...)}
	}
	if err = s.store.SetTunnelWAFPathRules(r.Context(), tunnelRec.ID, tunnelRec.WAFPathRules); err != nil {
		http.Error(w, "failed to persist tunnel WAF path rules", http.StatusInternalServerError)
		return
	}
	registeredRoute := domain.TunnelRoute{Domain: domainRec, Tunnel: tunnelRec}
	s.liveRoutes.setRegistrationConfig(tunnelRec.ID, prepared.accessUser, prepared.accessMode, prepared.passwordHash, tunnelRec.WAFPathRules)
	s.publishRegisteredRoute(registeredRoute)
	s.routeLifecycleMu.Unlock()
	lifecycleLocked = false

	token, err := s.store.CreateConnectToken(r.Context(), tunnelRec.ID, s.cfg.ConnectTokenTTL)
	if err != nil {
		http.Error(w, "failed to create connect token", http.StatusInternalServerError)
		return
	}

	publicURL, wsURL, h3URL := s.registerURLs(r.Host, domainRec.Hostname, token)
	capabilities := []string{"ws_v1", "h3_compat", "h3_multistream_v2", "h3_multistream", domain.CapabilityWAFIgnorePaths}

	resp := domain.RegisterResponse{
		TunnelID:      tunnelRec.ID,
		PublicURL:     publicURL,
		WSURL:         wsURL,
		H3URL:         h3URL,
		Capabilities:  capabilities,
		ServerTLSMode: s.serverTLSMode(),
		ServerVersion: s.version,
		WAFEnabled:    s.cfg.WAFEnabled,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) allowPreAuthRequest(w http.ResponseWriter, r *http.Request) bool {
	if s.authLimiter == nil || s.authLimiter.allow(clientIPFromRemoteAddr(r.RemoteAddr)) {
		return true
	}
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	return false
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
		http.NotFound(w, r)
		return
	}

	host := normalizeHost(r.Host)
	if !s.allowPublicRouteLookup(host, r) {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	snap, err := s.resolvePublicRoute(r.Context(), host)
	if err != nil {
		status, msg := publicRouteLookupErrorStatus(err)
		http.Error(w, msg, status)
		return
	}

	route := snap.route
	sess, status, msg, ok := s.resolvePublicSession(snap)
	if !ok {
		http.Error(w, msg, status)
		return
	}

	if !s.allowPublicRequest(route, r) {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	if !s.authorizePublicRequest(w, r, route) {
		return
	}

	if websocket.IsWebSocketUpgrade(r) {
		if sess.hasH3MultiStream() {
			s.handlePublicWebSocketH3MultiStream(w, r, route, sess)
			return
		}
		s.handlePublicWebSocket(w, r, route, sess)
		return
	}

	if sess.hasH3MultiStream() {
		s.proxyPublicHTTPH3MultiStream(w, r, route, sess)
		return
	}
	s.proxyPublicHTTP(w, r, route, sess)
}

func (s *Server) handlePublicWebSocket(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	if route.Tunnel.AccessPasswordHash != "" && !publicWebSocketOriginAllowed(r) {
		http.Error(w, "websocket origin not allowed", http.StatusForbidden)
		return
	}
	if !sess.tryAcquireWebSocket(maxPendingPerSessionFor(s.cfg)) {
		http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		return
	}
	defer sess.releaseWebSocket()

	streamID := s.nextWSStreamID()
	streamCh := make(chan tunnelproto.Message, 64)
	sess.wsPendingStore(streamID, streamCh)
	defer sess.wsPendingDelete(streamID)

	headers := tunnelproto.ShallowCloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	stripPublicAccessCookie(headers)
	stripPublicAccessCredentials(headers, route)
	injectForwardedProxyHeaders(headers, r)
	injectForwardedFor(headers, r.RemoteAddr)
	openMsg := tunnelproto.Message{
		Kind: tunnelproto.KindWSOpen,
		WSOpen: &tunnelproto.WSOpen{
			ID:      streamID,
			Method:  r.Method,
			Path:    r.URL.Path,
			RawPath: r.URL.RawPath,
			Query:   r.URL.RawQuery,
			Headers: headers,
		},
	}
	if err := sess.writeJSON(openMsg); err != nil {
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	timer := timerpool.Acquire(s.cfg.RequestTimeout)
	timerReleased := false
	stopTimer := func() {
		if timerReleased {
			return
		}
		timerReleased = true
		timerpool.Release(timer)
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

	checkOrigin := func(*http.Request) bool { return true }
	if route.Tunnel.AccessPasswordHash != "" {
		checkOrigin = publicWebSocketOriginAllowed
	}
	upgrader := websocket.Upgrader{CheckOrigin: checkOrigin}
	if p := strings.TrimSpace(ack.Subprotocol); p != "" {
		upgrader.Subprotocols = []string{p}
	}
	publicConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSClose, WSClose: &tunnelproto.WSClose{ID: streamID, Code: websocket.CloseGoingAway, Text: "public upgrade failed"}})
		return
	}
	publicConn.SetReadLimit(webSocketReadLimitFor(s.cfg))
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
	s.startPublicWSWriteRelay(r, publicConn, streamCh, relayStop, writeDone)

	select {
	case <-r.Context().Done():
	case <-readDone:
	case <-writeDone:
	}
}

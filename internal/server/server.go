// Package server implements the expose HTTPS reverse-proxy server with
// WebSocket-based tunnel management, ACME TLS, and session lifecycle.
package server

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

// Server is the main expose HTTPS server that manages tunnel registrations,
// WebSocket sessions, TLS certificates, and public HTTP proxying.
type Server struct {
	cfg           config.ServerConfig
	store         *sqlite.Store
	log           *slog.Logger
	hub           *hub
	wildcardTLSOn bool
	requestSeq    atomic.Uint64
	regLimiter    rateLimiter
	routes        routeCache
}

// rateLimiter implements a simple per-key token-bucket rate limiter.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	lastCheck time.Time
}

const (
	regRateLimit  = 5.0             // registrations per second per key
	regBurstLimit = 10.0            // max burst
	regCleanupAge = 5 * time.Minute // evict idle buckets
)

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: regBurstLimit, lastCheck: now}
		rl.buckets[key] = b
	}

	elapsed := now.Sub(b.lastCheck).Seconds()
	b.tokens += elapsed * regRateLimit
	if b.tokens > regBurstLimit {
		b.tokens = regBurstLimit
	}
	b.lastCheck = now

	if b.tokens < 1.0 {
		return false
	}
	b.tokens--
	return true
}

// cleanup evicts idle rate-limit buckets. Called periodically by the janitor
// so that the hot allow() path is never burdened with map iteration.
func (rl *rateLimiter) cleanup() {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, v := range rl.buckets {
		if now.Sub(v.lastCheck) > regCleanupAge {
			delete(rl.buckets, k)
		}
	}
}

type hub struct {
	mu       sync.RWMutex
	sessions map[string]*session
	wg       sync.WaitGroup
}

type session struct {
	tunnelID         string
	conn             *websocket.Conn
	writeMu          sync.Mutex
	pendingMu        sync.Mutex
	pending          map[string]chan *tunnelproto.HTTPResponse
	wsMu             sync.Mutex
	wsPending        map[string]chan tunnelproto.Message
	pendingCount     atomic.Int64
	lastSeenUnixNano atomic.Int64
	closing          atomic.Bool
}

// routeCache stores recently resolved hostname→TunnelRoute mappings with a
// short TTL. Entries are explicitly invalidated on connect/disconnect to keep
// the data fresh; the TTL is a safety-net for any missed invalidation.
type routeCache struct {
	mu      sync.RWMutex
	entries map[string]routeCacheEntry
}

type routeCacheEntry struct {
	route     domain.TunnelRoute
	expiresAt time.Time
}

const routeCacheTTL = 5 * time.Second

func (c *routeCache) get(host string) (domain.TunnelRoute, bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return domain.TunnelRoute{}, false
	}
	return e.route, true
}

func (c *routeCache) set(host string, route domain.TunnelRoute) {
	c.mu.Lock()
	c.entries[host] = routeCacheEntry{route: route, expiresAt: time.Now().Add(routeCacheTTL)}
	c.mu.Unlock()
}

func (c *routeCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for host, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, host)
		}
	}
}

// deleteByTunnelID removes any cached entry whose tunnel matches tunnelID.
func (c *routeCache) deleteByTunnelID(tunnelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for host, e := range c.entries {
		if e.route.Tunnel.ID == tunnelID {
			delete(c.entries, host)
		}
	}
}

type staticCertificate struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	certFile string
	keyFile  string
}

const (
	tlsModeAuto          = "auto"
	tlsModeDynamic       = "dynamic"
	tlsModeWildcard      = "wildcard"
	maxRegisterBodyBytes = 64 * 1024
	minWSReadLimit       = 32 * 1024 * 1024
	maxPendingPerSession = 32
	wsWriteTimeout       = 15 * time.Second
	httpsReadTimeout     = 30 * time.Second
	httpsWriteTimeout    = 60 * time.Second
	httpsIdleTimeout     = 120 * time.Second
	httpsMaxHeaderBytes  = 1 << 20
	httpIdleTimeout      = 60 * time.Second
	usedTokenRetention   = 1 * time.Hour
	tokenPurgeBatchLimit = 1000
)

type registerRequest struct {
	Mode            string `json:"mode"`
	Subdomain       string `json:"subdomain,omitempty"`
	User            string `json:"user,omitempty"`
	Password        string `json:"password,omitempty"`
	ClientHostname  string `json:"client_hostname,omitempty"`
	ClientMachineID string `json:"client_machine_id,omitempty"`
	LocalPort       string `json:"local_port,omitempty"`
}

type registerResponse struct {
	TunnelID      string `json:"tunnel_id"`
	PublicURL     string `json:"public_url"`
	WSURL         string `json:"ws_url"`
	ServerTLSMode string `json:"server_tls_mode"`
}

type errorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code,omitempty"`
}

const (
	errCodeHostnameInUse = "hostname_in_use"
	errCodeRateLimit     = "rate_limit"
	errCodeTunnelLimit   = "tunnel_limit"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// New creates a Server with the given configuration, store, and logger.
func New(cfg config.ServerConfig, store *sqlite.Store, logger *slog.Logger) *Server {
	return &Server{
		cfg:        cfg,
		store:      store,
		log:        logger,
		hub:        &hub{sessions: map[string]*session{}},
		regLimiter: rateLimiter{buckets: make(map[string]*bucket)},
		routes:     routeCache{entries: make(map[string]routeCacheEntry)},
	}
}

// Run starts the HTTPS server, ACME challenge server, and background janitor.
// It blocks until ctx is cancelled or a fatal error occurs.
func (s *Server) Run(ctx context.Context) error {
	resetCount, err := s.store.ResetConnectedTunnels(ctx)
	if err != nil {
		return fmt.Errorf("reset connected tunnels: %w", err)
	}
	if resetCount > 0 {
		s.log.Info("reconciled stale connected tunnels", "count", resetCount)
	}

	go s.runJanitor(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tunnels/register", s.handleRegister)
	mux.HandleFunc("/v1/tunnels/connect", s.handleConnect)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handlePublic)

	var manager *autocert.Manager
	useDynamicACME := s.cfg.TLSMode != tlsModeWildcard
	if useDynamicACME {
		manager = &autocert.Manager{
			Cache:  autocert.DirCache(s.cfg.CertCacheDir),
			Prompt: autocert.AcceptTOS,
			HostPolicy: func(ctx context.Context, host string) error {
				host = normalizeHost(host)
				base := normalizeHost(s.cfg.BaseDomain)
				if host == base {
					return nil
				}
				ok, err := s.store.IsHostnameActive(ctx, host)
				if err != nil {
					return errors.New("failed to authorize host")
				}
				if ok {
					return nil
				}
				return errors.New("host not allowed")
			},
		}
	}

	staticCert, err := s.loadStaticCertificate(s.cfg.TLSMode)
	if err != nil {
		return err
	}
	s.wildcardTLSOn = false
	if staticCert != nil {
		base := normalizeHost(s.cfg.BaseDomain)
		s.wildcardTLSOn = staticCert.supportsHost("probe." + base)
	}

	var tlsConfig *tls.Config
	if manager != nil {
		tlsConfig = manager.TLSConfig()
	} else {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.GetCertificate = s.selectCertificate(manager, staticCert, s.cfg.TLSMode)

	httpsServer := &http.Server{
		Addr:              s.cfg.ListenHTTPS,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       httpsReadTimeout,
		WriteTimeout:      httpsWriteTimeout,
		IdleTimeout:       httpsIdleTimeout,
		MaxHeaderBytes:    httpsMaxHeaderBytes,
		TLSConfig:         tlsConfig,
		ErrorLog:          log.New(newHTTPSErrorLogWriter(s.log, useDynamicACME), "", 0),
	}

	errChSize := 1
	if useDynamicACME {
		errChSize = 2
	}
	errCh := make(chan error, errChSize)

	var challengeServer *http.Server
	if useDynamicACME {
		challengeServer = &http.Server{
			Addr:              s.cfg.ListenHTTP,
			Handler:           manager.HTTPHandler(http.NotFoundHandler()),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       httpIdleTimeout,
			MaxHeaderBytes:    httpsMaxHeaderBytes,
		}
		go func() {
			s.log.Info("starting ACME challenge server", "addr", s.cfg.ListenHTTP)
			if err := challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("challenge server: %w", err)
			}
		}()
	} else {
		s.log.Info("TLS mode wildcard: dynamic ACME disabled", "hint", "set EXPOSE_TLS_MODE=auto to allow dynamic per-host fallback")
	}

	go func() {
		s.log.Info("starting HTTPS server", "addr", s.cfg.ListenHTTPS)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		s.closeAllSessions()
		var firstErr error
		if err := shutdownServer(httpsServer, 5*time.Second); err != nil {
			firstErr = err
		}
		if challengeServer != nil {
			if err := shutdownServer(challengeServer, 5*time.Second); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		waitGroupWait(&s.hub.wg, 15*time.Second)
		return firstErr
	case err := <-errCh:
		s.closeAllSessions()
		_ = shutdownServer(httpsServer, 5*time.Second)
		if challengeServer != nil {
			_ = shutdownServer(challengeServer, 5*time.Second)
		}
		waitGroupWait(&s.hub.wg, 15*time.Second)
		return err
	}
}

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

	var req registerRequest
	if err := decodeJSONBody(w, r, maxRegisterBodyBytes, &req); err != nil {
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		req.Mode = "temporary"
	}
	if req.Mode != "temporary" && req.Mode != "permanent" {
		http.Error(w, "invalid mode", http.StatusBadRequest)
		return
	}
	if req.Mode == "permanent" && req.Subdomain == "" {
		http.Error(w, "permanent mode requires subdomain", http.StatusBadRequest)
		return
	}
	req.User = strings.TrimSpace(req.User)
	if req.User == "" {
		req.User = "admin"
	}
	if len(req.User) > 64 {
		http.Error(w, "user must be at most 64 characters", http.StatusBadRequest)
		return
	}
	req.Password = strings.TrimSpace(req.Password)
	if len(req.Password) > 256 {
		http.Error(w, "password must be at most 256 characters", http.StatusBadRequest)
		return
	}
	accessUser := ""
	passwordHash := ""
	if req.Password != "" {
		accessUser = req.User
		hashed, hashErr := auth.HashPassword(req.Password)
		if hashErr != nil {
			http.Error(w, "failed to hash password", http.StatusInternalServerError)
			return
		}
		passwordHash = hashed
	}
	autoStableSubdomain := false
	if req.Mode == "temporary" && strings.TrimSpace(req.Subdomain) == "" && !s.wildcardTLSOn {
		if stable := stableTemporarySubdomain(req.ClientHostname, req.LocalPort); stable != "" {
			req.Subdomain = stable
			autoStableSubdomain = true
		}
	}
	clientMachineID := normalizedClientMachineID(req.ClientMachineID, req.ClientHostname)

	domainRec, tunnelRec, err := s.store.AllocateDomainAndTunnelWithClientMeta(r.Context(), keyID, req.Mode, req.Subdomain, s.cfg.BaseDomain, clientMachineID)
	if isHostnameInUseError(err) {
		if swappedDomain, swappedTunnel, swapped, swapErr := s.trySwapInactiveClientSession(r.Context(), keyID, req.Subdomain, clientMachineID); swapErr != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			s.log.Error("failed to swap inactive tunnel session", "subdomain", req.Subdomain, "err", swapErr)
			return
		} else if swapped {
			domainRec = swappedDomain
			tunnelRec = swappedTunnel
			err = nil
		}
	}
	if autoStableSubdomain && isHostnameInUseError(err) {
		domainRec, tunnelRec, err = s.store.AllocateDomainAndTunnelWithClientMeta(r.Context(), keyID, req.Mode, "", s.cfg.BaseDomain, clientMachineID)
	}
	if err != nil {
		if isHostnameInUseError(err) {
			writeJSON(w, http.StatusConflict, errorResponse{Error: err.Error(), ErrorCode: errCodeHostnameInUse})
		} else {
			http.Error(w, err.Error(), http.StatusConflict)
		}
		return
	}
	if err = s.store.SetTunnelAccessCredentials(r.Context(), tunnelRec.ID, accessUser, passwordHash); err != nil {
		http.Error(w, "failed to persist tunnel auth settings", http.StatusInternalServerError)
		return
	}
	token, err := s.store.CreateConnectToken(r.Context(), tunnelRec.ID, s.cfg.ConnectTokenTTL)
	if err != nil {
		http.Error(w, "failed to create connect token", http.StatusInternalServerError)
		return
	}

	wsAuthority := registrationWSAuthority(r.Host, normalizeHost(s.cfg.BaseDomain))
	publicURL := "https://" + domainRec.Hostname
	if port := authorityPort(wsAuthority); port != "" && port != "443" {
		publicURL = fmt.Sprintf("https://%s:%s", domainRec.Hostname, port)
	}
	wsURL := fmt.Sprintf("wss://%s/v1/tunnels/connect?token=%s", wsAuthority, token)

	resp := registerResponse{
		TunnelID:      tunnelRec.ID,
		PublicURL:     publicURL,
		WSURL:         wsURL,
		ServerTLSMode: s.serverTLSMode(),
	}
	writeJSON(w, http.StatusOK, resp)
}

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
		pending:   make(map[string]chan *tunnelproto.HTTPResponse),
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
		if err := sess.conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
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
			if v, ok := sess.pendingLoadAndDelete(msg.Response.ID); ok {
				sess.releasePending()
				select {
				case v <- msg.Response:
				default:
				}
				close(v)
			}
		case tunnelproto.KindWSOpenAck:
			if msg.WSOpenAck == nil {
				continue
			}
			if ch, ok := sess.wsPendingLoad(msg.WSOpenAck.ID); ok {
				ch <- msg
			}
		case tunnelproto.KindWSData:
			if msg.WSData == nil {
				continue
			}
			if ch, ok := sess.wsPendingLoad(msg.WSData.ID); ok {
				ch <- msg
			}
		case tunnelproto.KindWSClose:
			if msg.WSClose == nil {
				continue
			}
			if ch, ok := sess.wsPendingLoad(msg.WSClose.ID); ok {
				ch <- msg
			}
		case tunnelproto.KindPing:
			_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPong})
		}
	}
}

func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
		http.NotFound(w, r)
		return
	}

	host := normalizeHost(r.Host)
	route, ok := s.routes.get(host)
	if !ok {
		var dbErr error
		route, dbErr = s.store.FindRouteByHost(r.Context(), host)
		if dbErr != nil {
			if errors.Is(dbErr, sql.ErrNoRows) {
				http.Error(w, "unknown host", http.StatusNotFound)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.routes.set(host, route)
	}

	s.hub.mu.RLock()
	sess := s.hub.sessions[route.Tunnel.ID]
	s.hub.mu.RUnlock()
	if sess == nil || route.Tunnel.State != domain.TunnelStateConnected {
		if !route.Tunnel.IsTemporary {
			http.Error(w, "tunnel offline", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}
	if route.Tunnel.AccessPasswordHash != "" {
		expectedUser := strings.TrimSpace(route.Tunnel.AccessUser)
		if expectedUser == "" {
			expectedUser = "admin"
		}
		if !isAuthorizedBasicPassword(r, expectedUser, route.Tunnel.AccessPasswordHash) {
			writeBasicAuthChallenge(w)
			return
		}
	}
	if websocket.IsWebSocketUpgrade(r) {
		s.handlePublicWebSocket(w, r, route, sess)
		return
	}

	body, err := readLimitedBody(w, r, s.cfg.MaxBodyBytes)
	if err != nil {
		if isBodyTooLargeError(err) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	reqID := s.nextRequestID()
	if !sess.tryAcquirePending(maxPendingPerSession) {
		http.Error(w, "tunnel overloaded", http.StatusServiceUnavailable)
		return
	}
	requestHeaders := tunnelproto.CloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(requestHeaders)
	msg := tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:      reqID,
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   r.URL.RawQuery,
			Headers: requestHeaders,
			BodyB64: tunnelproto.EncodeBody(body),
		},
	}

	respCh := make(chan *tunnelproto.HTTPResponse, 1)
	sess.pendingStore(reqID, respCh)
	if err := sess.writeJSON(msg); err != nil {
		if sess.pendingDelete(reqID) {
			sess.releasePending()
		}
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	timer := time.NewTimer(s.cfg.RequestTimeout)
	defer timer.Stop()

	select {
	case resp := <-respCh:
		if resp == nil {
			http.Error(w, "tunnel closed", http.StatusBadGateway)
			return
		}
		respHeaders := tunnelproto.CloneHeaders(resp.Headers)
		netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
		for k, vals := range respHeaders {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.Status)
		b, err := tunnelproto.DecodeBody(resp.BodyB64)
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
		domainID := route.Domain.ID
		go func() { _ = s.store.TouchDomain(context.Background(), domainID) }()
	case <-timer.C:
		if sess.pendingDelete(reqID) {
			sess.releasePending()
		}
		http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
	case <-r.Context().Done():
		if sess.pendingDelete(reqID) {
			sess.releasePending()
		}
	}
}

func (s *Server) handlePublicWebSocket(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, sess *session) {
	streamID := s.nextWSStreamID()
	streamCh := make(chan tunnelproto.Message, 64)
	sess.wsPendingStore(streamID, streamCh)
	defer sess.wsPendingDelete(streamID)

	headers := tunnelproto.CloneHeaders(r.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
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
	defer timer.Stop()

	var ack *tunnelproto.WSOpenAck
	for ack == nil {
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
			return
		case msg, ok := <-streamCh:
			if !ok {
				http.Error(w, "tunnel closed", http.StatusBadGateway)
				return
			}
			if msg.Kind == tunnelproto.KindWSOpenAck && msg.WSOpenAck != nil {
				ack = msg.WSOpenAck
			}
		}
	}

	if !ack.OK {
		status := ack.Status
		if status == 0 {
			status = http.StatusBadGateway
		}
		if strings.TrimSpace(ack.Error) == "" {
			http.Error(w, "websocket upstream open failed", status)
			return
		}
		http.Error(w, ack.Error, status)
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

	domainID := route.Domain.ID
	go func() { _ = s.store.TouchDomain(context.Background(), domainID) }()

	readDone := make(chan struct{})
	writeDone := make(chan struct{})
	relayStop := make(chan struct{})
	defer close(relayStop)

	go func() {
		defer close(readDone)
		for {
			msgType, payload, err := publicConn.ReadMessage()
			if err != nil {
				code, text := websocket.CloseNormalClosure, ""
				var ce *websocket.CloseError
				if errors.As(err, &ce) {
					code, text = ce.Code, ce.Text
				}
				_ = sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSClose, WSClose: &tunnelproto.WSClose{ID: streamID, Code: code, Text: text}})
				return
			}
			if err := sess.writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSData, WSData: &tunnelproto.WSData{ID: streamID, MessageType: msgType, DataB64: tunnelproto.EncodeBody(payload)}}); err != nil {
				return
			}
		}
	}()

	go func() {
		defer close(writeDone)
		for {
			select {
			case <-relayStop:
				return
			case <-r.Context().Done():
				return
			case msg, ok := <-streamCh:
				if !ok {
					return
				}
				switch msg.Kind {
				case tunnelproto.KindWSData:
					if msg.WSData == nil {
						continue
					}
					b, err := tunnelproto.DecodeBody(msg.WSData.DataB64)
					if err != nil {
						continue
					}
					if err := publicConn.WriteMessage(msg.WSData.MessageType, b); err != nil {
						return
					}
				case tunnelproto.KindWSClose:
					if msg.WSClose == nil {
						return
					}
					_ = publicConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text), time.Now().Add(5*time.Second))
					return
				}
			}
		}
	}()

	select {
	case <-r.Context().Done():
	case <-readDone:
	case <-writeDone:
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

func (s *session) pendingStore(id string, ch chan *tunnelproto.HTTPResponse) {
	s.pendingMu.Lock()
	s.pending[id] = ch
	s.pendingMu.Unlock()
}

func (s *session) pendingLoadAndDelete(id string) (chan *tunnelproto.HTTPResponse, bool) {
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
	s.wsMu.Lock()
	ch, ok := s.wsPending[id]
	s.wsMu.Unlock()
	return ch, ok
}

func (s *session) wsPendingDelete(id string) {
	s.wsMu.Lock()
	if _, ok := s.wsPending[id]; ok {
		delete(s.wsPending, id)
	}
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

func (s *Server) closeAllSessions() {
	s.hub.mu.RLock()
	sessions := make([]*session, 0, len(s.hub.sessions))
	for _, sess := range s.hub.sessions {
		sessions = append(sessions, sess)
	}
	s.hub.mu.RUnlock()

	for _, sess := range sessions {
		_ = sess.conn.Close()
	}
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

func normalizeHost(host string) string {
	return netutil.NormalizeHost(host)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = r.Body.Close() }()

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func readLimitedBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

func isBodyTooLargeError(err error) bool {
	var tooLarge *http.MaxBytesError
	return errors.As(err, &tooLarge)
}

func (s *Server) nextRequestID() string {
	return fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), s.requestSeq.Add(1))
}

func (s *Server) nextWSStreamID() string {
	return fmt.Sprintf("ws_%d_%d", time.Now().UnixNano(), s.requestSeq.Add(1))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

func shutdownServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// waitGroupWait blocks until wg reaches zero or timeout elapses.
// Returns false if the timeout fired before all goroutines finished.
func waitGroupWait(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (s *Server) loadStaticCertificate(mode string) (*staticCertificate, error) {
	certFile := strings.TrimSpace(s.cfg.TLSCertFile)
	keyFile := strings.TrimSpace(s.cfg.TLSKeyFile)
	mode = normalizeTLSMode(mode)
	defaultCertFile := filepath.Join(s.cfg.CertCacheDir, "wildcard.crt")
	defaultKeyFile := filepath.Join(s.cfg.CertCacheDir, "wildcard.key")

	if mode == tlsModeDynamic {
		return nil, nil
	}

	if certFile == "" && keyFile == "" {
		if fileExists(defaultCertFile) && fileExists(defaultKeyFile) {
			certFile = defaultCertFile
			keyFile = defaultKeyFile
		} else {
			if mode == tlsModeWildcard {
				return nil, errors.New(s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
			}
			base := normalizeHost(s.cfg.BaseDomain)
			s.log.Info("static wildcard TLS not configured; using dynamic per-host ACME", "hint", fmt.Sprintf("to enable wildcard mode, set EXPOSE_TLS_MODE=wildcard and prepare a Let's Encrypt DNS-01 cert for %s and *.%s", base, base))
			return nil, nil
		}
	}
	if certFile == "" || keyFile == "" {
		if mode == tlsModeWildcard {
			return nil, errors.New(s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
		}
		s.log.Warn("incomplete static TLS configuration; using dynamic per-host ACME", "tls_cert_file", certFile, "tls_key_file", keyFile, "hint", "set both EXPOSE_TLS_CERT_FILE and EXPOSE_TLS_KEY_FILE")
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if mode == tlsModeWildcard {
			return nil, fmt.Errorf("wildcard TLS mode requires a valid static certificate: %w\n\n%s", err, s.wildcardSetupGuide(defaultCertFile, defaultKeyFile))
		}
		s.log.Warn("failed to load static TLS certificate; using dynamic per-host ACME", "cert_file", certFile, "key_file", keyFile, "err", err)
		return nil, nil
	}
	var leaf *x509.Certificate
	if len(cert.Certificate) > 0 {
		leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	base := normalizeHost(s.cfg.BaseDomain)
	if leaf != nil && mode == tlsModeWildcard {
		if err := leaf.VerifyHostname(base); err != nil {
			return nil, fmt.Errorf("wildcard TLS certificate must include %s: %w", base, err)
		}
		wildHost := "check." + base
		if err := leaf.VerifyHostname(wildHost); err != nil {
			return nil, fmt.Errorf("wildcard TLS certificate must include *.%s: %w", base, err)
		}
	}
	subject := ""
	if leaf != nil {
		subject = leaf.Subject.String()
	}
	s.log.Info("static TLS certificate loaded", "cert_file", certFile, "key_file", keyFile, "subject", subject)
	return &staticCertificate{
		cert:     cert,
		leaf:     leaf,
		certFile: certFile,
		keyFile:  keyFile,
	}, nil
}

func (s *Server) selectCertificate(manager *autocert.Manager, staticCert *staticCertificate, mode string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	mode = normalizeTLSMode(mode)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		host := normalizeHost(hello.ServerName)
		if staticCert != nil && staticCert.supportsHost(host) {
			return &staticCert.cert, nil
		}
		if mode == tlsModeWildcard {
			if host == "" {
				return nil, errors.New("wildcard TLS mode requires SNI host")
			}
			return nil, fmt.Errorf("wildcard TLS certificate does not cover host %q", host)
		}
		if manager == nil {
			return nil, errors.New("dynamic TLS is not available")
		}
		return manager.GetCertificate(hello)
	}
}

func (c *staticCertificate) supportsHost(host string) bool {
	if c == nil {
		return false
	}
	if host == "" {
		return true
	}
	if c.leaf == nil {
		return true
	}
	return c.leaf.VerifyHostname(host) == nil
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func normalizeTLSMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return tlsModeAuto
	}
	return mode
}

type httpsServerErrorLogWriter struct {
	log                  *slog.Logger
	dynamicACME          bool
	provisioningHintOnce sync.Once
}

func newHTTPSErrorLogWriter(logger *slog.Logger, dynamicACME bool) *httpsServerErrorLogWriter {
	return &httpsServerErrorLogWriter{log: logger, dynamicACME: dynamicACME}
}

func (w *httpsServerErrorLogWriter) Write(p []byte) (n int, err error) {
	line := strings.TrimSpace(string(p))
	if line == "" {
		return len(p), nil
	}
	if w.logTLSHandshakeLine(line) {
		return len(p), nil
	}
	w.log.Warn("https server error", "err", line)
	return len(p), nil
}

func (w *httpsServerErrorLogWriter) logTLSHandshakeLine(line string) bool {
	const marker = "TLS handshake error from "
	if !strings.Contains(line, marker) {
		return false
	}
	idx := strings.Index(line, marker)
	if idx < 0 {
		return false
	}
	payload := line[idx+len(marker):]
	addr, reason, ok := strings.Cut(payload, ": ")
	if !ok {
		w.log.Debug("tls handshake dropped", "detail", payload)
		return true
	}
	reason = strings.TrimSpace(reason)
	if isLikelyScannerTLSReason(reason) {
		w.log.Debug("tls handshake rejected", "remote_addr", strings.TrimSpace(addr), "reason", reason)
		return true
	}
	if w.dynamicACME && isLikelyTLSProvisioningReason(reason) {
		w.provisioningHintOnce.Do(func() {
			w.log.Info("TLS certificate provisioning in progress for a new host; initial handshake retries are expected")
		})
		w.log.Info("tls handshake retried during certificate provisioning", "remote_addr", strings.TrimSpace(addr), "reason", reason)
		return true
	}
	w.log.Warn("tls handshake failed", "remote_addr", strings.TrimSpace(addr), "reason", reason)
	return true
}

func isLikelyTLSProvisioningReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return strings.Contains(reason, "bad certificate") ||
		strings.Contains(reason, "failed to verify certificate") ||
		strings.Contains(reason, "certificate is not standards compliant") ||
		strings.Contains(reason, "x509:")
}

func isLikelyScannerTLSReason(reason string) bool {
	reason = strings.ToLower(strings.TrimSpace(reason))
	if reason == "" {
		return false
	}
	return reason == "eof" ||
		strings.Contains(reason, "missing server name") ||
		strings.Contains(reason, "unsupported application protocols") ||
		strings.Contains(reason, "offered only unsupported versions") ||
		strings.Contains(reason, "no cipher suite supported by both client and server")
}

func (s *Server) wildcardSetupGuide(defaultCertFile, defaultKeyFile string) string {
	base := normalizeHost(s.cfg.BaseDomain)
	return fmt.Sprintf(`wildcard TLS mode is enabled, but wildcard certificate files are not ready.

Required certificate SANs:
  - %s
  - *.%s

Place certificate files in one of these ways:
  1) Set EXPOSE_TLS_CERT_FILE and EXPOSE_TLS_KEY_FILE
  2) Or place files at:
     cert: %s
     key:  %s

Let's Encrypt wildcard requires DNS-01 challenge (TXT records in your DNS zone).

Step-by-step (Certbot + DNS provider API):
  1) Create a DNS API token for %s with permission to edit TXT records.
  2) Install Certbot and your DNS provider plugin.
  3) Request cert for both apex and wildcard:
     certbot certonly --agree-tos --email <your-email> --non-interactive \
       --dns-<provider> --dns-<provider>-credentials <credentials-file> \
       -d %s -d '*.%s'
  4) Certbot output files are usually:
       /etc/letsencrypt/live/%s/fullchain.pem
       /etc/letsencrypt/live/%s/privkey.pem
  5) Copy/link them to:
       %s
       %s
     (or set EXPOSE_TLS_CERT_FILE / EXPOSE_TLS_KEY_FILE directly)
  6) Restart server with EXPOSE_TLS_MODE=wildcard.

Tip: use EXPOSE_TLS_MODE=auto to keep service running with dynamic per-host ACME while preparing wildcard certs.`,
		base, base, defaultCertFile, defaultKeyFile, base, base, base, base, base, defaultCertFile, defaultKeyFile)
}

func (s *Server) serverTLSMode() string {
	if s.wildcardTLSOn {
		return tlsModeWildcard
	}
	return tlsModeDynamic
}

func stableTemporarySubdomain(hostname, port string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	port = strings.TrimSpace(port)
	if hostname == "" || port == "" {
		return ""
	}
	seed := hostname + ":" + port
	sum := sha1.Sum([]byte(seed))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	enc = strings.ToLower(enc)
	const subdomainLen = 6
	if len(enc) > subdomainLen {
		enc = enc[:subdomainLen]
	}
	return enc
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

func isHostnameInUseError(err error) bool {
	return errors.Is(err, sqlite.ErrHostnameInUse)
}

func normalizedClientMachineID(machineID, hostname string) string {
	if v := strings.TrimSpace(machineID); v != "" {
		return v
	}
	return strings.ToLower(strings.TrimSpace(hostname))
}

func registrationWSAuthority(hostHeader, fallbackHost string) string {
	hostHeader = strings.TrimSpace(hostHeader)
	if hostHeader == "" {
		return fallbackHost
	}
	h, port, err := net.SplitHostPort(hostHeader)
	if err == nil {
		h = normalizeHost(h)
		if h == "" {
			h = fallbackHost
		}
		if port == "" || port == "443" {
			return h
		}
		return net.JoinHostPort(h, port)
	}
	hostOnly := normalizeHost(hostHeader)
	if hostOnly != "" {
		return hostOnly
	}
	return fallbackHost
}

func authorityPort(authority string) string {
	_, port, err := net.SplitHostPort(strings.TrimSpace(authority))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
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

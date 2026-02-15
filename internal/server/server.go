package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type Server struct {
	cfg   config.ServerConfig
	store *sqlite.Store
	log   *slog.Logger
	hub   *hub
}

type hub struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	tunnelID string
	conn     *websocket.Conn
	writeMu  sync.Mutex
	pending  sync.Map
}

type registerRequest struct {
	Mode         string `json:"mode"`
	Subdomain    string `json:"subdomain,omitempty"`
	CustomDomain string `json:"custom_domain,omitempty"`
	LocalScheme  string `json:"local_scheme,omitempty"`
}

type registerResponse struct {
	TunnelID  string `json:"tunnel_id"`
	PublicURL string `json:"public_url"`
	WSURL     string `json:"ws_url"`
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func New(cfg config.ServerConfig, store *sqlite.Store, logger *slog.Logger) *Server {
	return &Server{
		cfg:   cfg,
		store: store,
		log:   logger,
		hub:   &hub{sessions: map[string]*session{}},
	}
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/tunnels/register", s.handleRegister)
	mux.HandleFunc("/v1/tunnels/connect", s.handleConnect)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", s.handlePublic)

	if s.cfg.AllowInsecureHTTP {
		server := &http.Server{
			Addr:              s.cfg.ListenHTTP,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		errCh := make(chan error, 1)
		go func() {
			s.log.Info("starting HTTP server", "addr", s.cfg.ListenHTTP)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
			close(errCh)
		}()

		select {
		case <-ctx.Done():
			return shutdownServer(server, 5*time.Second)
		case err, ok := <-errCh:
			if ok {
				return err
			}
			return nil
		}
	}

	manager := &autocert.Manager{
		Cache:  autocert.DirCache(s.cfg.CertCacheDir),
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			host = normalizeHost(host)
			base := normalizeHost(s.cfg.BaseDomain)
			if host == base || strings.HasSuffix(host, "."+base) {
				return nil
			}
			if _, err := s.store.FindRouteByHost(ctx, host); err == nil {
				return nil
			}
			return errors.New("host not allowed")
		},
	}

	challengeServer := &http.Server{
		Addr:              s.cfg.ListenHTTP,
		Handler:           manager.HTTPHandler(http.NotFoundHandler()),
		ReadHeaderTimeout: 5 * time.Second,
	}

	httpsServer := &http.Server{
		Addr:              s.cfg.ListenHTTPS,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         manager.TLSConfig(),
	}
	errCh := make(chan error, 2)
	go func() {
		s.log.Info("starting ACME challenge server", "addr", s.cfg.ListenHTTP)
		if err := challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("challenge server: %w", err)
		}
	}()
	go func() {
		s.log.Info("starting HTTPS server", "addr", s.cfg.ListenHTTPS)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("https server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		var firstErr error
		if err := shutdownServer(httpsServer, 5*time.Second); err != nil {
			firstErr = err
		}
		if err := shutdownServer(challengeServer, 5*time.Second); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	case err := <-errCh:
		_ = shutdownServer(httpsServer, 5*time.Second)
		_ = shutdownServer(challengeServer, 5*time.Second)
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

	active, err := s.store.ActiveTunnelCountByKey(r.Context(), keyID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if active >= s.cfg.MaxActivePerKey {
		http.Error(w, "active tunnel limit reached", http.StatusTooManyRequests)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
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
	if req.Mode == "permanent" && req.Subdomain == "" && req.CustomDomain == "" {
		http.Error(w, "permanent mode requires subdomain or custom_domain", http.StatusBadRequest)
		return
	}

	domainRec, tunnelRec, err := s.store.AllocateDomainAndTunnel(r.Context(), keyID, req.Mode, req.Subdomain, req.CustomDomain, s.cfg.BaseDomain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	token, err := s.store.CreateConnectToken(r.Context(), tunnelRec.ID, s.cfg.ConnectTokenTTL)
	if err != nil {
		http.Error(w, "failed to create connect token", http.StatusInternalServerError)
		return
	}

	publicURL := "https://" + domainRec.Hostname
	if s.cfg.AllowInsecureHTTP {
		publicURL = "http://" + domainRec.Hostname
	}
	base, err := url.Parse(s.cfg.PublicURL)
	if err != nil {
		http.Error(w, "server misconfigured public URL", http.StatusInternalServerError)
		return
	}
	base.Scheme = "wss"
	if s.cfg.AllowInsecureHTTP {
		base.Scheme = "ws"
	}
	base.Path = "/v1/tunnels/connect"
	q := base.Query()
	q.Set("token", token)
	base.RawQuery = q.Encode()

	resp := registerResponse{
		TunnelID:  tunnelRec.ID,
		PublicURL: publicURL,
		WSURL:     base.String(),
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

	sess := &session{
		tunnelID: tunnelID,
		conn:     conn,
	}
	s.hub.mu.Lock()
	s.hub.sessions[tunnelID] = sess
	s.hub.mu.Unlock()
	s.log.Info("tunnel connected", "tunnel_id", tunnelID)

	go s.readLoop(sess)
}

func (s *Server) readLoop(sess *session) {
	defer func() {
		_ = sess.conn.Close()
		s.hub.mu.Lock()
		delete(s.hub.sessions, sess.tunnelID)
		s.hub.mu.Unlock()
		if err := s.store.SetTunnelDisconnected(context.Background(), sess.tunnelID); err != nil {
			s.log.Error("failed to mark tunnel disconnected", "tunnel_id", sess.tunnelID, "err", err)
		}
		s.log.Info("tunnel disconnected", "tunnel_id", sess.tunnelID)
	}()

	for {
		var msg tunnelproto.Message
		if err := sess.conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Kind {
		case tunnelproto.KindResponse:
			if msg.Response == nil {
				continue
			}
			if v, ok := sess.pending.LoadAndDelete(msg.Response.ID); ok {
				ch := v.(chan *tunnelproto.HTTPResponse)
				select {
				case ch <- msg.Response:
				default:
				}
				close(ch)
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
	route, err := s.store.FindRouteByHost(r.Context(), host)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
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

	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes))
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	reqID := fmt.Sprintf("req_%d", time.Now().UnixNano())
	msg := tunnelproto.Message{
		Kind: tunnelproto.KindRequest,
		Request: &tunnelproto.HTTPRequest{
			ID:      reqID,
			Method:  r.Method,
			Path:    r.URL.Path,
			Query:   r.URL.RawQuery,
			Headers: cloneHeaders(r.Header),
			BodyB64: tunnelproto.EncodeBody(body),
		},
	}

	respCh := make(chan *tunnelproto.HTTPResponse, 1)
	sess.pending.Store(reqID, respCh)
	if err := sess.writeJSON(msg); err != nil {
		sess.pending.Delete(reqID)
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	select {
	case resp := <-respCh:
		if resp == nil {
			http.Error(w, "tunnel closed", http.StatusBadGateway)
			return
		}
		for k, vals := range resp.Headers {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.Status)
		b, err := tunnelproto.DecodeBody(resp.BodyB64)
		if err == nil && len(b) > 0 {
			_, _ = w.Write(b)
		}
		_ = s.store.TouchDomain(r.Context(), route.Domain.ID)
	case <-time.After(s.cfg.RequestTimeout):
		sess.pending.Delete(reqID)
		http.Error(w, "upstream timeout", http.StatusGatewayTimeout)
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
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.conn.WriteJSON(msg)
}

func cloneHeaders(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		c := make([]string, len(v))
		copy(c, v)
		out[k] = c
	}
	return out
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(host, ":") {
		p := strings.Split(host, ":")
		return p[0]
	}
	return strings.TrimSuffix(host, ".")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func shutdownServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

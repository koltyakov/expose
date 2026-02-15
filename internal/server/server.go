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
	"log/slog"
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
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type Server struct {
	cfg           config.ServerConfig
	store         *sqlite.Store
	log           *slog.Logger
	hub           *hub
	wildcardTLSOn bool
}

type hub struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	tunnelID         string
	conn             *websocket.Conn
	writeMu          sync.Mutex
	pending          sync.Map
	lastSeenUnixNano atomic.Int64
	closing          atomic.Bool
}

type staticCertificate struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	certFile string
	keyFile  string
}

const (
	tlsModeAuto     = "auto"
	tlsModeDynamic  = "dynamic"
	tlsModeWildcard = "wildcard"
)

type registerRequest struct {
	Mode            string `json:"mode"`
	Subdomain       string `json:"subdomain,omitempty"`
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
	tlsConfig.GetCertificate = s.selectCertificate(manager, staticCert, s.cfg.TLSMode)

	httpsServer := &http.Server{
		Addr:              s.cfg.ListenHTTPS,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConfig,
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
		var firstErr error
		if err := shutdownServer(httpsServer, 5*time.Second); err != nil {
			firstErr = err
		}
		if challengeServer != nil {
			if err := shutdownServer(challengeServer, 5*time.Second); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	case err := <-errCh:
		_ = shutdownServer(httpsServer, 5*time.Second)
		if challengeServer != nil {
			_ = shutdownServer(challengeServer, 5*time.Second)
		}
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
	if req.Mode == "permanent" && req.Subdomain == "" {
		http.Error(w, "permanent mode requires subdomain", http.StatusBadRequest)
		return
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
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	token, err := s.store.CreateConnectToken(r.Context(), tunnelRec.ID, s.cfg.ConnectTokenTTL)
	if err != nil {
		http.Error(w, "failed to create connect token", http.StatusInternalServerError)
		return
	}

	publicURL := "https://" + domainRec.Hostname
	wsURL := fmt.Sprintf("wss://%s/v1/tunnels/connect?token=%s", normalizeHost(s.cfg.BaseDomain), token)

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

	sess := &session{
		tunnelID: tunnelID,
		conn:     conn,
	}
	sess.touch(time.Now())
	s.hub.mu.Lock()
	s.hub.sessions[tunnelID] = sess
	s.hub.mu.Unlock()
	s.log.Info("tunnel connected", "tunnel_id", tunnelID)

	go s.readLoop(sess)
}

func (s *Server) readLoop(sess *session) {
	defer func() {
		_ = sess.conn.Close()
		sess.closePending()
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
		sess.touch(time.Now())

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
	s.pending.Range(func(_, v any) bool {
		ch, ok := v.(chan *tunnelproto.HTTPResponse)
		if !ok {
			return true
		}
		close(ch)
		return true
	})
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
	defer heartbeatTicker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			s.expireStaleSessions()
		case <-cleanupTicker.C:
			s.cleanupStaleTemporaryResources(ctx)
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
		hostname, closed, err := s.store.CloseTemporaryTunnel(context.Background(), sess.tunnelID)
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
		return
	}
	if len(hosts) == 0 {
		return
	}
	removedFiles := 0
	for _, host := range hosts {
		removed, err := removeTunnelCertCache(s.cfg.CertCacheDir, host)
		if err != nil {
			s.log.Error("failed to remove certificate cache during cleanup", "hostname", host, "err", err)
			continue
		}
		removedFiles += removed
	}
	s.log.Info("stale temporary domains cleaned", "domains", len(hosts), "cert_files", removedFiles)
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

func isHostnameInUseError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "hostname already in use")
}

func normalizedClientMachineID(machineID, hostname string) string {
	if v := strings.TrimSpace(machineID); v != "" {
		return v
	}
	return strings.ToLower(strings.TrimSpace(hostname))
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

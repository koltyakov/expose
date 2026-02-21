// Package server implements the expose HTTPS reverse-proxy server with
// WebSocket-based tunnel management, ACME TLS, and session lifecycle.
package server

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/waf"
	"log/slog"
)

type serverStore interface {
	ResetConnectedTunnels(ctx context.Context) (int64, error)
	ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error)
	IsHostnameActive(ctx context.Context, host string) (bool, error)
	AllocateDomainAndTunnelWithClientMeta(ctx context.Context, keyID, mode, subdomain, baseDomain, clientMeta string) (domain.Domain, domain.Tunnel, error)
	SetTunnelAccessCredentials(ctx context.Context, tunnelID, user, hash string) error
	CreateConnectToken(ctx context.Context, tunnelID string, ttl time.Duration) (string, error)
	ConsumeConnectToken(ctx context.Context, token string) (string, error)
	SetTunnelConnected(ctx context.Context, tunnelID string) error
	SetTunnelDisconnected(ctx context.Context, tunnelID string) error
	FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error)
	TouchDomain(ctx context.Context, domainID string) error
	PurgeInactiveTemporaryDomains(ctx context.Context, olderThan time.Time, limit int) ([]string, error)
	PurgeStaleConnectTokens(ctx context.Context, now, usedOlderThan time.Time, limit int) (int64, error)
	CloseTemporaryTunnel(ctx context.Context, tunnelID string) (string, bool, error)
	ResolveAPIKeyID(ctx context.Context, keyHash string) (string, error)
	SwapTunnelSession(ctx context.Context, domainID, keyID, clientMeta string) (domain.Tunnel, error)
}

var _ serverStore = (*sqlite.Store)(nil)

// Server is the main expose HTTPS server that manages tunnel registrations,
// WebSocket sessions, TLS certificates, and public HTTP proxying.
type Server struct {
	cfg           config.ServerConfig
	store         serverStore
	log           *slog.Logger
	hub           *hub
	version       string
	wildcardTLSOn bool
	requestSeq    atomic.Uint64
	regLimiter    rateLimiter
	routes        routeCache
	domainTouches chan string
	domainTouchMu sync.Mutex
	domainTouched map[string]struct{}
	wafBlocks     sync.Map // hostname → *atomic.Int64
	wafAuditQueue chan wafAuditEvent
}

type wafAuditEvent struct {
	event       waf.BlockEvent
	totalBlocks int64
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
	pendingMu        sync.RWMutex
	pending          map[string]chan tunnelproto.Message
	wsMu             sync.RWMutex
	wsPending        map[string]chan tunnelproto.Message
	pendingCount     atomic.Int64
	lastSeenUnixNano atomic.Int64
	closing          atomic.Bool
}

const (
	tlsModeAuto           = "auto"
	tlsModeDynamic        = "dynamic"
	tlsModeWildcard       = "wildcard"
	maxRegisterBodyBytes  = 64 * 1024
	minWSReadLimit        = 32 * 1024 * 1024
	maxPendingPerSession  = 32
	streamingThreshold    = 256 * 1024
	streamingChunkSize    = 256 * 1024
	streamingChanSize     = 16
	streamBodySendTimeout = 5 * time.Second
	wsWriteTimeout        = 15 * time.Second
	httpsReadTimeout      = 30 * time.Second
	httpsWriteTimeout     = 60 * time.Second
	httpsIdleTimeout      = 120 * time.Second
	httpsMaxHeaderBytes   = 1 << 20
	httpIdleTimeout       = 60 * time.Second
	usedTokenRetention    = 1 * time.Hour
	tokenPurgeBatchLimit  = 1000
	domainTouchQueueSize  = 2048
	domainTouchTimeout    = 3 * time.Second
	wafAuditQueueSize     = 2048
	wafAuditLookupTimeout = 250 * time.Millisecond
	wsDataDispatchWait    = 250 * time.Millisecond
	wsControlDispatchWait = 2 * time.Second
)

type registerRequest struct {
	Mode            string `json:"mode"`
	Subdomain       string `json:"subdomain,omitempty"`
	User            string `json:"user,omitempty"`
	Password        string `json:"password,omitempty"`
	ClientHostname  string `json:"client_hostname,omitempty"`
	ClientMachineID string `json:"client_machine_id,omitempty"`
	LocalPort       string `json:"local_port,omitempty"`
	ClientVersion   string `json:"client_version,omitempty"`
}

type registerResponse struct {
	TunnelID      string `json:"tunnel_id"`
	PublicURL     string `json:"public_url"`
	WSURL         string `json:"ws_url"`
	ServerTLSMode string `json:"server_tls_mode"`
	ServerVersion string `json:"server_version,omitempty"`
	WAFEnabled    bool   `json:"waf_enabled,omitempty"`
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
func New(cfg config.ServerConfig, store *sqlite.Store, logger *slog.Logger, version string) *Server {
	return &Server{
		cfg:           cfg,
		store:         store,
		log:           logger,
		hub:           &hub{sessions: map[string]*session{}},
		version:       version,
		regLimiter:    rateLimiter{buckets: make(map[string]*bucket)},
		routes:        routeCache{entries: make(map[string]routeCacheEntry), hostsByTunnel: make(map[string]map[string]struct{})},
		domainTouches: make(chan string, domainTouchQueueSize),
		domainTouched: make(map[string]struct{}),
		wafAuditQueue: make(chan wafAuditEvent, wafAuditQueueSize),
	}
}

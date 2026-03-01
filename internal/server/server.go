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

	"log/slog"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/waf"
)

type serverStore interface {
	ResetConnectedTunnels(ctx context.Context) (int64, error)
	ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error)
	GetAPIKeyTunnelLimit(ctx context.Context, keyID string) (int, error)
	IsHostnameActive(ctx context.Context, host string) (bool, error)
	AllocateDomainAndTunnelWithClientMeta(ctx context.Context, keyID, mode, subdomain, baseDomain, clientMeta string) (domain.Domain, domain.Tunnel, error)
	SetTunnelAccessCredentials(ctx context.Context, tunnelID, user, mode, hash string) error
	CreateConnectToken(ctx context.Context, tunnelID string, ttl time.Duration) (string, error)
	ConsumeConnectToken(ctx context.Context, token string) (string, error)
	SetTunnelConnected(ctx context.Context, tunnelID string) error
	TrySetTunnelConnected(ctx context.Context, tunnelID string) error
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
	regLimiter    *rateLimiter
	routes        routeCache
	domainTouches chan string
	domainTouchMu sync.Mutex
	domainTouched map[string]struct{}
	wafBlocks     sync.Map // hostname → *wafCounter
	wafAuditQueue chan wafAuditEvent
}

type wafAuditEvent struct {
	event       waf.BlockEvent
	totalBlocks int64
}

type wafCounter struct {
	total            atomic.Int64
	lastSeenUnixNano atomic.Int64
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
	tlsModeAuto                 = "auto"
	tlsModeDynamic              = "dynamic"
	tlsModeWildcard             = "wildcard"
	maxRegisterBodyBytes        = 64 * 1024
	minWSReadLimit              = 32 * 1024 * 1024
	defaultMaxPendingPerSession = 32
	streamingThreshold          = 256 * 1024
	streamingChunkSize          = 256 * 1024
	streamingChanSize           = 16
	streamBodySendTimeout       = 5 * time.Second
	wsWriteTimeout              = 15 * time.Second
	httpsReadTimeout            = 30 * time.Second
	httpsWriteTimeout           = 60 * time.Second
	httpsIdleTimeout            = 120 * time.Second
	httpsMaxHeaderBytes         = 1 << 20
	httpIdleTimeout             = 60 * time.Second
	usedTokenRetention          = 1 * time.Hour
	tokenPurgeBatchLimit        = 1000
	domainTouchQueueSize        = 2048
	domainTouchTimeout          = 3 * time.Second
	wafAuditQueueSize           = 2048
	wafAuditLookupTimeout       = 250 * time.Millisecond
	wsDataDispatchWait          = 250 * time.Millisecond
	wsControlDispatchWait       = 2 * time.Second
	defaultWAFCounterRetention  = time.Hour
)

// Type aliases for the shared domain request/response types.
type registerRequest = domain.RegisterRequest
type registerResponse = domain.RegisterResponse
type errorResponse = domain.ErrorResponse

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
		regLimiter:    newRateLimiter(),
		routes:        routeCache{entries: make(map[string]routeCacheEntry), hostsByTunnel: make(map[string]map[string]struct{}), ttl: durationOr(cfg.RouteCacheTTL, defaultRouteCacheTTL)},
		domainTouches: make(chan string, domainTouchQueueSize),
		domainTouched: make(map[string]struct{}),
		wafAuditQueue: make(chan wafAuditEvent, wafAuditQueueSize),
	}
}

// durationOr returns d if positive, otherwise the fallback.
func durationOr(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func maxPendingPerSessionFor(cfg config.ServerConfig) int64 {
	if cfg.MaxPendingPerTunnel > 0 {
		return int64(cfg.MaxPendingPerTunnel)
	}
	return defaultMaxPendingPerSession
}

func wafCounterRetentionFor(cfg config.ServerConfig) time.Duration {
	return durationOr(cfg.WAFCounterRetention, defaultWAFCounterRetention)
}

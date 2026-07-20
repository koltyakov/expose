// Package server implements the expose HTTPS reverse-proxy server with
// WebSocket-based tunnel management, ACME TLS, and session lifecycle.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"log/slog"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/store/sqlite"
	"github.com/koltyakov/expose/internal/tunnelproto"
	"github.com/koltyakov/expose/internal/tunneltransport"
	"github.com/koltyakov/expose/internal/waf"
)

type tunnelRegistrar interface {
	AllocateDomainAndTunnelWithClientMeta(ctx context.Context, keyID, mode, subdomain, baseDomain, clientMeta string) (domain.Domain, domain.Tunnel, error)
	SetTunnelAccessCredentials(ctx context.Context, tunnelID, user, mode, hash string) error
	CreateConnectToken(ctx context.Context, tunnelID string, ttl time.Duration) (string, error)
	ResumeTunnelSession(ctx context.Context, tunnelID, keyID, clientMeta string) (domain.Domain, domain.Tunnel, error)
	IsHostnameActive(ctx context.Context, host string) (bool, error)
}

type tunnelConnector interface {
	ConsumeConnectToken(ctx context.Context, token string) (string, error)
	TrySetTunnelConnected(ctx context.Context, tunnelID string) error
	SetTunnelDisconnected(ctx context.Context, tunnelID string) error
	SetTunnelsDisconnected(ctx context.Context, tunnelIDs []string) error
	ResetConnectedTunnels(ctx context.Context) (int64, error)
	CloseTemporaryTunnel(ctx context.Context, tunnelID string) (string, bool, error)
}

type routeResolver interface {
	FindRouteByHost(ctx context.Context, host string) (domain.TunnelRoute, error)
	FindRouteByTunnelID(ctx context.Context, tunnelID string) (domain.TunnelRoute, error)
	TouchDomain(ctx context.Context, domainID string) error
}

type tunnelLimiter interface {
	ActiveTunnelCountByKey(ctx context.Context, keyID string) (int, error)
	GetAPIKeyTunnelLimit(ctx context.Context, keyID string) (int, error)
}

type serverStore interface {
	tunnelRegistrar
	tunnelConnector
	routeResolver
	tunnelLimiter
	ResolveAPIKeyID(ctx context.Context, keyHash string) (string, error)
	PurgeInactiveTemporaryDomains(ctx context.Context, olderThan time.Time, limit int) ([]domain.Domain, error)
	PurgeStaleConnectTokens(ctx context.Context, now, usedOlderThan time.Time, limit int) (int64, error)
	OperationalStats() sqlite.OperationalStats
}

var _ serverStore = (*sqlite.Store)(nil)

// Server is the main expose HTTPS server that manages tunnel registrations,
// WebSocket sessions, TLS certificates, and public HTTP proxying.
type Server struct {
	cfg              config.ServerConfig
	store            serverStore
	log              *slog.Logger
	hub              *hub
	version          string
	wildcardTLSOn    bool
	requestSeq       atomic.Uint64
	regLimiter       *rateLimiter
	authLimiter      *rateLimiter
	lookupLimiter    *rateLimiter
	publicLimiter    *rateLimiter
	accessLimiter    *rateLimiter
	routes           routeCache
	routeLookups     lookupGroup[liveRouteSnapshot]
	routeVersions    routeVersions
	liveRoutes       *liveRouteIndex
	activeTunnels    *activeTunnelTracker
	runtimeCtx       atomic.Value // context.Context
	domainTouches    chan string
	domainTouchMu    sync.Mutex
	domainTouched    map[string]struct{}
	routeLifecycleMu sync.Mutex
	disconnects      chan string
	disconnectMu     sync.Mutex
	disconnectQ      map[string]struct{}
	disconnectWg     sync.WaitGroup
	wafBlocks        sync.Map // hostname → *wafCounter
	wafAuditQueue    chan wafAuditEvent
	h3Sessions       sync.Map // auth token -> *session
	wafAuditDrops    atomic.Int64
	domainTouchDrops atomic.Int64
	disconnectDrops  atomic.Int64
	routeCacheHits   atomic.Int64
	routeCacheMisses atomic.Int64
	routeStoreLoads  atomic.Int64
	connectionsTotal atomic.Int64
	shutdownNanos    atomic.Int64
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
	transport        tunneltransport.Transport
	writer           sessionWriter
	transportName    string
	h3StreamV2       bool
	h3StreamPool     *h3StreamPool
	h3AuthToken      string
	h3WorkerSignal   atomic.Bool
	h3WorkerDemand   atomic.Int32
	pendingMu        sync.RWMutex
	pending          map[string]*pendingRequest
	wsMu             sync.RWMutex
	wsPending        map[string]chan tunnelproto.Message
	pendingCount     atomic.Int64
	webSocketCount   atomic.Int64
	lastSeenUnixNano atomic.Int64
	closing          atomic.Bool
}

type sessionWriter interface {
	WriteJSON(tunnelproto.Message) error
	WriteBinaryFrame(byte, string, int, []byte) error
	Close()
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
	streamBodySendTimeout       = 0
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
	disconnectQueueSize         = 4096
	disconnectBatchSize         = 64
	disconnectFlushInterval     = 75 * time.Millisecond
	disconnectTimeout           = 10 * time.Second
	publicRateLimitCleanupAge   = 5 * time.Minute
	lookupRateLimit             = 20.0
	lookupBurstLimit            = 40.0
	preAuthRateLimit            = 10.0
	preAuthBurstLimit           = 30.0
	wafAuditQueueSize           = 2048
	wafAuditLookupTimeout       = 250 * time.Millisecond
	wsDataDispatchWait          = 0
	wsControlDispatchWait       = 2 * time.Second
	defaultWAFCounterRetention  = time.Hour
	wsWriteControlQueueSize     = 64
	wsWriteDataQueueSize        = 128
	// tunnelWSBufferSize sizes the tunnel websocket read buffers. Tunnel
	// frames carry up to streamingChunkSize payloads; the gorilla default of
	// 4KB fragments each chunk into dozens of small reads and syscalls.
	tunnelWSBufferSize = 64 * 1024
	// tunnelWSWriteBufferSize fits a full streaming chunk plus frame overhead
	// so each chunk flushes to the socket in a single write. The buffers are
	// shared across tunnel connections via wsWriteBufferPool rather than held
	// per connection.
	tunnelWSWriteBufferSize = 264 * 1024
)

// wsWriteBufferPool shares tunnel websocket write buffers across connections;
// gorilla acquires a buffer per message write and returns it afterwards.
var wsWriteBufferPool = &sync.Pool{}

const (
	errCodeHostnameInUse = "hostname_in_use"
	errCodeRateLimit     = "rate_limit"
	errCodeTunnelLimit   = "tunnel_limit"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  tunnelWSBufferSize,
	WriteBufferSize: tunnelWSWriteBufferSize,
	WriteBufferPool: wsWriteBufferPool,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// New creates a Server with the given configuration, store, and logger.
func New(cfg config.ServerConfig, store *sqlite.Store, logger *slog.Logger, version string) *Server {
	if strings.TrimSpace(cfg.AccessCookieSecret) == "" {
		cfg.AccessCookieSecret = newEphemeralAccessCookieSecret()
		if logger != nil {
			logger.Warn("access cookie secret not configured; using an ephemeral secret, protected-route form sessions will reset on restart", "env", "EXPOSE_ACCESS_COOKIE_SECRET")
		}
	}
	var publicLimiter *rateLimiter
	if cfg.PublicRateLimitRPS > 0 {
		publicLimiter = newConfiguredRateLimiter(
			float64(cfg.PublicRateLimitRPS),
			float64(cfg.PublicRateLimitBurst),
			publicRateLimitCleanupAge,
		)
	}
	return &Server{
		cfg:           cfg,
		store:         store,
		log:           logger,
		hub:           &hub{sessions: map[string]*session{}},
		version:       version,
		regLimiter:    newRateLimiter(),
		authLimiter:   newConfiguredRateLimiter(preAuthRateLimit, preAuthBurstLimit, regCleanupAge),
		lookupLimiter: newConfiguredRateLimiter(lookupRateLimit, lookupBurstLimit, regCleanupAge),
		publicLimiter: publicLimiter,
		accessLimiter: newConfiguredRateLimiter(accessAuthFailRate, accessAuthFailBurst, accessAuthCleanupAge),
		routes:        routeCache{entries: make(map[string]routeCacheEntry), hostsByTunnel: make(map[string]map[string]struct{}), ttl: durationOr(cfg.RouteCacheTTL, defaultRouteCacheTTL)},
		liveRoutes:    newLiveRouteIndex(),
		activeTunnels: newActiveTunnelTracker(),
		domainTouches: make(chan string, domainTouchQueueSize),
		domainTouched: make(map[string]struct{}),
		disconnects:   make(chan string, disconnectQueueSize),
		disconnectQ:   make(map[string]struct{}),
		wafAuditQueue: make(chan wafAuditEvent, wafAuditQueueSize),
	}
}

func newEphemeralAccessCookieSecret() string {
	buf := make([]byte, 32)
	// crypto/rand.Read never fails (it panics internally on a broken
	// entropy source since Go 1.24), so no predictable fallback is needed.
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
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

func webSocketReadLimitFor(cfg config.ServerConfig) int64 {
	return max(cfg.MaxBodyBytes*2, int64(minWSReadLimit))
}

func wafCounterRetentionFor(cfg config.ServerConfig) time.Duration {
	return durationOr(cfg.WAFCounterRetention, defaultWAFCounterRetention)
}

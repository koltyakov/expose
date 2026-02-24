// Package client implements the expose tunnel client that registers with the
// server, maintains a WebSocket session, and proxies traffic to a local port.
package client

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

// Type aliases for the shared domain request/response types.
type registerRequest = domain.RegisterRequest
type registerResponse = domain.RegisterResponse

// ErrAutoUpdated is returned from [Client.Run] when the binary was replaced
// by the auto-updater and the caller should restart the process.
var ErrAutoUpdated = errors.New("binary updated; restart required")

// Client connects to the expose server and proxies public traffic to a local port.
type Client struct {
	cfg        config.ClientConfig
	log        *slog.Logger
	version    string       // client version, set via SetVersion
	display    *Display     // optional interactive terminal display
	apiClient  *http.Client // for registration API calls
	fwdClient  *http.Client // for local upstream forwarding
	autoUpdate bool         // when true, periodically self-update and restart
}

// SetDisplay configures the interactive terminal display.
// When set, the client renders an ngrok-style interface instead of plain
// structured log output for tunnel status and request logging.
func (c *Client) SetDisplay(d *Display) {
	c.display = d
}

// SetLogger replaces the client's logger.
func (c *Client) SetLogger(l *slog.Logger) {
	c.log = l
}

// SetVersion sets the client version string for server exchange.
func (c *Client) SetVersion(v string) {
	c.version = v
}

// SetAutoUpdate enables background self-update. When enabled the client
// periodically checks for new releases and also reacts to server version
// changes detected during reconnection. If an update is applied the Run
// method returns [ErrAutoUpdated].
func (c *Client) SetAutoUpdate(enabled bool) {
	c.autoUpdate = enabled
}

const (
	reconnectInitialDelay      = 2 * time.Second
	reconnectMaxDelay          = 30 * time.Second
	maxConcurrentForwards      = 32
	wsMessageBufferSize        = 64
	clientWSWriteTimeout       = 15 * time.Second
	clientWSReadLimit          = 64 * 1024 * 1024
	localForwardResponseMaxB64 = 10 * 1024 * 1024
	wsHandshakeTimeout         = 10 * time.Second
	tlsProvisioningInfoRetries = 3
	streamingThreshold         = 256 * 1024
	streamingChunkSize         = 256 * 1024
	streamingReqBodyBufSize    = 64
)

// New creates a Client with the given configuration and logger.
func New(cfg config.ClientConfig, logger *slog.Logger) *Client {
	return &Client{
		cfg: cfg,
		log: logger,
		apiClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		fwdClient: &http.Client{
			Transport: newForwardHTTPTransport(),
		},
	}
}

func newForwardHTTPTransport() *http.Transport {
	base, _ := http.DefaultTransport.(*http.Transport)
	tr := base.Clone()
	tr.MaxIdleConns = 100
	tr.MaxIdleConnsPerHost = 100
	tr.MaxConnsPerHost = maxConcurrentForwards
	tr.IdleConnTimeout = 90 * time.Second
	tr.ResponseHeaderTimeout = 2 * time.Minute
	return tr
}

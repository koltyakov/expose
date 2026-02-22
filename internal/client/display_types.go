package client

import (
	"io"
	"os"
	"sync"
	"time"
)

// ANSI escape codes for terminal styling.
const (
	ansiReset     = "\033[0m"
	ansiBold      = "\033[1m"
	ansiDim       = "\033[2m"
	ansiRed       = "\033[31m"
	ansiGreen     = "\033[32m"
	ansiYellow    = "\033[33m"
	ansiCyan      = "\033[36m"
	ansiClearDown = "\033[J" // clear from cursor to end of screen
	ansiHome      = "\033[H" // move cursor to top-left
	ansiHideCur   = "\033[?25l"
	ansiShowCur   = "\033[?25h"
)

// displayFieldWidth is the column width for header field labels.
const displayFieldWidth = 18

// maxDisplayRequests is the number of HTTP request lines kept visible.
const maxDisplayRequests = 10

// activeClientWindow is the duration within which a visitor is considered
// "active" based on their last-seen timestamp. WebSocket connections also
// keep a visitor active for as long as the socket remains open.
const activeClientWindow = 60 * time.Second

// wsCloseDebounce is the delay before a WebSocket-close event triggers a
// screen redraw. During a page refresh the browser disconnects and
// reconnects quickly; the debounce prevents the counter from briefly
// dropping and causing visible flicker.
const wsCloseDebounce = 500 * time.Millisecond

const (
	displayLocalHealthCacheTTL = 2 * time.Second
	displayLocalHealthTimeout  = 200 * time.Millisecond
)

// requestEntry stores one logged HTTP request for the rolling display.
type requestEntry struct {
	ts       time.Time
	method   string
	path     string
	status   int
	duration time.Duration
}

// wsEntry stores one active WebSocket connection for the display.
type wsEntry struct {
	id          string
	path        string
	ts          time.Time
	fingerprint string // visitor fingerprint (IP|UA)
}

type localHealthEntry struct {
	ok        bool
	checkedAt time.Time
}

// Display renders an ngrok-inspired terminal interface for the tunnel client.
// It redraws the entire screen on every state change so the header, counters,
// and request log are always visible. Safe for concurrent use.
type Display struct {
	out   io.Writer
	mu    sync.Mutex
	color bool

	// banner / header state
	version       string
	status        string // "online", "reconnecting", …
	tunnelID      string
	publicURL     string
	localAddr     string
	tlsMode       string
	serverVersion string
	wafEnabled    bool   // true when WAF is enabled on the server
	updateVersion string // non-empty when an update is available

	// counters
	totalHTTP  int   // total HTTP requests forwarded
	wafBlocked int64 // WAF-blocked requests reported by the server

	// session timing
	sessionStart    time.Time // when the first successful connection happened
	lastReconnect   time.Time // when the most recent reconnection happened (zero if none)
	statusChangedAt time.Time // when the current status was set

	// latency from most recent ping/pong round-trip
	latency time.Duration

	// unique visitor tracking (IP + User-Agent fingerprint → last seen)
	visitors map[string]time.Time

	// nowFunc returns the current time; override in tests.
	nowFunc func() time.Time

	// rolling request log (most recent at the end)
	requests []requestEntry

	// active WebSocket streams
	wsConns map[string]wsEntry

	// wsDisplayMin is the debounced floor for the displayed WebSocket
	// count. During a page refresh the browser disconnects and quickly
	// reconnects; by keeping the pre-close count as a floor, the
	// displayed value never dips below it until the debounce expires.
	wsDisplayMin    int
	wsDebounceTimer *time.Timer
	wsDebounceGen   uint64

	localHealth map[string]localHealthEntry
}

// NewDisplay creates a Display that writes to stdout.
// When color is true, ANSI escape codes are used for styling.
func NewDisplay(color bool) *Display {
	return &Display{
		out:         os.Stdout,
		color:       color,
		wsConns:     make(map[string]wsEntry),
		visitors:    make(map[string]time.Time),
		requests:    make([]requestEntry, 0, maxDisplayRequests),
		nowFunc:     time.Now,
		localHealth: make(map[string]localHealthEntry),
	}
}

// Package client implements the expose tunnel client that registers with the
// server, maintains a WebSocket session, and proxies traffic to a local port.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/tunnelproto"
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
}

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
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 2 * time.Minute,
			},
		},
	}
}

func (c *Client) Run(ctx context.Context) error {
	localBase, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", c.cfg.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local URL: %w", err)
	}

	// Auto-update: periodic background check + server-version-change trigger.
	autoUpdateCh := make(chan struct{}, 1) // signals that the binary was replaced
	var lastServerVersion string
	if c.autoUpdate && !isNonReleaseVersion(c.version) {
		go c.runAutoUpdateLoop(ctx, autoUpdateCh)
	}

	backoff := reconnectInitialDelay
	tlsProvisioningRetries := 0
	for {
		reg, err := c.register(ctx)
		if err != nil {
			if isNonRetriableRegisterError(err) {
				return err
			}
			if isTLSProvisioningInProgressError(err) {
				tlsProvisioningRetries++
				if tlsProvisioningRetries <= tlsProvisioningInfoRetries {
					if c.display != nil {
						c.display.ShowInfo(fmt.Sprintf("TLS certificate provisioning in progress; retrying in %s", backoff.Round(time.Second)))
					} else {
						c.log.Info("server TLS certificate provisioning in progress; retrying", "err", err, "retry_in", backoff.Round(time.Second).String())
					}
				} else {
					if c.display != nil {
						c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), backoff.Round(time.Second)))
					} else {
						c.log.Warn("tunnel register failed while waiting for TLS certificate provisioning", "err", err, "retry_in", backoff.Round(time.Second).String())
					}
				}
			} else {
				tlsProvisioningRetries = 0
				if c.display != nil {
					c.display.ShowWarning(fmt.Sprintf("tunnel register failed, %s; retrying in %s", shortenError(err), backoff.Round(time.Second)))
				} else {
					c.log.Warn("tunnel register failed", "err", err, "retry_in", backoff.Round(time.Second).String())
				}
			}
			select {
			case <-ctx.Done():
				return nil
			case <-autoUpdateCh:
				return ErrAutoUpdated
			case <-time.After(backoff):
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = reconnectInitialDelay
		tlsProvisioningRetries = 0
		if c.display != nil {
			c.display.ShowBanner(c.version)
			localAddr := fmt.Sprintf("http://localhost:%d", c.cfg.LocalPort)
			c.display.ShowTunnelInfo(reg.PublicURL, localAddr, reg.ServerTLSMode, reg.TunnelID)
			c.display.ShowVersions(c.version, ensureVPrefix(reg.ServerVersion))
		} else {
			c.log.Info("tunnel ready", "public_url", reg.PublicURL, "tunnel_id", reg.TunnelID)
			if reg.ServerTLSMode != "" {
				c.log.Info("server tls mode", "mode", reg.ServerTLSMode)
			}
			if reg.ServerVersion != "" {
				c.log.Info("versions", "client", c.version, "server", ensureVPrefix(reg.ServerVersion))
			}
		}

		// Check for updates in the background (non-blocking).
		if !isNonReleaseVersion(c.version) {
			// If server version changed since last registration and auto-update
			// is on, immediately try to self-update.
			if c.autoUpdate && lastServerVersion != "" && reg.ServerVersion != "" &&
				reg.ServerVersion != lastServerVersion {
				c.log.Info("server version changed", "from", lastServerVersion, "to", reg.ServerVersion)
				if c.trySelfUpdate(ctx) {
					return ErrAutoUpdated
				}
			}
			lastServerVersion = reg.ServerVersion
			go c.checkForUpdates(ctx)
		}

		// Check if the background auto-update loop applied an update.
		select {
		case <-autoUpdateCh:
			return ErrAutoUpdated
		default:
		}

		err = c.runSession(ctx, localBase, reg)
		if ctx.Err() != nil {
			return nil
		}
		if c.display != nil {
			reason := "unknown"
			if err != nil {
				reason = err.Error()
			}
			c.display.ShowReconnecting(reason)
		} else {
			c.log.Warn("client disconnected; reconnecting", "err", err, "retry_in", reconnectInitialDelay.Round(time.Second).String())
		}
		select {
		case <-ctx.Done():
			return nil
		case <-autoUpdateCh:
			return ErrAutoUpdated
		case <-time.After(reconnectInitialDelay):
		}
	}
}

func (c *Client) runSession(ctx context.Context, localBase *url.URL, reg registerResponse) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: wsHandshakeTimeout,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
	}
	conn, _, err := dialer.DialContext(ctx, reg.WSURL, nil)
	if err != nil {
		return fmt.Errorf("ws connect: %w", err)
	}
	conn.SetReadLimit(clientWSReadLimit)

	sessionCtx, cancelSession := context.WithCancel(ctx)

	stopClose := make(chan struct{})
	go func() {
		select {
		case <-sessionCtx.Done():
			_ = conn.Close()
		case <-stopClose:
		}
	}()

	var requestWG sync.WaitGroup
	var wsMu sync.RWMutex
	wsConns := make(map[string]*websocket.Conn)
	streamedReqChunks := make(map[string]chan []byte)
	defer func() {
		cancelSession()
		close(stopClose)
		_ = conn.Close()
		wsMu.Lock()
		for id, streamConn := range wsConns {
			delete(wsConns, id)
			_ = streamConn.Close()
		}
		wsMu.Unlock()
		for id, ch := range streamedReqChunks {
			close(ch)
			delete(streamedReqChunks, id)
		}
		requestWG.Wait()
	}()

	var writeMu sync.Mutex
	writeJSON := func(msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout)); err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
		err := conn.WriteJSON(msg)
		if err != nil {
			_ = conn.Close()
		}
		return err
	}
	writeBinary := func(frameKind byte, id string, wsMessageType int, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := conn.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout)); err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

		w, err := conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if err := tunnelproto.WriteBinaryFrame(w, frameKind, id, wsMessageType, payload); err != nil {
			_ = w.Close()
			_ = conn.Close()
			return err
		}
		if err := w.Close(); err != nil {
			_ = conn.Close()
			return err
		}
		return nil
	}

	var pingSentMu sync.Mutex
	var pingSentAt time.Time

	// Send an immediate ping to measure latency on connect.
	pingSentAt = time.Now()
	if err := writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
		return err
	}

	keepaliveErr := make(chan error, 1)
	if c.cfg.PingInterval > 0 {
		go func() {
			ticker := time.NewTicker(c.cfg.PingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-sessionCtx.Done():
					return
				case <-ticker.C:
					pingSentMu.Lock()
					pingSentAt = time.Now()
					pingSentMu.Unlock()
					if err := writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPing}); err != nil {
						select {
						case keepaliveErr <- err:
						default:
						}
						return
					}
				}
			}
		}()
	}

	msgCh := make(chan tunnelproto.Message, wsMessageBufferSize)
	readErr := make(chan error, 1)
	go func() {
		for {
			var msg tunnelproto.Message
			if err := tunnelproto.ReadWSMessage(conn, &msg); err != nil {
				select {
				case readErr <- err:
				default:
				}
				return
			}
			select {
			case msgCh <- msg:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	requestSem := make(chan struct{}, maxConcurrentForwards)

	setWSConn := func(id string, streamConn *websocket.Conn) {
		wsMu.Lock()
		wsConns[id] = streamConn
		wsMu.Unlock()
	}
	getWSConn := func(id string) (*websocket.Conn, bool) {
		wsMu.RLock()
		streamConn, ok := wsConns[id]
		wsMu.RUnlock()
		return streamConn, ok
	}
	deleteWSConn := func(id string) {
		wsMu.Lock()
		streamConn, ok := wsConns[id]
		if ok {
			delete(wsConns, id)
		}
		wsMu.Unlock()
		if ok {
			_ = streamConn.Close()
			if c.display != nil {
				c.display.TrackWSClose(id)
			}
		}
	}
	startLocalWSReader := func(streamID string, streamConn *websocket.Conn) {
		requestWG.Add(1)
		go func() {
			defer requestWG.Done()
			defer deleteWSConn(streamID)
			for {
				msgType, payload, err := streamConn.ReadMessage()
				if err != nil {
					closeCode := websocket.CloseNormalClosure
					closeText := ""
					var closeErr *websocket.CloseError
					if errors.As(err, &closeErr) {
						closeCode = closeErr.Code
						closeText = closeErr.Text
					}
					_ = writeJSON(tunnelproto.Message{Kind: tunnelproto.KindWSClose, WSClose: &tunnelproto.WSClose{ID: streamID, Code: closeCode, Text: closeText}})
					return
				}
				if err := writeBinary(tunnelproto.BinaryFrameWSData, streamID, msgType, payload); err != nil {
					return
				}
			}
		}()
	}

	for {
		select {
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		case err := <-keepaliveErr:
			if sessionCtx.Err() != nil {
				return sessionCtx.Err()
			}
			return err
		case err := <-readErr:
			if sessionCtx.Err() != nil {
				return sessionCtx.Err()
			}
			return err
		case msg := <-msgCh:
			switch msg.Kind {
			case tunnelproto.KindRequest:
				if msg.Request == nil {
					continue
				}
				select {
				case requestSem <- struct{}{}:
				case <-sessionCtx.Done():
					return sessionCtx.Err()
				}
				requestWG.Add(1)
				reqCopy := *msg.Request
				var bodyCh chan []byte
				if reqCopy.Streamed {
					bodyCh = make(chan []byte, streamingReqBodyBufSize)
					streamedReqChunks[reqCopy.ID] = bodyCh
				}
				go func(req tunnelproto.HTTPRequest, bodyCh <-chan []byte) {
					defer requestWG.Done()
					defer func() { <-requestSem }()
					c.forwardAndSend(sessionCtx, localBase, &req, bodyCh, writeJSON, func(id string, payload []byte) error {
						return writeBinary(tunnelproto.BinaryFrameRespBody, id, 0, payload)
					})
				}(reqCopy, bodyCh)
			case tunnelproto.KindReqBody:
				if msg.BodyChunk == nil {
					continue
				}
				ch, ok := streamedReqChunks[msg.BodyChunk.ID]
				if !ok {
					continue
				}
				data, err := msg.BodyChunk.Payload()
				if err != nil {
					continue
				}
				select {
				case ch <- data:
				case <-sessionCtx.Done():
					return sessionCtx.Err()
				}
			case tunnelproto.KindReqBodyEnd:
				if msg.BodyChunk == nil {
					continue
				}
				ch, ok := streamedReqChunks[msg.BodyChunk.ID]
				if !ok {
					continue
				}
				close(ch)
				delete(streamedReqChunks, msg.BodyChunk.ID)
			case tunnelproto.KindWSOpen:
				if msg.WSOpen == nil {
					continue
				}
				streamID := strings.TrimSpace(msg.WSOpen.ID)
				if streamID == "" {
					continue
				}
				upstreamConn, status, subprotocol, err := c.openLocalWebSocket(sessionCtx, localBase, msg.WSOpen)
				if err != nil {
					_ = writeJSON(tunnelproto.Message{
						Kind: tunnelproto.KindWSOpenAck,
						WSOpenAck: &tunnelproto.WSOpenAck{
							ID:     streamID,
							OK:     false,
							Status: status,
							Error:  err.Error(),
						},
					})
					continue
				}
				setWSConn(streamID, upstreamConn)
				if c.display != nil {
					wsPath := msg.WSOpen.Path
					if msg.WSOpen.Query != "" {
						wsPath += "?" + msg.WSOpen.Query
					}
					c.display.TrackWSOpen(streamID, wsPath, msg.WSOpen.Headers)
				}
				if err := writeJSON(tunnelproto.Message{
					Kind: tunnelproto.KindWSOpenAck,
					WSOpenAck: &tunnelproto.WSOpenAck{
						ID:          streamID,
						OK:          true,
						Status:      http.StatusSwitchingProtocols,
						Subprotocol: subprotocol,
					},
				}); err != nil {
					deleteWSConn(streamID)
					continue
				}
				startLocalWSReader(streamID, upstreamConn)
			case tunnelproto.KindWSData:
				if msg.WSData == nil {
					continue
				}
				streamConn, ok := getWSConn(msg.WSData.ID)
				if !ok {
					continue
				}
				payload, err := msg.WSData.Payload()
				if err != nil {
					continue
				}
				if err := streamConn.WriteMessage(msg.WSData.MessageType, payload); err != nil {
					deleteWSConn(msg.WSData.ID)
				}
			case tunnelproto.KindWSClose:
				if msg.WSClose == nil {
					continue
				}
				streamConn, ok := getWSConn(msg.WSClose.ID)
				if !ok {
					continue
				}
				_ = streamConn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text), time.Now().Add(5*time.Second))
				deleteWSConn(msg.WSClose.ID)
			case tunnelproto.KindPong, tunnelproto.KindPing:
				if msg.Kind == tunnelproto.KindPing {
					if err := writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && sessionCtx.Err() == nil {
						return err
					}
				}
				if msg.Kind == tunnelproto.KindPong {
					pingSentMu.Lock()
					sentAt := pingSentAt
					pingSentMu.Unlock()
					if !sentAt.IsZero() {
						rtt := time.Since(sentAt)
						if c.display != nil {
							c.display.ShowLatency(rtt)
						}
					}
				}
			case tunnelproto.KindClose:
				return errors.New("server closed tunnel")
			}
		}
	}
}

func (c *Client) openLocalWebSocket(ctx context.Context, base *url.URL, req *tunnelproto.WSOpen) (*websocket.Conn, int, string, error) {
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + req.Path
	target.RawQuery = req.Query
	if strings.EqualFold(target.Scheme, "https") {
		target.Scheme = "wss"
	} else {
		target.Scheme = "ws"
	}

	headers := tunnelproto.CloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	for key := range headers {
		lowerKey := strings.ToLower(strings.TrimSpace(key))
		if lowerKey == "connection" || lowerKey == "upgrade" {
			delete(headers, key)
			continue
		}
		if lowerKey == "sec-websocket-key" ||
			lowerKey == "sec-websocket-version" ||
			lowerKey == "sec-websocket-extensions" ||
			lowerKey == "sec-websocket-accept" {
			delete(headers, key)
		}
	}

	dialer := websocket.Dialer{HandshakeTimeout: wsHandshakeTimeout}
	upstreamConn, resp, err := dialer.DialContext(ctx, target.String(), headers)
	if err != nil {
		status := http.StatusBadGateway
		if resp != nil && resp.StatusCode > 0 {
			status = resp.StatusCode
		}
		return nil, status, "", err
	}
	return upstreamConn, http.StatusSwitchingProtocols, upstreamConn.Subprotocol(), nil
}

func (c *Client) register(ctx context.Context) (registerResponse, error) {
	mode := "temporary"
	if c.cfg.Name != "" {
		mode = "permanent"
	}
	hostname, _ := os.Hostname()
	machineID := resolveClientMachineID(hostname)
	user := strings.TrimSpace(c.cfg.User)
	if user == "" {
		user = "admin"
	}
	body, _ := json.Marshal(registerRequest{
		Mode:            mode,
		Subdomain:       strings.TrimSpace(c.cfg.Name),
		User:            user,
		Password:        strings.TrimSpace(c.cfg.Password),
		ClientHostname:  strings.TrimSpace(hostname),
		ClientMachineID: machineID,
		LocalPort:       fmt.Sprintf("%d", c.cfg.LocalPort),
		ClientVersion:   c.version,
	})
	u := strings.TrimSuffix(c.cfg.ServerURL, "/") + "/v1/tunnels/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return registerResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.apiClient.Do(req)
	if err != nil {
		return registerResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		re := &registerError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(b))}
		// Try to parse structured JSON error.
		var errResp struct {
			Error     string `json:"error"`
			ErrorCode string `json:"error_code"`
		}
		if json.Unmarshal(b, &errResp) == nil && errResp.Error != "" {
			re.Message = errResp.Error
			re.Code = errResp.ErrorCode
		}
		return registerResponse{}, re
	}
	var out registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return registerResponse{}, err
	}
	out.WSURL = normalizeWSURLPort(out.WSURL, c.cfg.ServerURL)
	if out.WSURL == "" {
		return registerResponse{}, errors.New("server returned empty ws_url")
	}
	return out, nil
}

func normalizeWSURLPort(wsURL, serverURL string) string {
	wsURL = strings.TrimSpace(wsURL)
	serverURL = strings.TrimSpace(serverURL)
	if wsURL == "" || serverURL == "" {
		return wsURL
	}
	wsParsed, err := url.Parse(wsURL)
	if err != nil {
		return wsURL
	}
	if wsParsed.Host == "" {
		return wsURL
	}
	if _, hasPort := splitHostAndPort(wsParsed.Host); hasPort {
		return wsURL
	}
	serverParsed, err := url.Parse(serverURL)
	if err != nil {
		return wsURL
	}
	port := strings.TrimSpace(serverParsed.Port())
	if port == "" || port == "443" {
		return wsURL
	}
	host, _ := splitHostAndPort(wsParsed.Host)
	if host == "" {
		host = wsParsed.Host
	}
	wsParsed.Host = net.JoinHostPort(host, port)
	return wsParsed.String()
}

func splitHostAndPort(hostport string) (string, bool) {
	hostport = strings.TrimSpace(hostport)
	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return host, true
	}
	if strings.Count(hostport, ":") > 1 && strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.Trim(hostport, "[]"), false
	}
	return hostport, false
}

func resolveClientMachineID(hostname string) string {
	if v := strings.TrimSpace(os.Getenv("EXPOSE_CLIENT_MACHINE_ID")); v != "" {
		return v
	}
	for _, p := range []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	} {
		if b, err := os.ReadFile(p); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return strings.TrimSpace(hostname)
}

var (
	bufferPool = sync.Pool{
		New: func() any {
			return new(bytes.Buffer)
		},
	}
	responseFirstChunkPool = sync.Pool{
		New: func() any {
			return make([]byte, streamingThreshold+1)
		},
	}
	responseStreamChunkPool = sync.Pool{
		New: func() any {
			return make([]byte, streamingChunkSize)
		},
	}
)

func (c *Client) forwardLocal(ctx context.Context, base *url.URL, req *tunnelproto.HTTPRequest) *tunnelproto.HTTPResponse {
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + req.Path
	target.RawQuery = req.Query

	body, err := tunnelproto.DecodeBody(req.BodyB64)
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		return &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway}
	}
	headers := tunnelproto.CloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	for k, vals := range headers {
		for _, v := range vals {
			localReq.Header.Add(k, v)
		}
	}
	localReq.Header.Del("Host")
	if forwardedHost != "" {
		localReq.Host = forwardedHost
	} else {
		localReq.Host = base.Host
	}

	resp, err := c.fwdClient.Do(localReq)
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream unavailable")),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	respHeaders := tunnelproto.CloneHeaders(resp.Header)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  resp.StatusCode,
			Headers: respHeaders,
		}
	}
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)
	_, err = buf.ReadFrom(io.LimitReader(resp.Body, localForwardResponseMaxB64+1))
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("failed to read local upstream response")),
		}
	}
	if buf.Len() > localForwardResponseMaxB64 {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream response too large")),
		}
	}
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)
	return &tunnelproto.HTTPResponse{
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: respHeaders,
		BodyB64: tunnelproto.EncodeBody(buf.Bytes()),
	}
}

// forwardAndSend handles a tunnelled HTTP request, optionally with a streamed
// request body (bodyCh != nil), forwards it to the local upstream, and sends
// the response back through writeMsg. Large response bodies (exceeding
// streamingThreshold) are streamed as multiple messages instead of being
// buffered entirely in memory.
func (c *Client) forwardAndSend(
	ctx context.Context,
	base *url.URL,
	req *tunnelproto.HTTPRequest,
	bodyCh <-chan []byte,
	writeMsg func(tunnelproto.Message) error,
	writeRespBodyChunk func(id string, payload []byte) error,
) {
	started := time.Now()
	target := *base
	target.Path = strings.TrimSuffix(base.Path, "/") + req.Path
	target.RawQuery = req.Query

	// Build request body reader.
	var body io.Reader
	if bodyCh != nil {
		pr, pw := io.Pipe()
		go func() {
			defer pw.Close()
			for {
				select {
				case chunk, ok := <-bodyCh:
					if !ok {
						return
					}
					if _, err := pw.Write(chunk); err != nil {
						return
					}
				case <-ctx.Done():
					pw.CloseWithError(ctx.Err())
					return
				}
			}
		}()
		body = pr
	} else {
		data, err := tunnelproto.DecodeBody(req.BodyB64)
		if err != nil {
			_ = writeMsg(tunnelproto.Message{
				Kind:     tunnelproto.KindResponse,
				Response: &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway},
			})
			c.logForwardResult(req, http.StatusBadGateway, started)
			return
		}
		body = bytes.NewReader(data)
	}

	localReq, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
	if err != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind:     tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{ID: req.ID, Status: http.StatusBadGateway},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}

	headers := tunnelproto.CloneHeaders(req.Headers)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(headers)
	forwardedHost := strings.TrimSpace(firstHeaderValueCI(headers, "Host"))
	for k, vals := range headers {
		for _, v := range vals {
			localReq.Header.Add(k, v)
		}
	}
	localReq.Header.Del("Host")
	if forwardedHost != "" {
		localReq.Host = forwardedHost
	} else {
		localReq.Host = base.Host
	}

	resp, err := c.fwdClient.Do(localReq)
	if err != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  http.StatusBadGateway,
				Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
				BodyB64: tunnelproto.EncodeBody([]byte("local upstream unavailable")),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	respHeaders := tunnelproto.CloneHeaders(resp.Header)
	netutil.RemoveHopByHopHeadersPreserveUpgrade(respHeaders)

	if resp.StatusCode == http.StatusSwitchingProtocols {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  resp.StatusCode,
				Headers: respHeaders,
			},
		})
		return
	}

	// Try to read the first chunk to decide inline vs streamed response.
	firstBuf := responseFirstChunkPool.Get().([]byte)
	if cap(firstBuf) < streamingThreshold+1 {
		firstBuf = make([]byte, streamingThreshold+1)
	} else {
		firstBuf = firstBuf[:streamingThreshold+1]
	}
	defer responseFirstChunkPool.Put(firstBuf)
	n, readErr := io.ReadFull(resp.Body, firstBuf)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		// Small response — send inline.
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  resp.StatusCode,
				Headers: respHeaders,
				BodyB64: tunnelproto.EncodeBody(firstBuf[:n]),
			},
		})
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	if readErr != nil {
		_ = writeMsg(tunnelproto.Message{
			Kind: tunnelproto.KindResponse,
			Response: &tunnelproto.HTTPResponse{
				ID:      req.ID,
				Status:  http.StatusBadGateway,
				Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
				BodyB64: tunnelproto.EncodeBody([]byte("failed to read local upstream response")),
			},
		})
		c.logForwardResult(req, http.StatusBadGateway, started)
		return
	}

	// Large response — stream it.
	if err := writeMsg(tunnelproto.Message{
		Kind: tunnelproto.KindResponse,
		Response: &tunnelproto.HTTPResponse{
			ID:       req.ID,
			Status:   resp.StatusCode,
			Headers:  respHeaders,
			Streamed: true,
		},
	}); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	// Send the already-read data as the first body chunk.
	if writeRespBodyChunk != nil {
		if err := writeRespBodyChunk(req.ID, firstBuf[:n]); err != nil {
			c.logForwardResult(req, resp.StatusCode, started)
			return
		}
	} else if err := writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindRespBody,
		BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, DataB64: tunnelproto.EncodeBody(firstBuf[:n])},
	}); err != nil {
		c.logForwardResult(req, resp.StatusCode, started)
		return
	}

	// Read remaining body in chunks.
	chunkBuf := responseStreamChunkPool.Get().([]byte)
	if cap(chunkBuf) < streamingChunkSize {
		chunkBuf = make([]byte, streamingChunkSize)
	} else {
		chunkBuf = chunkBuf[:streamingChunkSize]
	}
	defer responseStreamChunkPool.Put(chunkBuf)
	for {
		cn, err := resp.Body.Read(chunkBuf)
		if cn > 0 {
			if writeRespBodyChunk != nil {
				if wErr := writeRespBodyChunk(req.ID, chunkBuf[:cn]); wErr != nil {
					c.logForwardResult(req, resp.StatusCode, started)
					return
				}
			} else if wErr := writeMsg(tunnelproto.Message{
				Kind:      tunnelproto.KindRespBody,
				BodyChunk: &tunnelproto.BodyChunk{ID: req.ID, DataB64: tunnelproto.EncodeBody(chunkBuf[:cn])},
			}); wErr != nil {
				c.logForwardResult(req, resp.StatusCode, started)
				return
			}
		}
		if err != nil {
			break
		}
	}

	// Signal end of response body.
	_ = writeMsg(tunnelproto.Message{
		Kind:      tunnelproto.KindRespBodyEnd,
		BodyChunk: &tunnelproto.BodyChunk{ID: req.ID},
	})
	c.logForwardResult(req, resp.StatusCode, started)
}

// logForwardResult logs the forwarded request result via display or logger.
func (c *Client) logForwardResult(req *tunnelproto.HTTPRequest, status int, started time.Time) {
	path := req.Path
	if strings.TrimSpace(req.Query) != "" {
		path = path + "?" + req.Query
	}
	elapsed := time.Since(started)
	if c.display != nil {
		c.display.LogRequest(req.Method, path, status, elapsed, req.Headers)
	} else if c.log != nil {
		c.log.Info("forwarded request", "method", req.Method, "path", path, "status", status, "duration", elapsed.String())
	}
}

// checkForUpdates queries GitHub for a newer release and displays the result.
func (c *Client) checkForUpdates(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rel, err := selfupdate.Check(checkCtx, c.version)
	if err != nil {
		c.log.Debug("update check failed", "err", err)
		return
	}
	if rel == nil {
		// Already up to date.
		if c.display != nil {
			c.display.ShowUpdateStatus("")
		}
		return
	}
	latest := ensureVPrefix(rel.TagName)
	if c.display != nil {
		c.display.ShowUpdateStatus(latest)
	} else {
		c.log.Info("update available", "latest", latest, "current", c.version, "run", "expose update")
	}
}

const clientAutoUpdateInterval = 30 * time.Minute

// runAutoUpdateLoop periodically checks for a newer release. When an update
// is downloaded and the binary replaced it sends on the channel and returns.
func (c *Client) runAutoUpdateLoop(ctx context.Context, updated chan<- struct{}) {
	c.log.Info("auto-update: periodic checks enabled", "interval", clientAutoUpdateInterval)
	ticker := time.NewTicker(clientAutoUpdateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.trySelfUpdate(ctx) {
				select {
				case updated <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

// trySelfUpdate checks for a newer release and applies it. Returns true
// when the binary was replaced and the process should restart.
func (c *Client) trySelfUpdate(ctx context.Context) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	result, err := selfupdate.CheckAndApply(checkCtx, c.version)
	if err != nil {
		c.log.Warn("auto-update: check failed", "err", err)
		return false
	}
	if !result.Updated {
		c.log.Debug("auto-update: already up to date")
		return false
	}
	c.log.Info("auto-update: binary replaced", "from", result.CurrentVersion, "to", ensureVPrefix(result.LatestVersion), "asset", result.AssetName)
	if c.display != nil {
		c.display.ShowInfo("Update applied (" + ensureVPrefix(result.LatestVersion) + "); restarting...")
	}
	return true
}

func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		current = reconnectInitialDelay
	}
	next := current * 2
	if next > reconnectMaxDelay {
		next = reconnectMaxDelay
	}
	// Add ±25% jitter to avoid thundering herd on reconnect.
	jitter := 1.0 + (rand.Float64()-0.5)*0.5 // range [0.75, 1.25]
	return time.Duration(float64(next) * jitter)
}

// registerError is a structured error from the server's registration endpoint.
type registerError struct {
	StatusCode int
	Message    string
	Code       string
}

func (e *registerError) Error() string {
	return e.Message
}

func isNonRetriableRegisterError(err error) bool {
	if err == nil {
		return false
	}
	var re *registerError
	if errors.As(err, &re) {
		if re.Code == "hostname_in_use" {
			return true
		}
		// Retry for backpressure and transient timeout statuses.
		if re.StatusCode == http.StatusTooManyRequests || re.StatusCode == http.StatusRequestTimeout {
			return false
		}
		// Other 4xx statuses are usually auth or request-shape errors and should
		// fail fast instead of reconnect-looping forever.
		return re.StatusCode >= 400 && re.StatusCode < 500
	}
	// Fallback for plain-text errors from older servers.
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "hostname already in use") {
		return true
	}
	return strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "invalid mode") ||
		strings.Contains(msg, "invalid json") ||
		strings.Contains(msg, "requires subdomain")
}

// shortenError extracts the innermost meaningful message from nested network
// errors (e.g. *url.Error → *net.OpError → syscall) so that display messages
// stay concise (e.g. "connection refused" instead of the full dial trace).
func shortenError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	return err.Error()
}

func isTLSProvisioningInProgressError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "failed to verify certificate") ||
		strings.Contains(msg, "certificate is not standards compliant") ||
		strings.Contains(msg, "x509:")
}

// ensureVPrefix returns s with a leading "v" if it doesn't already have one.
func ensureVPrefix(s string) string {
	if s != "" && !strings.HasPrefix(s, "v") {
		return "v" + s
	}
	return s
}

func isNonReleaseVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version == "" || version == "dev" || strings.HasSuffix(version, "-dev")
}

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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
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

// Client connects to the expose server and proxies public traffic to a local port.
type Client struct {
	cfg       config.ClientConfig
	log       *slog.Logger
	apiClient *http.Client // for registration API calls
	fwdClient *http.Client // for local upstream forwarding
}

const (
	reconnectInitialDelay      = 2 * time.Second
	reconnectMaxDelay          = 1 * time.Minute
	maxConcurrentForwards      = 32
	wsMessageBufferSize        = 64
	clientWSWriteTimeout       = 15 * time.Second
	clientWSReadLimit          = 32 * 1024 * 1024
	localForwardResponseMaxB64 = 10 * 1024 * 1024
	wsHandshakeTimeout         = 10 * time.Second
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
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) Run(ctx context.Context) error {
	localBase, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", c.cfg.LocalPort))
	if err != nil {
		return fmt.Errorf("invalid local URL: %w", err)
	}

	backoff := reconnectInitialDelay
	for {
		reg, err := c.register(ctx)
		if err != nil {
			if isNonRetriableRegisterError(err) {
				return err
			}
			c.log.Warn("tunnel register failed", "err", err, "retry_in", backoff.String())
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = reconnectInitialDelay
		c.log.Info("tunnel ready", "public_url", reg.PublicURL, "tunnel_id", reg.TunnelID)
		if reg.ServerTLSMode != "" {
			c.log.Info("server tls mode", "mode", reg.ServerTLSMode)
		}

		err = c.runSession(ctx, localBase, reg)
		if ctx.Err() != nil {
			return nil
		}
		c.log.Warn("client disconnected; reconnecting", "err", err, "retry_in", reconnectInitialDelay.String())
		select {
		case <-ctx.Done():
			return nil
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
	defer func() {
		cancelSession()
		close(stopClose)
		_ = conn.Close()
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
			if err := conn.ReadJSON(&msg); err != nil {
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
				go func(req tunnelproto.HTTPRequest) {
					defer requestWG.Done()
					defer func() { <-requestSem }()

					resp := c.forwardLocal(sessionCtx, localBase, &req)
					if err := writeJSON(tunnelproto.Message{
						Kind:     tunnelproto.KindResponse,
						Response: resp,
					}); err != nil && sessionCtx.Err() == nil {
						c.log.Warn("failed to send response to server", "req_id", req.ID, "err", err)
					}
				}(reqCopy)
			case tunnelproto.KindPong, tunnelproto.KindPing:
				if msg.Kind == tunnelproto.KindPing {
					if err := writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && sessionCtx.Err() == nil {
						return err
					}
				}
			case tunnelproto.KindClose:
				return errors.New("server closed tunnel")
			}
		}
	}
}

func (c *Client) register(ctx context.Context) (registerResponse, error) {
	mode := "temporary"
	if c.cfg.Name != "" {
		mode = "permanent"
	}
	hostname, _ := os.Hostname()
	machineID := resolveClientMachineID(hostname)
	body, _ := json.Marshal(registerRequest{
		Mode:            mode,
		Subdomain:       strings.TrimSpace(c.cfg.Name),
		ClientHostname:  strings.TrimSpace(hostname),
		ClientMachineID: machineID,
		LocalPort:       fmt.Sprintf("%d", c.cfg.LocalPort),
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
	if out.WSURL == "" {
		return registerResponse{}, errors.New("server returned empty ws_url")
	}
	return out, nil
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
	netutil.RemoveHopByHopHeaders(headers)
	for k, vals := range headers {
		for _, v := range vals {
			localReq.Header.Add(k, v)
		}
	}
	localReq.Header.Del("Host")
	localReq.Host = base.Host

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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, localForwardResponseMaxB64+1))
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("failed to read local upstream response")),
		}
	}
	if len(respBody) > localForwardResponseMaxB64 {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream response too large")),
		}
	}
	respHeaders := tunnelproto.CloneHeaders(resp.Header)
	netutil.RemoveHopByHopHeaders(respHeaders)
	return &tunnelproto.HTTPResponse{
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: respHeaders,
		BodyB64: tunnelproto.EncodeBody(respBody),
	}
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

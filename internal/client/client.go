package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type registerRequest struct {
	Mode           string `json:"mode"`
	Subdomain      string `json:"subdomain,omitempty"`
	ClientHostname string `json:"client_hostname,omitempty"`
	LocalPort      string `json:"local_port,omitempty"`
}

type registerResponse struct {
	TunnelID      string `json:"tunnel_id"`
	PublicURL     string `json:"public_url"`
	WSURL         string `json:"ws_url"`
	ServerTLSMode string `json:"server_tls_mode"`
}

type Client struct {
	cfg    config.ClientConfig
	log    *slog.Logger
	client *http.Client
}

const (
	reconnectInitialDelay = 2 * time.Second
	reconnectMaxDelay     = 1 * time.Minute
)

func New(cfg config.ClientConfig, logger *slog.Logger) *Client {
	return &Client{
		cfg: cfg,
		log: logger,
		client: &http.Client{
			Timeout: cfg.Timeout,
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
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, reg.WSURL, nil)
	if err != nil {
		return fmt.Errorf("ws connect: %w", err)
	}
	defer conn.Close()
	stopClose := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopClose:
		}
	}()
	defer close(stopClose)
	var writeMu sync.Mutex
	writeJSON := func(msg tunnelproto.Message) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteJSON(msg)
	}
	keepaliveErr := make(chan error, 1)
	if c.cfg.PingInterval > 0 {
		go func() {
			ticker := time.NewTicker(c.cfg.PingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-keepaliveErr:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		default:
		}

		var msg tunnelproto.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		switch msg.Kind {
		case tunnelproto.KindRequest:
			if msg.Request == nil {
				continue
			}
			resp := c.forwardLocal(ctx, localBase, msg.Request)
			if err := writeJSON(tunnelproto.Message{
				Kind:     tunnelproto.KindResponse,
				Response: resp,
			}); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return err
			}
		case tunnelproto.KindPong, tunnelproto.KindPing:
			if msg.Kind == tunnelproto.KindPing {
				if err := writeJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && ctx.Err() == nil {
					return err
				}
			}
		case tunnelproto.KindClose:
			return errors.New("server closed tunnel")
		}
	}
}

func (c *Client) register(ctx context.Context) (registerResponse, error) {
	mode := "temporary"
	if c.cfg.Permanent {
		mode = "permanent"
	}
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(registerRequest{
		Mode:           mode,
		Subdomain:      strings.TrimSpace(c.cfg.Name),
		ClientHostname: strings.TrimSpace(hostname),
		LocalPort:      fmt.Sprintf("%d", c.cfg.LocalPort),
	})
	u := strings.TrimSuffix(c.cfg.ServerURL, "/") + "/v1/tunnels/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return registerResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return registerResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return registerResponse{}, errors.New(strings.TrimSpace(string(b)))
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
	for k, vals := range req.Headers {
		for _, v := range vals {
			localReq.Header.Add(k, v)
		}
	}
	localReq.Header.Del("Host")
	localReq.Host = base.Host

	resp, err := c.client.Do(localReq)
	if err != nil {
		return &tunnelproto.HTTPResponse{
			ID:      req.ID,
			Status:  http.StatusBadGateway,
			Headers: map[string][]string{"Content-Type": {"text/plain; charset=utf-8"}},
			BodyB64: tunnelproto.EncodeBody([]byte("local upstream unavailable")),
		}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	return &tunnelproto.HTTPResponse{
		ID:      req.ID,
		Status:  resp.StatusCode,
		Headers: cloneHeaders(resp.Header),
		BodyB64: tunnelproto.EncodeBody(respBody),
	}
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

func nextBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return reconnectInitialDelay
	}
	next := current * 2
	if next > reconnectMaxDelay {
		return reconnectMaxDelay
	}
	return next
}

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
	"strings"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

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

type Client struct {
	cfg    config.ClientConfig
	log    *slog.Logger
	client *http.Client
}

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
	reg, err := c.register(ctx)
	if err != nil {
		return err
	}
	c.log.Info("tunnel ready", "public_url", reg.PublicURL, "tunnel_id", reg.TunnelID)

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

	localBase, err := url.Parse(c.cfg.LocalURL)
	if err != nil {
		return fmt.Errorf("invalid local URL: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var msg tunnelproto.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch msg.Kind {
		case tunnelproto.KindRequest:
			if msg.Request == nil {
				continue
			}
			resp := c.forwardLocal(ctx, localBase, msg.Request)
			if err := conn.WriteJSON(tunnelproto.Message{
				Kind:     tunnelproto.KindResponse,
				Response: resp,
			}); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		case tunnelproto.KindPong, tunnelproto.KindPing:
			if msg.Kind == tunnelproto.KindPing {
				if err := conn.WriteJSON(tunnelproto.Message{Kind: tunnelproto.KindPong}); err != nil && ctx.Err() == nil {
					return err
				}
			}
		case tunnelproto.KindClose:
			return nil
		}
	}
}

func (c *Client) register(ctx context.Context) (registerResponse, error) {
	mode := "temporary"
	if c.cfg.Permanent {
		mode = "permanent"
	}
	body, _ := json.Marshal(registerRequest{
		Mode:         mode,
		Subdomain:    strings.TrimSpace(c.cfg.Subdomain),
		CustomDomain: strings.TrimSpace(c.cfg.Domain),
		LocalScheme:  "http",
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

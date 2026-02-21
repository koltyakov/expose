package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

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

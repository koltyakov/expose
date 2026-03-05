package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/tunneltransport"
)

type sessionTransportConn struct {
	transport tunneltransport.Transport
	writer    *tunneltransport.WritePump
	name      string
}

type nonRetriableSessionError struct {
	err error
}

func (e nonRetriableSessionError) Error() string {
	if e.err == nil {
		return "session error"
	}
	return e.err.Error()
}

func (e nonRetriableSessionError) Unwrap() error {
	if e.err == nil {
		return nil
	}
	return e.err
}

func isNonRetriableSessionError(err error) bool {
	var target nonRetriableSessionError
	return errors.As(err, &target)
}

func (c *Client) connectSessionTransport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	switch c.cfg.Transport {
	case "ws":
		return c.connectWebSocketTransport(ctx, reg)
	case "quic":
		if strings.TrimSpace(reg.H3URL) == "" {
			return sessionTransportConn{}, nonRetriableSessionError{err: errors.New("server does not advertise HTTP/3 tunnel support")}
		}
		conn, err := c.connectHTTP3Transport(ctx, reg)
		if err != nil {
			return sessionTransportConn{}, nonRetriableSessionError{err: fmt.Errorf("http3 tunnel connect failed: %w", err)}
		}
		return conn, nil
	default:
		if strings.TrimSpace(reg.H3URL) != "" {
			conn, err := c.connectHTTP3Transport(ctx, reg)
			if err == nil {
				return conn, nil
			}
			c.reportTransportFallback(err)
		}
		return c.connectWebSocketTransport(ctx, reg)
	}
}

func (c *Client) connectWebSocketTransport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: wsHandshakeTimeout,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
	}
	conn, _, err := dialer.DialContext(ctx, reg.WSURL, nil)
	if err != nil {
		return sessionTransportConn{}, fmt.Errorf("ws connect: %w", err)
	}
	return sessionTransportConn{
		transport: tunneltransport.NewWebSocketTransport(conn),
		writer:    tunneltransport.NewWebSocketWritePump(conn, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize),
		name:      "ws",
	}, nil
}

func (c *Client) connectHTTP3Transport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	target, err := url.Parse(strings.TrimSpace(reg.H3URL))
	if err != nil {
		return sessionTransportConn{}, fmt.Errorf("invalid h3_url: %w", err)
	}
	addr := http3DialAuthority(target)
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
		ServerName: target.Hostname(),
	}
	quicConn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		return sessionTransportConn{}, err
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConf,
	}
	clientConn := h3Transport.NewClientConn(quicConn)
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if err := stream.SendRequestHeader(req); err != nil {
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := resp.Status
		if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096)); readErr == nil && strings.TrimSpace(string(body)) != "" {
			msg = strings.TrimSpace(string(body))
		}
		_ = resp.Body.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, fmt.Errorf("http3 connect rejected: %s", msg)
	}

	closeFn := func() error {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		err := stream.Close()
		_ = quicConn.CloseWithError(0, "")
		return err
	}

	return sessionTransportConn{
		transport: tunneltransport.NewStreamTransport("quic", stream, closeFn),
		writer:    tunneltransport.NewStreamWritePump(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() }),
		name:      "quic",
	}, nil
}

func (c *Client) reportTransportFallback(err error) {
	msg := fmt.Sprintf("HTTP/3 tunnel connect failed (%s); falling back to WebSocket", shortenError(err))
	if c.display != nil {
		c.display.ShowInfo(msg)
		return
	}
	if c.log != nil {
		c.log.Warn("http3 tunnel connect failed; falling back to websocket", "err", err)
	}
}

func http3DialAuthority(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return ""
	}
	port := strings.TrimSpace(u.Port())
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(host, port)
}

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

	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/tunneltransport"
)

type sessionTransportConn struct {
	transport      tunneltransport.Transport
	writer         *tunneltransport.WritePump
	name           string
	protocol       string
	h3Conn         *quic.Conn
	h3ClientConn   *http3.ClientConn
	h3Transport    *http3.Transport
	h3WorkerURL    string
	h3SessionToken string
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

const (
	tunnelCapabilityH3CompatV1      = "h3_compat"
	tunnelCapabilityH3MultistreamV2 = "h3_multistream_v2"
	tunnelCapabilityH3Multistream   = "h3_multistream"
)

func (c *Client) connectSessionTransport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	switch c.cfg.Transport {
	case "ws":
		return c.connectWebSocketTransport(ctx, reg)
	case "quic":
		var errs []error
		if canUseH3MultiStream(reg) {
			conn, err := c.connectHTTP3MultiStreamTransport(ctx, reg)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Errorf("http3 multistream tunnel connect failed: %w", err))
		}
		if canUseH3Compat(reg) {
			conn, err := c.connectHTTP3Transport(ctx, reg)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Errorf("http3 tunnel connect failed: %w", err))
		}
		if !canUseH3MultiStream(reg) && !canUseH3Compat(reg) {
			return sessionTransportConn{}, nonRetriableSessionError{err: errors.New("server does not advertise HTTP/3 tunnel support")}
		}
		return sessionTransportConn{}, nonRetriableSessionError{err: errors.Join(errs...)}
	default:
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
		protocol:  "ws_v1",
	}, nil
}

func (c *Client) connectHTTP3Transport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	target, err := url.Parse(strings.TrimSpace(reg.H3URL))
	if err != nil {
		return sessionTransportConn{}, fmt.Errorf("invalid h3_url: %w", err)
	}
	quicConn, h3Transport, clientConn, err := c.openHTTP3ClientConnection(ctx, target)
	if err != nil {
		return sessionTransportConn{}, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if err := stream.SendRequestHeader(req); err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := resp.Status
		if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096)); readErr == nil && strings.TrimSpace(string(body)) != "" {
			msg = strings.TrimSpace(string(body))
		}
		_ = resp.Body.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, fmt.Errorf("http3 connect rejected: %s", msg)
	}

	closeFn := func() error {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		err := stream.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return err
	}

	return sessionTransportConn{
		transport:    tunneltransport.NewStreamTransport("quic", stream, closeFn),
		writer:       tunneltransport.NewStreamWritePump(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() }),
		name:         "quic",
		protocol:     tunnelCapabilityH3CompatV1,
		h3Conn:       quicConn,
		h3Transport:  h3Transport,
		h3ClientConn: clientConn,
	}, nil
}

func (c *Client) connectHTTP3MultiStreamTransport(ctx context.Context, reg registerResponse) (sessionTransportConn, error) {
	target, err := url.Parse(strings.TrimSpace(reg.H3URL))
	if err != nil {
		return sessionTransportConn{}, fmt.Errorf("invalid h3_url: %w", err)
	}
	workerURL := h3WorkerURL(target)
	quicConn, h3Transport, clientConn, err := c.openHTTP3ClientConnection(ctx, target)
	if err != nil {
		return sessionTransportConn{}, err
	}
	stream, err := clientConn.OpenRequestStream(ctx)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	protocol := h3MultiStreamProtocol(reg)
	mode := "multistream"
	if protocol == tunnelCapabilityH3MultistreamV2 {
		mode = "multistream-v2"
	}
	req.Header.Set("X-Expose-H3-Mode", mode)
	if err := stream.SendRequestHeader(req); err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := resp.Status
		if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096)); readErr == nil && strings.TrimSpace(string(body)) != "" {
			msg = strings.TrimSpace(string(body))
		}
		_ = resp.Body.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, fmt.Errorf("http3 multistream connect rejected: %s", msg)
	}
	sessionToken := strings.TrimSpace(resp.Header.Get("X-Expose-H3-Session"))
	if sessionToken == "" {
		_ = resp.Body.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, errors.New("server did not return h3 session token")
	}

	closeFn := func() error {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		err := stream.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return err
	}

	transport := tunneltransport.NewStreamTransport("quic", stream, closeFn)
	writer := tunneltransport.NewStreamWritePump(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() })
	if protocol == tunnelCapabilityH3MultistreamV2 {
		transport = tunneltransport.NewStreamTransportV2("quic", stream, closeFn)
		writer = tunneltransport.NewStreamWritePumpV2(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() })
	}

	return sessionTransportConn{
		transport:      transport,
		writer:         writer,
		name:           "quic",
		protocol:       protocol,
		h3Conn:         quicConn,
		h3Transport:    h3Transport,
		h3ClientConn:   clientConn,
		h3WorkerURL:    workerURL,
		h3SessionToken: sessionToken,
	}, nil
}

func (c *Client) openHTTP3ClientConnection(ctx context.Context, target *url.URL) (*quic.Conn, *http3.Transport, *http3.ClientConn, error) {
	addr := http3DialAuthority(target)
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{http3.NextProtoH3},
		ServerName: target.Hostname(),
	}
	if c != nil && c.h3TLSConfig != nil {
		tlsConf = c.h3TLSConfig.Clone()
		if tlsConf.MinVersion == 0 {
			tlsConf.MinVersion = tls.VersionTLS13
		}
		if len(tlsConf.NextProtos) == 0 {
			tlsConf.NextProtos = []string{http3.NextProtoH3}
		}
		if strings.TrimSpace(tlsConf.ServerName) == "" {
			tlsConf.ServerName = target.Hostname()
		}
	}
	quicConn, err := quic.DialAddr(ctx, addr, tlsConf, netutil.TunnelQUICConfig(0))
	if err != nil {
		return nil, nil, nil, err
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConf,
	}
	clientConn := h3Transport.NewClientConn(quicConn)
	return quicConn, h3Transport, clientConn, nil
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

func canUseH3Compat(reg registerResponse) bool {
	if strings.TrimSpace(reg.H3URL) == "" {
		return false
	}
	if len(reg.Capabilities) == 0 {
		return true
	}
	return hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3CompatV1)
}

func canUseH3MultiStream(reg registerResponse) bool {
	if strings.TrimSpace(reg.H3URL) == "" {
		return false
	}
	if len(reg.Capabilities) == 0 {
		return false
	}
	return hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3MultistreamV2) ||
		hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3Multistream)
}

func h3MultiStreamProtocol(reg registerResponse) string {
	if hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3MultistreamV2) {
		return tunnelCapabilityH3MultistreamV2
	}
	return tunnelCapabilityH3Multistream
}

func hasTunnelCapability(caps []string, want string) bool {
	want = strings.TrimSpace(strings.ToLower(want))
	if want == "" {
		return false
	}
	for _, cap := range caps {
		if strings.TrimSpace(strings.ToLower(cap)) == want {
			return true
		}
	}
	return false
}

func h3WorkerURL(controlURL *url.URL) string {
	if controlURL == nil {
		return ""
	}
	workerURL := *controlURL
	workerURL.Path = strings.TrimSuffix(strings.TrimSpace(controlURL.Path), "/") + "/stream"
	workerURL.RawQuery = ""
	return workerURL.String()
}

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
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/koltyakov/expose/internal/domain"
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

// closeSessionTransportConn releases a connected transport that no runtime
// took ownership of.
func closeSessionTransportConn(conn sessionTransportConn) {
	if conn.transport != nil {
		_ = conn.transport.Close()
	}
	if conn.writer != nil {
		conn.writer.Close()
	}
	if conn.h3Transport != nil {
		_ = conn.h3Transport.Close()
	}
	if conn.h3Conn != nil {
		_ = conn.h3Conn.CloseWithError(0, "")
	}
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

// connectSessionTransport bounds every connect step by ctx, including the
// connect-token refresh before an HTTP/3 compat fallback. A returned
// connection is not bound to ctx.
func (c *Client) connectSessionTransport(ctx context.Context, reg domain.RegisterResponse) (sessionTransportConn, error) {
	switch c.cfg.Transport {
	case "ws":
		return c.connectWebSocketTransport(ctx, reg)
	case "quic":
		if !canUseH3MultiStream(reg) && !canUseH3Compat(reg) {
			return sessionTransportConn{}, nonRetriableSessionError{err: errors.New("server does not advertise HTTP/3 tunnel support")}
		}
		if err := validateSecureTransportURL(reg.H3URL, "https", ""); err != nil {
			return sessionTransportConn{}, nonRetriableSessionError{err: err}
		}
		var errs []error
		if canUseH3MultiStream(reg) {
			conn, err := c.connectHTTP3MultiStreamTransport(ctx, reg)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Errorf("http3 multistream tunnel connect failed: %w", err))
			if ctx.Err() != nil {
				return sessionTransportConn{}, ctx.Err()
			}
			if canUseH3Compat(reg) {
				// The server consumes connect tokens before activating a session.
				// Even a rejected attempt may have used this token already.
				fresh, err := c.registerWithResume(ctx, reg.TunnelID)
				if err != nil {
					if isNonRetriableRegisterError(err) {
						err = nonRetriableSessionError{err: err}
					}
					return sessionTransportConn{}, fmt.Errorf("refresh HTTP/3 connect token: %w", err)
				}
				if fresh.TunnelID != reg.TunnelID {
					return sessionTransportConn{}, errors.New("tunnel changed while refreshing HTTP/3 connect token; register again")
				}
				reg = fresh
			}
		}
		if canUseH3Compat(reg) {
			conn, err := c.connectHTTP3Transport(ctx, reg)
			if err == nil {
				return conn, nil
			}
			errs = append(errs, fmt.Errorf("http3 tunnel connect failed: %w", err))
		}
		// Re-registration on the next iteration determines whether credentials
		// are still valid. Network failures and spent tokens must remain retryable.
		return sessionTransportConn{}, errors.Join(errs...)
	default:
		return c.connectWebSocketTransport(ctx, reg)
	}
}

func (c *Client) connectWebSocketTransport(ctx context.Context, reg domain.RegisterResponse) (sessionTransportConn, error) {
	if err := validateSecureTransportURL(reg.WSURL, "wss", "ws"); err != nil {
		return sessionTransportConn{}, err
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: wsHandshakeTimeout,
		TLSClientConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
		ReadBufferSize:   tunnelWSBufferSize,
		WriteBufferSize:  tunnelWSWriteBufferSize,
		WriteBufferPool:  wsWriteBufferPool,
	}
	// The dialer applies ctx's deadline to the handshake but not its
	// cancellation, so a cancelled connect would otherwise wait for a stalled
	// upgrade response until HandshakeTimeout. Close the raw connection if ctx
	// ends before the handshake completes. The watch is on ctx, not the
	// dialer's handshake context, which the dialer cancels on return. Without
	// a proxy the dialer calls NetDialContext once, on this goroutine.
	stopWatch := func() bool { return true }
	var watchDone chan struct{}
	dialer.NetDialContext = func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		nc, err := (&net.Dialer{}).DialContext(dialCtx, network, addr)
		if err != nil {
			return nil, err
		}
		watchDone = make(chan struct{})
		stopWatch = context.AfterFunc(ctx, func() {
			defer close(watchDone)
			_ = nc.Close()
		})
		return nc, nil
	}
	dialURL, token := splitConnectToken(reg.WSURL, reg)
	conn, _, err := dialer.DialContext(ctx, dialURL, connectAuthHeader(token))
	if !stopWatch() {
		// ctx ended during the handshake and closed its connection.
		<-watchDone
		if conn != nil {
			_ = conn.Close()
		}
		err = ctx.Err()
	}
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

func (c *Client) connectHTTP3Transport(ctx context.Context, reg domain.RegisterResponse) (sessionTransportConn, error) {
	if err := validateSecureTransportURL(reg.H3URL, "https", ""); err != nil {
		return sessionTransportConn{}, fmt.Errorf("invalid h3_url: %w", err)
	}
	h3URL, token := splitConnectToken(reg.H3URL, reg)
	target, err := url.Parse(strings.TrimSpace(h3URL))
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	_, rejected, err := h3ControlHandshake(ctx, quicConn, stream, req)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if rejected != "" {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, fmt.Errorf("http3 connect rejected: %s", rejected)
	}

	closeFn := abortH3ControlStream(stream, h3Transport, quicConn)

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

func (c *Client) connectHTTP3MultiStreamTransport(ctx context.Context, reg domain.RegisterResponse) (sessionTransportConn, error) {
	if err := validateSecureTransportURL(reg.H3URL, "https", ""); err != nil {
		return sessionTransportConn{}, fmt.Errorf("invalid h3_url: %w", err)
	}
	h3URL, token := splitConnectToken(reg.H3URL, reg)
	target, err := url.Parse(strings.TrimSpace(h3URL))
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, rejected, err := h3ControlHandshake(ctx, quicConn, stream, req)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, err
	}
	if rejected != "" {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, fmt.Errorf("http3 multistream connect rejected: %s", rejected)
	}
	sessionToken := strings.TrimSpace(resp.Header.Get("X-Expose-H3-Session"))
	if sessionToken == "" {
		_ = resp.Body.Close()
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "")
		return sessionTransportConn{}, errors.New("server did not return h3 session token")
	}

	closeFn := abortH3ControlStream(stream, h3Transport, quicConn)

	transport := tunneltransport.NewStreamTransport("quic", stream, closeFn)
	var writer *tunneltransport.WritePump
	if protocol == tunnelCapabilityH3MultistreamV2 {
		transport = tunneltransport.NewStreamTransportV2("quic", stream, closeFn)
		writer = tunneltransport.NewStreamWritePumpV2(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() })
	} else {
		writer = tunneltransport.NewStreamWritePump(stream, clientWSWriteTimeout, wsWriteControlQueueSize, wsWriteDataQueueSize, func() { _ = closeFn() })
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

// abortH3ControlStream returns the close function for an established control
// stream. The transport, its WritePump and readiness aborts may all call it,
// possibly while the pump is inside Write. It therefore resets both stream
// directions instead of calling Close: Close sends a graceful FIN and reads
// write state that a concurrent Write mutates. The first call does the work;
// later calls wait for it and return its result.
func abortH3ControlStream(stream *http3.RequestStream, h3Transport *http3.Transport, quicConn *quic.Conn) func() error {
	var (
		once sync.Once
		err  error
	)
	return func() error {
		once.Do(func() {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			err = errors.Join(h3Transport.Close(), quicConn.CloseWithError(0, ""))
		})
		return err
	}
}

// h3ControlHandshakeTimeout bounds sending the control request and reading
// its response, as the worker streams do.
var h3ControlHandshakeTimeout = h3WorkerConnectTimeout

// h3ControlHandshake sends req on the control stream and reads the response.
// Deadlines bound a server that accepts the QUIC connection but never
// answers, and cancelling ctx closes the connection so the caller returns at
// once. A non-2xx response is drained, closed, and reported as rejected.
func h3ControlHandshake(ctx context.Context, quicConn *quic.Conn, stream *http3.RequestStream, req *http.Request) (*http.Response, string, error) {
	aborted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(aborted)
		_ = quicConn.CloseWithError(0, "connect cancelled")
	})
	defer func() {
		if !stop() {
			<-aborted
		}
	}()
	fail := func(err error) (*http.Response, string, error) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, "", ctxErr
		}
		return nil, "", err
	}
	deadline := time.Now().Add(h3ControlHandshakeTimeout)
	_ = stream.SetWriteDeadline(deadline)
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	if err := stream.SendRequestHeader(req); err != nil {
		return fail(err)
	}
	_ = stream.SetReadDeadline(deadline)
	defer func() { _ = stream.SetReadDeadline(time.Time{}) }()
	resp, err := stream.ReadResponse()
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := resp.Status
		if body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096)); readErr == nil && strings.TrimSpace(string(body)) != "" {
			msg = strings.TrimSpace(string(body))
		}
		_ = resp.Body.Close()
		return nil, msg, nil
	}
	return resp, "", nil
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

// splitConnectToken moves the connect token out of the connect URL and into a
// value the caller sends as `Authorization: Bearer`, so the token never
// appears in a request line that proxies and gateways routinely log. Servers
// that do not advertise CapabilityConnectTokenHeader only read the query
// parameter, so for them the URL is returned untouched.
func splitConnectToken(rawURL string, reg domain.RegisterResponse) (string, string) {
	if !hasTunnelCapability(reg.Capabilities, domain.CapabilityConnectTokenHeader) {
		return rawURL, ""
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return rawURL, ""
	}
	query := u.Query()
	token := strings.TrimSpace(query.Get("token"))
	if token == "" {
		return rawURL, ""
	}
	query.Del("token")
	u.RawQuery = query.Encode()
	return u.String(), token
}

// connectAuthHeader builds the bearer header for a connect token, or nil when
// the token stays in the URL.
func connectAuthHeader(token string) http.Header {
	if token == "" {
		return nil
	}
	return http.Header{"Authorization": []string{"Bearer " + token}}
}

// validateSecureTransportURL rejects plaintext tunnel transport URLs before
// dialing. ws_url must use wss:// and h3_url must use https://. Plaintext
// schemes to loopback hosts are tolerated for local development.
func validateSecureTransportURL(rawURL, wantScheme, plaintextScheme string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("invalid tunnel transport URL: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == wantScheme {
		return nil
	}
	if plaintextScheme != "" && scheme == plaintextScheme && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("insecure tunnel transport URL %q: scheme must be %s://", rawURL, wantScheme)
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func canUseH3Compat(reg domain.RegisterResponse) bool {
	if strings.TrimSpace(reg.H3URL) == "" {
		return false
	}
	if len(reg.Capabilities) == 0 {
		return true
	}
	return hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3CompatV1)
}

func canUseH3MultiStream(reg domain.RegisterResponse) bool {
	if strings.TrimSpace(reg.H3URL) == "" {
		return false
	}
	if len(reg.Capabilities) == 0 {
		return false
	}
	return hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3MultistreamV2) ||
		hasTunnelCapability(reg.Capabilities, tunnelCapabilityH3Multistream)
}

func h3MultiStreamProtocol(reg domain.RegisterResponse) string {
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

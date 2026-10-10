// Package turnrelay runs the optional public TURN service for WebRTC clients.
package turnrelay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/pion/turn/v5"

	"github.com/koltyakov/expose/internal/config"
)

// Relay owns TURN listeners, accepted connections and allocation sockets.
type Relay struct {
	cfg       config.TURNConfig
	server    *turn.Server
	sockets   []io.Closer
	peers     *connectionPool
	allocator *relayGenerator
	closeOnce sync.Once
	closeErr  error
}

// Start binds all listeners before returning. Failure closes every acquired resource.
// TLS reuses the HTTPS certificate provider but runs on a separate TCP listener.
func Start(cfg config.TURNConfig, tlsConfig *tls.Config, logger *slog.Logger) (*Relay, error) {
	return start(cfg, tlsConfig, logger, publicPeerPermission)
}

func start(cfg config.TURNConfig, tlsConfig *tls.Config, logger *slog.Logger, permission turn.PermissionHandler) (_ *Relay, err error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.ListenTLS != "" && tlsConfig == nil {
		return nil, errors.New("TURN TLS listener requires a TLS certificate provider")
	}
	r := &Relay{
		cfg:       cfg,
		peers:     newConnectionPool(cfg.MaxConnections),
		allocator: newRelayGenerator(cfg),
	}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	serverConfig := turn.ServerConfig{
		Realm:         cfg.Realm,
		AuthHandler:   authHandler(cfg),
		LoggerFactory: logFactory{logger: logger},
		EventHandler: turn.EventHandler{
			OnAuth: func(src, dst net.Addr, _, _, _, _ string, verdict bool) {
				if verdict {
					r.peers.authenticated(src, dst)
				}
			},
		},
	}
	if cfg.ListenUDP != "" {
		conn, listenErr := net.ListenPacket("udp4", cfg.ListenUDP)
		if listenErr != nil {
			return nil, fmt.Errorf("listen TURN UDP: %w", listenErr)
		}
		r.sockets = append(r.sockets, conn)
		r.cfg.ListenUDP = conn.LocalAddr().String()
		serverConfig.PacketConnConfigs = append(serverConfig.PacketConnConfigs, turn.PacketConnConfig{
			PacketConn: conn, RelayAddressGenerator: r.allocator, PermissionHandler: permission,
		})
	}
	for _, listener := range []struct {
		addr string
		tls  bool
	}{{cfg.ListenTCP, false}, {cfg.ListenTLS, true}} {
		if listener.addr == "" {
			continue
		}
		conn, listenErr := net.Listen("tcp4", listener.addr)
		if listenErr != nil {
			return nil, fmt.Errorf("listen TURN TCP/TLS: %w", listenErr)
		}
		if listener.tls {
			turnTLS := tlsConfig.Clone()
			turnTLS.MinVersion = tls.VersionTLS12
			// TURN is not HTTP and must not negotiate h2 or ACME's challenge protocol.
			turnTLS.NextProtos = nil
			conn = tls.NewListener(conn, turnTLS)
			r.cfg.ListenTLS = conn.Addr().String()
		} else {
			r.cfg.ListenTCP = conn.Addr().String()
		}
		conn = &limitedListener{Listener: conn, pool: r.peers}
		r.sockets = append(r.sockets, conn)
		serverConfig.ListenerConfigs = append(serverConfig.ListenerConfigs, turn.ListenerConfig{
			Listener: conn, RelayAddressGenerator: r.allocator, PermissionHandler: permission,
		})
	}
	r.server, err = turn.NewServer(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("start TURN: %w", err)
	}
	if logger != nil {
		logger.Info("TURN relay listening", "urls", r.URLs(), "public_ip", cfg.PublicIP,
			"relay_ports", fmt.Sprintf("%d-%d", cfg.MinPort, cfg.MaxPort))
	}
	return r, nil
}

// URLs lists the public ICE URLs, preserving the listeners' configured ports.
// NAT deployments must forward these ports without renumbering them.
func (r *Relay) URLs() []string {
	urls := make([]string, 0, 3)
	for _, listener := range []struct {
		addr, scheme, transport string
	}{{r.cfg.ListenUDP, "turn", "udp"}, {r.cfg.ListenTCP, "turn", "tcp"}, {r.cfg.ListenTLS, "turns", "tcp"}} {
		if listener.addr == "" {
			continue
		}
		_, port, _ := net.SplitHostPort(listener.addr)
		urls = append(urls, listener.scheme+":"+net.JoinHostPort(r.cfg.Host, port)+"?transport="+listener.transport)
	}
	return urls
}

// Close also terminates idle, unauthenticated TCP/TLS clients. Pion only closes
// listening sockets itself, so these accepted connections are tracked separately.
func (r *Relay) Close() error {
	r.closeOnce.Do(func() {
		if r.server != nil {
			r.closeErr = r.server.Close()
		} else {
			for _, socket := range r.sockets {
				r.closeErr = errors.Join(r.closeErr, socket.Close())
			}
		}
		r.peers.close()
		r.allocator.close()
	})
	return r.closeErr
}

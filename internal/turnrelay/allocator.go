package turnrelay

import (
	"errors"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"

	"github.com/pion/turn/v5"

	"github.com/koltyakov/expose/internal/config"
)

// A single generator enforces the allocation limit across every listener.
// Requested ports, including EVEN-PORT reservations, cannot escape the range.
type relayGenerator struct {
	cfg    config.TURNConfig
	mu     sync.Mutex
	conns  map[*relayPacketConn]struct{}
	closed bool
}

var _ turn.RelayAddressGenerator = (*relayGenerator)(nil)

func newRelayGenerator(cfg config.TURNConfig) *relayGenerator {
	return &relayGenerator{cfg: cfg, conns: make(map[*relayPacketConn]struct{})}
}

func (g *relayGenerator) Validate() error { return g.cfg.Validate() }

func (g *relayGenerator) AllocatePacketConn(info turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	network, requestedPort := info.Network, info.RequestedPort
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, nil, net.ErrClosed
	}
	if network != "udp4" {
		return nil, nil, errors.New("TURN only supports IPv4 UDP relay allocations")
	}
	if len(g.conns) >= g.cfg.MaxAllocations {
		return nil, nil, errors.New("TURN allocation limit reached")
	}
	if requestedPort != 0 && (requestedPort < g.cfg.MinPort || requestedPort > g.cfg.MaxPort) {
		return nil, nil, errors.New("requested TURN port is outside the relay range")
	}
	count := g.cfg.MaxPort - g.cfg.MinPort + 1
	start := rand.IntN(count)
	for i := 0; i < count; i++ {
		port := g.cfg.MinPort + (start+i)%count
		if requestedPort != 0 {
			port = requestedPort
		}
		conn, err := net.ListenPacket("udp4", net.JoinHostPort(g.cfg.RelayAddress, strconv.Itoa(port)))
		if err == nil {
			tracked := &relayPacketConn{PacketConn: conn, owner: g}
			g.conns[tracked] = struct{}{}
			return tracked, &net.UDPAddr{IP: net.ParseIP(g.cfg.PublicIP), Port: port}, nil
		}
		if requestedPort != 0 {
			return nil, nil, err
		}
	}
	return nil, nil, errors.New("TURN relay port range exhausted")
}

func (g *relayGenerator) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, errors.New("TCP relay allocations are not supported; use UDP allocations over TURN TCP/TLS")
}

func (g *relayGenerator) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, errors.New("TCP relay connections are not supported; use UDP allocations over TURN TCP/TLS")
}

func (g *relayGenerator) close() {
	g.mu.Lock()
	g.closed = true
	conns := make([]*relayPacketConn, 0, len(g.conns))
	for conn := range g.conns {
		conns = append(conns, conn)
	}
	g.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type relayPacketConn struct {
	net.PacketConn
	owner *relayGenerator
	once  sync.Once
	err   error
}

func (c *relayPacketConn) Close() error {
	c.once.Do(func() {
		c.err = c.PacketConn.Close()
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.err
}

package turnrelay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type connectionPool struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	// byAddr indexes conns by "remote|local" so each successful TURN auth
	// finds its connection without formatting every tracked address.
	byAddr map[string][]*trackedConn
	max    int
	closed bool
}

func newConnectionPool(max int) *connectionPool {
	return &connectionPool{max: max, conns: make(map[*trackedConn]struct{}), byAddr: make(map[string][]*trackedConn)}
}

func connAddrKey(remote, local net.Addr) string {
	if remote == nil || local == nil {
		return ""
	}
	return remote.String() + "|" + local.String()
}

func (p *connectionPool) add(conn net.Conn) (*trackedConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.conns) >= p.max {
		return nil, false
	}
	c := &trackedConn{Conn: conn, pool: p, authDeadline: time.Now().Add(10 * time.Second)}
	c.addrKey = connAddrKey(conn.RemoteAddr(), conn.LocalAddr())
	p.conns[c] = struct{}{}
	p.byAddr[c.addrKey] = append(p.byAddr[c.addrKey], c)
	return c, true
}

func (p *connectionPool) remove(c *trackedConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
	peers := p.byAddr[c.addrKey]
	for i, peer := range peers {
		if peer == c {
			peers = append(peers[:i], peers[i+1:]...)
			break
		}
	}
	if len(peers) == 0 {
		delete(p.byAddr, c.addrKey)
	} else {
		p.byAddr[c.addrKey] = peers
	}
}

// authenticated marks the stream connection behind a successful TURN auth.
// UDP allocations have no tracked connection.
func (p *connectionPool) authenticated(src, dst net.Addr) {
	if _, udp := src.(*net.UDPAddr); udp {
		return
	}
	key := connAddrKey(src, dst)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.byAddr[key] {
		conn.ready.Store(true)
	}
}

func (p *connectionPool) close() {
	p.mu.Lock()
	p.closed = true
	conns := make([]*trackedConn, 0, len(p.conns))
	for conn := range p.conns {
		conns = append(conns, conn)
	}
	p.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type limitedListener struct {
	net.Listener
	pool *connectionPool
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if tracked, ok := l.pool.add(conn); ok {
			return tracked, nil
		}
		_ = conn.Close()
	}
}

type trackedConn struct {
	net.Conn
	pool         *connectionPool
	addrKey      string
	authDeadline time.Time
	ready        atomic.Bool
	once         sync.Once
	err          error
}

func (c *trackedConn) Read(buf []byte) (int, error) {
	deadline := c.authDeadline
	if c.ready.Load() {
		deadline = time.Now().Add(10 * time.Minute)
	}
	if err := c.SetReadDeadline(deadline); err != nil {
		return 0, err
	}
	return c.Conn.Read(buf)
}

func (c *trackedConn) Write(buf []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(buf)
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.pool.remove(c)
	})
	return c.err
}

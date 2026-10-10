package turnrelay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type connectionPool struct {
	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	max    int
	closed bool
}

func newConnectionPool(max int) *connectionPool {
	return &connectionPool{max: max, conns: make(map[*trackedConn]struct{})}
}

func (p *connectionPool) add(conn net.Conn) (*trackedConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.conns) >= p.max {
		return nil, false
	}
	c := &trackedConn{Conn: conn, pool: p, authDeadline: time.Now().Add(10 * time.Second)}
	p.conns[c] = struct{}{}
	return c, true
}

func (p *connectionPool) authenticated(src, dst net.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.conns {
		if conn.RemoteAddr().String() == src.String() && conn.LocalAddr().String() == dst.String() {
			conn.ready.Store(true)
		}
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
		c.pool.mu.Lock()
		delete(c.pool.conns, c)
		c.pool.mu.Unlock()
	})
	return c.err
}

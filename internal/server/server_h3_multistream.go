package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

const (
	h3SessionHeader    = "X-Expose-H3-Session"
	h3WorkerQueueDepth = 256
)

var errH3WorkerUnavailable = errors.New("http3 worker stream unavailable")

type h3StreamPool struct {
	ready     chan *http3.Stream
	closed    chan struct{}
	closeOnce sync.Once
}

func newH3StreamPool(queueDepth int) *h3StreamPool {
	if queueDepth <= 0 {
		queueDepth = h3WorkerQueueDepth
	}
	return &h3StreamPool{
		ready:  make(chan *http3.Stream, queueDepth),
		closed: make(chan struct{}),
	}
}

func (p *h3StreamPool) enqueue(stream *http3.Stream) bool {
	if p == nil || stream == nil {
		return false
	}
	select {
	case <-p.closed:
		closeH3Stream(stream)
		return false
	default:
	}
	select {
	case p.ready <- stream:
		return true
	case <-p.closed:
		closeH3Stream(stream)
		return false
	default:
		closeH3Stream(stream)
		return false
	}
}

func (p *h3StreamPool) acquire(ctx context.Context, timeout time.Duration) (*http3.Stream, error) {
	if p == nil {
		return nil, errH3WorkerUnavailable
	}
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.closed:
		return nil, errH3WorkerUnavailable
	case <-timer.C:
		return nil, errH3WorkerUnavailable
	case stream, ok := <-p.ready:
		if !ok || stream == nil {
			return nil, errH3WorkerUnavailable
		}
		return stream, nil
	}
}

func (p *h3StreamPool) close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		close(p.closed)
		close(p.ready)
		for stream := range p.ready {
			closeH3Stream(stream)
		}
	})
}

func closeH3Stream(stream *http3.Stream) {
	if stream == nil {
		return
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	_ = stream.Close()
}

func newH3SessionToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "h3_" + hex.EncodeToString(raw[:]), nil
}

func (s *session) hasH3MultiStream() bool {
	return s != nil && s.h3StreamPool != nil
}

func (s *session) acquireH3Worker(ctx context.Context, timeout time.Duration) (*http3.Stream, error) {
	if s == nil || s.h3StreamPool == nil {
		return nil, errH3WorkerUnavailable
	}
	return s.h3StreamPool.acquire(ctx, timeout)
}

func (s *session) addH3Worker(stream *http3.Stream) bool {
	if s == nil || s.h3StreamPool == nil {
		closeH3Stream(stream)
		return false
	}
	return s.h3StreamPool.enqueue(stream)
}

func (s *session) closeH3StreamPool() {
	if s == nil || s.h3StreamPool == nil {
		return
	}
	s.h3StreamPool.close()
}

func (s *Server) registerH3SessionToken(token string, sess *session) {
	if s == nil || sess == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	s.h3Sessions.Store(token, sess)
}

func (s *Server) unregisterH3SessionToken(token string, sess *session) {
	if s == nil {
		return
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return
	}
	if sess == nil {
		s.h3Sessions.Delete(token)
		return
	}
	if existing, ok := s.h3Sessions.Load(token); ok && existing == sess {
		s.h3Sessions.Delete(token)
	}
}

func (s *Server) lookupSessionByH3Token(token string) *session {
	if s == nil {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	existing, ok := s.h3Sessions.Load(token)
	if !ok {
		return nil
	}
	sess, _ := existing.(*session)
	return sess
}

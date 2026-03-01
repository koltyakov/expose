package tunnelproto

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var ErrWSWritePumpClosed = errors.New("websocket write pump closed")
var ErrWSWritePumpBackpressure = errors.New("websocket write pump backpressure")

const (
	defaultWSWriteControlEnqueueTimeout = 2 * time.Second
	defaultWSWriteDataEnqueueTimeout    = 500 * time.Millisecond
)

type wsWriteRequest struct {
	msg           Message
	frameKind     byte
	id            string
	wsMessageType int
	payload       []byte
	binary        bool
	done          chan error
}

// WSWritePump serializes websocket writes while prioritizing control traffic
// ahead of bulk binary frames.
type WSWritePump struct {
	writeFn     func(wsWriteRequest) error
	closeFn     func()
	high        chan wsWriteRequest
	low         chan wsWriteRequest
	stop        chan struct{}
	done        chan struct{}
	closed      atomic.Bool
	stopOnce    sync.Once
	highTimeout time.Duration
	lowTimeout  time.Duration
}

func NewWSWritePump(conn *websocket.Conn, writeTimeout time.Duration, highCap, lowCap int) *WSWritePump {
	return newWSWritePumpWithWriter(func(req wsWriteRequest) error {
		if conn == nil {
			return ErrWSWritePumpClosed
		}
		if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

		if !req.binary {
			err := conn.WriteJSON(req.msg)
			if err != nil {
				_ = conn.Close()
			}
			return err
		}

		w, err := conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if err := WriteBinaryFrame(w, req.frameKind, req.id, req.wsMessageType, req.payload); err != nil {
			_ = w.Close()
			_ = conn.Close()
			return err
		}
		if err := w.Close(); err != nil {
			_ = conn.Close()
			return err
		}
		return nil
	}, func() {
		if conn != nil {
			_ = conn.Close()
		}
	}, highCap, lowCap, defaultWSWriteControlEnqueueTimeout, defaultWSWriteDataEnqueueTimeout)
}

func newWSWritePumpWithWriter(
	writeFn func(wsWriteRequest) error,
	closeFn func(),
	highCap, lowCap int,
	highTimeout, lowTimeout time.Duration,
) *WSWritePump {
	if highCap <= 0 {
		highCap = 1
	}
	if lowCap <= 0 {
		lowCap = 1
	}
	if highTimeout <= 0 {
		highTimeout = defaultWSWriteControlEnqueueTimeout
	}
	if lowTimeout <= 0 {
		lowTimeout = defaultWSWriteDataEnqueueTimeout
	}
	p := &WSWritePump{
		writeFn:     writeFn,
		closeFn:     closeFn,
		high:        make(chan wsWriteRequest, highCap),
		low:         make(chan wsWriteRequest, lowCap),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		highTimeout: highTimeout,
		lowTimeout:  lowTimeout,
	}
	go p.run()
	return p
}

func (p *WSWritePump) WriteJSON(msg Message) error {
	return p.enqueue(wsWriteRequest{
		msg:  msg,
		done: make(chan error, 1),
	}, true)
}

func (p *WSWritePump) WriteBinaryFrame(frameKind byte, id string, wsMessageType int, payload []byte) error {
	return p.enqueue(wsWriteRequest{
		frameKind:     frameKind,
		id:            id,
		wsMessageType: wsMessageType,
		payload:       payload,
		binary:        true,
		done:          make(chan error, 1),
	}, false)
}

func (p *WSWritePump) Close() {
	p.closed.Store(true)
	p.signalStop()
	<-p.done
}

func (p *WSWritePump) enqueue(req wsWriteRequest, high bool) error {
	if p.closed.Load() {
		return ErrWSWritePumpClosed
	}

	target := p.low
	wait := p.lowTimeout
	if high {
		target = p.high
		wait = p.highTimeout
	}

	if wait <= 0 {
		wait = defaultWSWriteDataEnqueueTimeout
		if high {
			wait = defaultWSWriteControlEnqueueTimeout
		}
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-p.stop:
		return ErrWSWritePumpClosed
	case target <- req:
	case <-timer.C:
		p.triggerBackpressure()
		return ErrWSWritePumpBackpressure
	}

	return <-req.done
}

func (p *WSWritePump) run() {
	defer close(p.done)

	for {
		req, ok := p.next()
		if !ok {
			p.failPending(ErrWSWritePumpClosed)
			return
		}
		err := p.write(req)
		req.done <- err
		if err != nil {
			p.closed.Store(true)
			p.signalStop()
			p.failPending(err)
			return
		}
		if p.closed.Load() {
			p.signalStop()
			p.failPending(ErrWSWritePumpClosed)
			return
		}
	}
}

func (p *WSWritePump) next() (wsWriteRequest, bool) {
	select {
	case req := <-p.high:
		return req, true
	default:
	}

	select {
	case <-p.stop:
		return wsWriteRequest{}, false
	case req := <-p.high:
		return req, true
	case req := <-p.low:
		return req, true
	}
}

func (p *WSWritePump) write(req wsWriteRequest) error {
	if p.writeFn == nil {
		return io.ErrClosedPipe
	}
	return p.writeFn(req)
}

func (p *WSWritePump) failPending(err error) {
	for {
		select {
		case req := <-p.high:
			req.done <- err
		case req := <-p.low:
			req.done <- err
		default:
			return
		}
	}
}

func (p *WSWritePump) signalStop() {
	p.stopOnce.Do(func() {
		close(p.stop)
	})
}

func (p *WSWritePump) triggerBackpressure() {
	if p.closed.Swap(true) {
		return
	}
	if p.closeFn != nil {
		p.closeFn()
	}
	p.signalStop()
}

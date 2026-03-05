package tunneltransport

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

var ErrWritePumpClosed = errors.New("transport write pump closed")
var ErrWritePumpBackpressure = errors.New("transport write pump backpressure")

const (
	defaultWriteControlEnqueueTimeout = 2 * time.Second
	defaultWriteDataEnqueueTimeout    = 500 * time.Millisecond
)

type writeRequest struct {
	msg           tunnelproto.Message
	frameKind     byte
	id            string
	wsMessageType int
	payload       []byte
	binary        bool
	done          chan error
}

type WritePump struct {
	writeFn     func(writeRequest) error
	closeFn     func()
	high        chan writeRequest
	low         chan writeRequest
	stop        chan struct{}
	done        chan struct{}
	closed      atomic.Bool
	stopOnce    sync.Once
	enqueueMu   sync.RWMutex
	highTimeout time.Duration
	lowTimeout  time.Duration
}

func NewWritePump(
	writeFn func(writeRequest) error,
	closeFn func(),
	highCap, lowCap int,
	highTimeout, lowTimeout time.Duration,
) *WritePump {
	if highCap <= 0 {
		highCap = 1
	}
	if lowCap <= 0 {
		lowCap = 1
	}
	if highTimeout <= 0 {
		highTimeout = defaultWriteControlEnqueueTimeout
	}
	if lowTimeout <= 0 {
		lowTimeout = defaultWriteDataEnqueueTimeout
	}
	p := &WritePump{
		writeFn:     writeFn,
		closeFn:     closeFn,
		high:        make(chan writeRequest, highCap),
		low:         make(chan writeRequest, lowCap),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		highTimeout: highTimeout,
		lowTimeout:  lowTimeout,
	}
	go p.run()
	return p
}

func (p *WritePump) WriteJSON(msg tunnelproto.Message) error {
	return p.enqueue(writeRequest{
		msg:  msg,
		done: make(chan error, 1),
	}, true)
}

func (p *WritePump) WriteBinaryFrame(frameKind byte, id string, wsMessageType int, payload []byte) error {
	return p.enqueue(writeRequest{
		frameKind:     frameKind,
		id:            id,
		wsMessageType: wsMessageType,
		payload:       payload,
		binary:        true,
		done:          make(chan error, 1),
	}, false)
}

func (p *WritePump) Close() {
	p.closed.Store(true)
	p.signalStop()
	<-p.done
}

func (p *WritePump) enqueue(req writeRequest, high bool) error {
	if p.closed.Load() {
		return ErrWritePumpClosed
	}
	p.enqueueMu.RLock()
	if p.closed.Load() {
		p.enqueueMu.RUnlock()
		return ErrWritePumpClosed
	}
	select {
	case <-p.stop:
		p.enqueueMu.RUnlock()
		return ErrWritePumpClosed
	default:
	}

	target := p.low
	wait := p.lowTimeout
	if high {
		target = p.high
		wait = p.highTimeout
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case target <- req:
		p.enqueueMu.RUnlock()
	case <-timer.C:
		p.enqueueMu.RUnlock()
		p.triggerBackpressure()
		return ErrWritePumpBackpressure
	}
	return <-req.done
}

func (p *WritePump) run() {
	defer close(p.done)

	for {
		req, ok := p.next()
		if !ok {
			p.failPending(ErrWritePumpClosed)
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
			p.failPending(ErrWritePumpClosed)
			return
		}
	}
}

func (p *WritePump) next() (writeRequest, bool) {
	select {
	case req := <-p.high:
		return req, true
	default:
	}

	select {
	case <-p.stop:
		return writeRequest{}, false
	case req := <-p.high:
		return req, true
	case req := <-p.low:
		return req, true
	}
}

func (p *WritePump) write(req writeRequest) error {
	if p.writeFn == nil {
		return ErrWritePumpClosed
	}
	return p.writeFn(req)
}

func (p *WritePump) signalStop() {
	p.stopOnce.Do(func() {
		p.enqueueMu.Lock()
		close(p.stop)
		p.enqueueMu.Unlock()
		if p.closeFn != nil {
			p.closeFn()
		}
	})
}

func (p *WritePump) triggerBackpressure() {
	p.closed.Store(true)
	p.signalStop()
}

func (p *WritePump) failPending(err error) {
	failQueue := func(ch <-chan writeRequest) {
		for {
			select {
			case req := <-ch:
				req.done <- err
			default:
				return
			}
		}
	}
	failQueue(p.high)
	failQueue(p.low)
}

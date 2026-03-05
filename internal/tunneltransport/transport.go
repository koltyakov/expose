package tunneltransport

import (
	"io"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

type Transport interface {
	ReadMessage(*tunnelproto.Message) error
	SetReadLimit(int64)
	Close() error
}

type namedTransport interface {
	Transport
	Name() string
}

func NameOf(t Transport) string {
	if t == nil {
		return ""
	}
	if named, ok := t.(namedTransport); ok {
		return named.Name()
	}
	return "unknown"
}

type StreamTransport struct {
	stream       io.ReadWriteCloser
	maxReadBytes int64
	name         string
	closeFn      func() error
}

func NewStreamTransport(name string, stream io.ReadWriteCloser, closeFn func() error) *StreamTransport {
	return &StreamTransport{
		stream:  stream,
		name:    name,
		closeFn: closeFn,
	}
}

func (t *StreamTransport) Name() string {
	return t.name
}

func (t *StreamTransport) ReadMessage(dst *tunnelproto.Message) error {
	return tunnelproto.ReadStreamMessage(t.stream, t.maxReadBytes, dst)
}

func (t *StreamTransport) SetReadLimit(maxBytes int64) {
	t.maxReadBytes = maxBytes
}

func (t *StreamTransport) Close() error {
	if t.closeFn != nil {
		return t.closeFn()
	}
	if t.stream == nil {
		return nil
	}
	return t.stream.Close()
}

type WebSocketTransport struct {
	conn *websocket.Conn
}

func NewWebSocketTransport(conn *websocket.Conn) *WebSocketTransport {
	return &WebSocketTransport{conn: conn}
}

func (t *WebSocketTransport) Name() string {
	return "ws"
}

func (t *WebSocketTransport) ReadMessage(dst *tunnelproto.Message) error {
	return tunnelproto.ReadWSMessage(t.conn, dst)
}

func (t *WebSocketTransport) SetReadLimit(maxBytes int64) {
	if t.conn != nil {
		t.conn.SetReadLimit(maxBytes)
	}
}

func (t *WebSocketTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func NewWebSocketWritePump(conn *websocket.Conn, writeTimeout time.Duration, highCap, lowCap int) *WritePump {
	return NewWritePump(func(req writeRequest) error {
		if conn == nil {
			return ErrWritePumpClosed
		}
		if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
			_ = conn.Close()
			return err
		}
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

		w, err := conn.NextWriter(websocket.BinaryMessage)
		if err != nil {
			_ = conn.Close()
			return err
		}
		if !req.binary {
			if err := tunnelproto.WriteMessage(w, req.msg); err != nil {
				_ = w.Close()
				_ = conn.Close()
				return err
			}
		} else {
			if err := tunnelproto.WriteBinaryFrame(w, req.frameKind, req.id, req.wsMessageType, req.payload); err != nil {
				_ = w.Close()
				_ = conn.Close()
				return err
			}
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
	}, highCap, lowCap, defaultWriteControlEnqueueTimeout, defaultWriteDataEnqueueTimeout)
}

func NewStreamWritePump(stream io.ReadWriteCloser, writeTimeout time.Duration, highCap, lowCap int, closeFn func()) *WritePump {
	type deadlineWriter interface {
		SetWriteDeadline(time.Time) error
	}

	return NewWritePump(func(req writeRequest) error {
		if stream == nil {
			return ErrWritePumpClosed
		}
		if dw, ok := stream.(deadlineWriter); ok && writeTimeout > 0 {
			if err := dw.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				if closeFn != nil {
					closeFn()
				}
				return err
			}
			defer func() { _ = dw.SetWriteDeadline(time.Time{}) }()
		}

		if !req.binary {
			return tunnelproto.WriteStreamJSON(stream, req.msg)
		}
		return tunnelproto.WriteStreamBinaryFrame(stream, req.frameKind, req.id, req.wsMessageType, req.payload)
	}, closeFn, highCap, lowCap, defaultWriteControlEnqueueTimeout, defaultWriteDataEnqueueTimeout)
}

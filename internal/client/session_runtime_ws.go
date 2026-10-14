package client

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/traffic"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

// localWebSocket is one forwarded websocket to the local upstream. Its writer
// goroutine delivers tunnel data in order, so a slow local endpoint never
// stalls the session's message loop and every other request on the tunnel.
type localWebSocket struct {
	conn   *websocket.Conn
	writes chan localWSWrite
	done   chan struct{}
	once   sync.Once
}

// localWSWrite is a data message, or a close frame when close is set.
type localWSWrite struct {
	messageType int
	payload     []byte
	close       *tunnelproto.WSClose
}

func (s *localWebSocket) stop() {
	s.once.Do(func() { close(s.done) })
}

// setWSConn registers an opened local websocket and starts its writer. It
// reports false once the session is closing, and the caller then owns conn.
func (rt *clientSessionRuntime) setWSConn(id string, streamConn *websocket.Conn) bool {
	stream := &localWebSocket{
		conn:   streamConn,
		writes: make(chan localWSWrite, localWSWriteQueueSize),
		done:   make(chan struct{}),
	}
	rt.wsMu.Lock()
	if rt.wsClosed {
		rt.wsMu.Unlock()
		return false
	}
	if rt.wsConns == nil {
		rt.wsConns = make(map[string]*localWebSocket)
	}
	rt.wsConns[id] = stream
	rt.wsMu.Unlock()
	rt.requestWG.Go(func() { rt.runLocalWSWriter(id, stream) })
	return true
}

func (rt *clientSessionRuntime) getWSConn(id string) (*localWebSocket, bool) {
	rt.wsMu.RLock()
	stream, ok := rt.wsConns[id]
	rt.wsMu.RUnlock()
	return stream, ok
}

func (rt *clientSessionRuntime) deleteWSConn(id string) {
	rt.wsMu.Lock()
	stream, ok := rt.wsConns[id]
	if ok {
		delete(rt.wsConns, id)
	}
	rt.wsMu.Unlock()

	if ok {
		stream.stop()
		_ = stream.conn.Close()
		rt.client.trackWSClose(id)
	}
}

// closeWSConns closes every local websocket and refuses new ones.
func (rt *clientSessionRuntime) closeWSConns() {
	rt.wsMu.Lock()
	rt.wsClosed = true
	streams := rt.wsConns
	rt.wsConns = make(map[string]*localWebSocket)
	rt.wsMu.Unlock()
	for _, stream := range streams {
		stream.stop()
		_ = stream.conn.Close()
	}
}

func (rt *clientSessionRuntime) runLocalWSWriter(streamID string, stream *localWebSocket) {
	for {
		select {
		case <-stream.done:
			return
		case write := <-stream.writes:
			if write.close != nil {
				_ = stream.conn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(write.close.Code, write.close.Text),
					time.Now().Add(5*time.Second),
				)
				rt.deleteWSConn(streamID)
				return
			}
			_ = stream.conn.SetWriteDeadline(time.Now().Add(clientWSWriteTimeout))
			if err := stream.conn.WriteMessage(write.messageType, write.payload); err != nil {
				rt.deleteWSConn(streamID)
				return
			}
			rt.client.recordTraffic(traffic.DirectionInbound, int64(len(write.payload)))
		}
	}
}

func (rt *clientSessionRuntime) startLocalWSReader(streamID string, streamConn *websocket.Conn) {
	rt.requestWG.Go(func() {
		defer rt.deleteWSConn(streamID)

		for {
			msgType, payload, err := streamConn.ReadMessage()
			if err != nil {
				closeCode := websocket.CloseNormalClosure
				closeText := ""
				if closeErr, ok := errors.AsType[*websocket.CloseError](err); ok {
					closeCode = closeErr.Code
					closeText = closeErr.Text
				}
				_ = rt.writeJSON(tunnelproto.Message{
					Kind:    tunnelproto.KindWSClose,
					WSClose: &tunnelproto.WSClose{ID: streamID, Code: closeCode, Text: closeText},
				})
				return
			}
			if err := rt.writeBinary(tunnelproto.BinaryFrameWSData, streamID, msgType, payload); err != nil {
				return
			}
			rt.client.recordTraffic(traffic.DirectionOutbound, int64(len(payload)))
		}
	})
}

// handleWSOpen dials the local upstream. It runs outside the session's
// message loop: a slow local handshake must not delay other tunnel traffic.
func (rt *clientSessionRuntime) handleWSOpen(open *tunnelproto.WSOpen) {
	if open == nil {
		return
	}
	streamID := strings.TrimSpace(open.ID)
	if streamID == "" {
		return
	}

	upstreamConn, status, subprotocol, err := rt.client.openLocalWebSocket(rt.ctx, rt.localBase, open)
	if err != nil {
		_ = rt.writeJSON(tunnelproto.Message{
			Kind: tunnelproto.KindWSOpenAck,
			WSOpenAck: &tunnelproto.WSOpenAck{
				ID:     streamID,
				OK:     false,
				Status: status,
				Error:  err.Error(),
			},
		})
		return
	}

	if !rt.setWSConn(streamID, upstreamConn) {
		_ = upstreamConn.Close()
		return
	}
	rt.client.trackWSOpen(streamID, open)

	// The server sends data only after this acknowledgement, so the stream is
	// registered before any of it arrives.
	if err := rt.writeJSON(tunnelproto.Message{
		Kind: tunnelproto.KindWSOpenAck,
		WSOpenAck: &tunnelproto.WSOpenAck{
			ID:          streamID,
			OK:          true,
			Status:      http.StatusSwitchingProtocols,
			Subprotocol: subprotocol,
		},
	}); err != nil {
		rt.deleteWSConn(streamID)
		return
	}

	rt.startLocalWSReader(streamID, upstreamConn)
}

func (rt *clientSessionRuntime) handleWSData(data *tunnelproto.WSData) {
	if data == nil {
		return
	}
	stream, ok := rt.getWSConn(data.ID)
	if !ok {
		return
	}
	payload, err := data.Payload()
	if err != nil {
		return
	}
	select {
	case stream.writes <- localWSWrite{messageType: data.MessageType, payload: payload}:
	default:
		// Like the server, drop a consumer that cannot keep up instead of
		// blocking every other stream behind it.
		rt.deleteWSConn(data.ID)
		_ = rt.writeJSONAsync(tunnelproto.Message{
			Kind:    tunnelproto.KindWSClose,
			WSClose: &tunnelproto.WSClose{ID: data.ID, Code: websocket.ClosePolicyViolation, Text: "stream consumer too slow"},
		})
	}
}

func (rt *clientSessionRuntime) handleWSClose(closeMsg *tunnelproto.WSClose) {
	if closeMsg == nil {
		return
	}
	stream, ok := rt.getWSConn(closeMsg.ID)
	if !ok {
		return
	}
	select {
	case stream.writes <- localWSWrite{close: closeMsg}: // after the data queued before it
	default:
		_ = stream.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(closeMsg.Code, closeMsg.Text),
			time.Now().Add(5*time.Second),
		)
		rt.deleteWSConn(closeMsg.ID)
	}
}

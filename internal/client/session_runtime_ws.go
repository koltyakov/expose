package client

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (rt *clientSessionRuntime) setWSConn(id string, streamConn *websocket.Conn) {
	rt.wsMu.Lock()
	rt.wsConns[id] = streamConn
	rt.wsMu.Unlock()
}

func (rt *clientSessionRuntime) getWSConn(id string) (*websocket.Conn, bool) {
	rt.wsMu.RLock()
	streamConn, ok := rt.wsConns[id]
	rt.wsMu.RUnlock()
	return streamConn, ok
}

func (rt *clientSessionRuntime) deleteWSConn(id string) {
	rt.wsMu.Lock()
	streamConn, ok := rt.wsConns[id]
	if ok {
		delete(rt.wsConns, id)
	}
	rt.wsMu.Unlock()

	if ok {
		_ = streamConn.Close()
		if rt.client.display != nil {
			rt.client.display.TrackWSClose(id)
		} else if rt.client.log != nil {
			rt.client.log.Info("forwarded websocket closed", "stream_id", id)
		}
	}
}

func (rt *clientSessionRuntime) startLocalWSReader(streamID string, streamConn *websocket.Conn) {
	rt.requestWG.Add(1)
	go func() {
		defer rt.requestWG.Done()
		defer rt.deleteWSConn(streamID)

		for {
			msgType, payload, err := streamConn.ReadMessage()
			if err != nil {
				closeCode := websocket.CloseNormalClosure
				closeText := ""
				var closeErr *websocket.CloseError
				if errors.As(err, &closeErr) {
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
		}
	}()
}

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

	rt.setWSConn(streamID, upstreamConn)
	if rt.client.display != nil {
		wsPath := open.Path
		if open.Query != "" {
			wsPath += "?" + open.Query
		}
		rt.client.display.TrackWSOpen(streamID, wsPath, open.Headers)
	} else if rt.client.log != nil {
		wsPath := open.Path
		if open.Query != "" {
			wsPath += "?" + open.Query
		}
		fp := visitorFingerprint(open.Headers)
		if fp != "" {
			rt.client.log.Info("forwarded websocket opened", "stream_id", streamID, "path", wsPath, "client_fingerprint", fp)
		} else {
			rt.client.log.Info("forwarded websocket opened", "stream_id", streamID, "path", wsPath)
		}
	}

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
	streamConn, ok := rt.getWSConn(data.ID)
	if !ok {
		return
	}
	payload, err := data.Payload()
	if err != nil {
		return
	}
	if err := streamConn.WriteMessage(data.MessageType, payload); err != nil {
		rt.deleteWSConn(data.ID)
	}
}

func (rt *clientSessionRuntime) handleWSClose(closeMsg *tunnelproto.WSClose) {
	if closeMsg == nil {
		return
	}
	streamConn, ok := rt.getWSConn(closeMsg.ID)
	if !ok {
		return
	}
	_ = streamConn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(closeMsg.Code, closeMsg.Text),
		time.Now().Add(5*time.Second),
	)
	rt.deleteWSConn(closeMsg.ID)
}

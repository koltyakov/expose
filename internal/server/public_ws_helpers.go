package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/koltyakov/expose/internal/tunnelproto"
)

func (s *Server) waitForPublicWSOpenAck(
	r *http.Request,
	timer *time.Timer,
	streamCh <-chan tunnelproto.Message,
) (*tunnelproto.WSOpenAck, int, string) {
	for {
		select {
		case <-r.Context().Done():
			return nil, 0, ""
		case <-timer.C:
			return nil, http.StatusGatewayTimeout, "upstream timeout"
		case msg, ok := <-streamCh:
			if !ok {
				return nil, http.StatusBadGateway, "tunnel closed"
			}
			if msg.Kind == tunnelproto.KindWSOpenAck && msg.WSOpenAck != nil {
				return msg.WSOpenAck, 0, ""
			}
		}
	}
}

func (s *Server) startPublicWSReadRelay(
	streamID string,
	sess *session,
	publicConn *websocket.Conn,
	readDone chan<- struct{},
) {
	go func() {
		defer close(readDone)
		for {
			msgType, payload, err := publicConn.ReadMessage()
			if err != nil {
				code, text := websocket.CloseNormalClosure, ""
				var ce *websocket.CloseError
				if errors.As(err, &ce) {
					code, text = ce.Code, ce.Text
				}
				_ = sess.writeJSON(tunnelproto.Message{
					Kind:    tunnelproto.KindWSClose,
					WSClose: &tunnelproto.WSClose{ID: streamID, Code: code, Text: text},
				})
				return
			}
			if err := sess.writeWSData(streamID, msgType, payload); err != nil {
				return
			}
		}
	}()
}

func (s *Server) startPublicWSWriteRelay(
	r *http.Request,
	streamID string,
	publicConn *websocket.Conn,
	streamCh <-chan tunnelproto.Message,
	relayStop <-chan struct{},
	writeDone chan<- struct{},
) {
	go func() {
		defer close(writeDone)
		for {
			select {
			case <-relayStop:
				return
			case <-r.Context().Done():
				return
			case msg, ok := <-streamCh:
				if !ok {
					return
				}
				switch msg.Kind {
				case tunnelproto.KindWSData:
					if msg.WSData == nil {
						continue
					}
					b, err := msg.WSData.Payload()
					if err != nil {
						continue
					}
					if err := publicConn.WriteMessage(msg.WSData.MessageType, b); err != nil {
						return
					}
				case tunnelproto.KindWSClose:
					if msg.WSClose == nil {
						return
					}
					_ = publicConn.WriteControl(
						websocket.CloseMessage,
						websocket.FormatCloseMessage(msg.WSClose.Code, msg.WSClose.Text),
						time.Now().Add(5*time.Second),
					)
					return
				}
			}
		}
	}()
}

func publicWSOpenFailure(ack *tunnelproto.WSOpenAck) (status int, message string) {
	status = ack.Status
	if status == 0 {
		status = http.StatusBadGateway
	}
	if strings.TrimSpace(ack.Error) == "" {
		return status, "websocket upstream open failed"
	}
	return status, ack.Error
}

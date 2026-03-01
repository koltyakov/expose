// Package tunnelproto defines the JSON wire protocol exchanged between the
// expose server and its tunnel clients over a WebSocket connection.
package tunnelproto

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

// Message kinds identify the type of payload carried by a [Message].
const (
	KindRequest     = "request"
	KindResponse    = "response"
	KindReqCancel   = "req_cancel"
	KindReqBody     = "req_body"
	KindReqBodyEnd  = "req_body_end"
	KindRespBody    = "resp_body"
	KindRespBodyEnd = "resp_body_end"
	KindWSOpen      = "ws_open"
	KindWSOpenAck   = "ws_open_ack"
	KindWSData      = "ws_data"
	KindWSClose     = "ws_close"
	KindPing        = "ping"
	KindPong        = "pong"
	KindError       = "error"
	KindClose       = "close"
)

const (
	// BinaryFrameReqBody carries request body chunks (server -> client).
	BinaryFrameReqBody byte = 1
	// BinaryFrameRespBody carries response body chunks (client -> server).
	BinaryFrameRespBody byte = 2
	// BinaryFrameWSData carries websocket stream frame payloads.
	BinaryFrameWSData byte = 3
)

const (
	binaryFrameVersion = 1
	binaryFrameHeader  = 6
)

// Message is the top-level envelope exchanged on the tunnel WebSocket.
type Message struct {
	Kind      string         `json:"kind"`
	Request   *HTTPRequest   `json:"request,omitempty"`
	Response  *HTTPResponse  `json:"response,omitempty"`
	ReqCancel *RequestCancel `json:"req_cancel,omitempty"`
	BodyChunk *BodyChunk     `json:"body_chunk,omitempty"`
	WSOpen    *WSOpen        `json:"ws_open,omitempty"`
	WSOpenAck *WSOpenAck     `json:"ws_open_ack,omitempty"`
	WSData    *WSData        `json:"ws_data,omitempty"`
	WSClose   *WSClose       `json:"ws_close,omitempty"`
	Stats     *Stats         `json:"stats,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// HTTPRequest represents an inbound public HTTP request forwarded to the client.
type HTTPRequest struct {
	ID        string              `json:"id"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Query     string              `json:"query,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	BodyB64   string              `json:"body_b64,omitempty"`
	Streamed  bool                `json:"streamed,omitempty"`
	TimeoutMs int                 `json:"timeout_ms,omitempty"`
}

// HTTPResponse is the client's reply to a forwarded [HTTPRequest].
type HTTPResponse struct {
	ID       string              `json:"id"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers,omitempty"`
	BodyB64  string              `json:"body_b64,omitempty"`
	Streamed bool                `json:"streamed,omitempty"`
}

// RequestCancel instructs the client to cancel an in-flight forwarded HTTP
// request identified by ID.
type RequestCancel struct {
	ID string `json:"id"`
}

// BodyChunk carries a chunk of request or response body data for streamed
// transfers. Used with [KindReqBody], [KindReqBodyEnd], [KindRespBody],
// and [KindRespBodyEnd] message kinds.
type BodyChunk struct {
	ID      string `json:"id"`
	DataB64 string `json:"data_b64,omitempty"`
	Data    []byte `json:"-"`
}

// WSOpen requests opening a local websocket stream on the client.
type WSOpen struct {
	ID      string              `json:"id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

// WSOpenAck reports websocket stream open result from the client.
type WSOpenAck struct {
	ID          string `json:"id"`
	OK          bool   `json:"ok"`
	Status      int    `json:"status,omitempty"`
	Subprotocol string `json:"subprotocol,omitempty"`
	Error       string `json:"error,omitempty"`
}

// WSData carries websocket frame payloads for a stream.
type WSData struct {
	ID          string `json:"id"`
	MessageType int    `json:"message_type"`
	DataB64     string `json:"data_b64,omitempty"`
	Data        []byte `json:"-"`
}

// WSClose notifies websocket stream closure.
type WSClose struct {
	ID   string `json:"id"`
	Code int    `json:"code,omitempty"`
	Text string `json:"text,omitempty"`
}

// Stats carries optional server-side statistics piggybacked on pong messages.
type Stats struct {
	WAFBlocked int64 `json:"waf_blocked,omitempty"`
}

// base64BufPool recycles byte slices used by [EncodeBody] so that hot-path
// body encoding avoids per-call heap allocations.
var base64BufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// EncodeBody base64-encodes a byte slice for JSON transport.
// It uses a pooled buffer to reduce GC pressure on the hot path.
func EncodeBody(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	needed := base64.StdEncoding.EncodedLen(len(b))
	bufPtr := base64BufPool.Get().(*[]byte)
	buf := *bufPtr
	if cap(buf) < needed {
		buf = make([]byte, needed)
	} else {
		buf = buf[:needed]
	}
	base64.StdEncoding.Encode(buf, b)
	s := string(buf)
	*bufPtr = buf
	base64BufPool.Put(bufPtr)
	return s
}

// DecodeBody decodes a base64-encoded body string.
func DecodeBody(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// Payload returns the decoded bytes for a body chunk regardless of whether it
// arrived as JSON base64 or as a binary websocket frame.
func (c *BodyChunk) Payload() ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	if c.Data != nil {
		return c.Data, nil
	}
	return DecodeBody(c.DataB64)
}

// Payload returns the decoded bytes for a websocket data frame regardless of
// whether it arrived as JSON base64 or as a binary websocket frame.
func (d *WSData) Payload() ([]byte, error) {
	if d == nil {
		return nil, nil
	}
	if d.Data != nil {
		return d.Data, nil
	}
	return DecodeBody(d.DataB64)
}

// ReadWSMessage reads the next websocket frame and decodes it into a tunnel
// message. Text frames are JSON control messages; binary frames are compact
// data frames used for req/resp body chunks and websocket stream payloads.
func ReadWSMessage(conn *websocket.Conn, dst *Message) error {
	for {
		msgType, data, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		switch msgType {
		case websocket.TextMessage:
			var msg Message
			if err := json.Unmarshal(data, &msg); err != nil {
				return err
			}
			*dst = msg
			return nil
		case websocket.BinaryMessage:
			msg, err := decodeBinaryFrame(data)
			if err != nil {
				return err
			}
			*dst = msg
			return nil
		}
	}
}

// WriteBinaryFrame writes a compact binary tunnel frame for high-volume data.
func WriteBinaryFrame(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	if len(id) == 0 {
		return errors.New("binary frame id is required")
	}
	if len(id) > 0xffff {
		return errors.New("binary frame id is too long")
	}
	if frameKind != BinaryFrameReqBody && frameKind != BinaryFrameRespBody && frameKind != BinaryFrameWSData {
		return fmt.Errorf("unsupported binary frame kind: %d", frameKind)
	}

	wsTypeByte := byte(0)
	if frameKind == BinaryFrameWSData {
		if wsMessageType < 0 || wsMessageType > 255 {
			return fmt.Errorf("invalid websocket message type for binary frame: %d", wsMessageType)
		}
		wsTypeByte = byte(wsMessageType)
	}

	var header [binaryFrameHeader]byte
	header[0] = binaryFrameVersion
	header[1] = frameKind
	header[2] = wsTypeByte
	binary.BigEndian.PutUint16(header[4:6], uint16(len(id)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, id); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

func decodeBinaryFrame(data []byte) (Message, error) {
	if len(data) < binaryFrameHeader {
		return Message{}, errors.New("binary frame is too short")
	}
	if data[0] != binaryFrameVersion {
		return Message{}, fmt.Errorf("unsupported binary frame version: %d", data[0])
	}

	frameKind := data[1]
	wsMsgType := int(data[2])
	idLen := int(binary.BigEndian.Uint16(data[4:6]))
	if idLen <= 0 {
		return Message{}, errors.New("invalid binary frame id length")
	}

	idStart := binaryFrameHeader
	idEnd := idStart + idLen
	if len(data) < idEnd {
		return Message{}, errors.New("binary frame id is truncated")
	}
	idBytes := data[idStart:idEnd]
	payload := data[idEnd:]
	id := string(idBytes)

	switch frameKind {
	case BinaryFrameReqBody:
		return Message{
			Kind:      KindReqBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		}, nil
	case BinaryFrameRespBody:
		return Message{
			Kind:      KindRespBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		}, nil
	case BinaryFrameWSData:
		return Message{
			Kind: KindWSData,
			WSData: &WSData{
				ID:          id,
				MessageType: wsMsgType,
				Data:        payload,
			},
		}, nil
	default:
		return Message{}, fmt.Errorf("unsupported binary frame kind: %d", frameKind)
	}
}

// CloneHeaders returns a deep copy of an HTTP header map.
func CloneHeaders(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		c := make([]string, len(v))
		copy(c, v)
		out[k] = c
	}
	return out
}

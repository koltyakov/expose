// Package tunnelproto defines the tunnel wire protocol exchanged between the
// expose server and its tunnel clients.
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
	KindWorkerCtrl  = "worker_ctrl"
	KindError       = "error"
	KindClose       = "close"
)

const (
	// BinaryFrameReqBody carries request body chunks (server -> client).
	BinaryFrameReqBody byte = 4
	// BinaryFrameRespBody carries response body chunks (client -> server).
	BinaryFrameRespBody byte = 6
	// BinaryFrameWSData carries websocket stream frame payloads.
	BinaryFrameWSData byte = 10
)

const (
	binaryFrameVersion = 2
	binaryFrameHeader  = 14
	maxBinaryFrameID   = 0xffff
)

const (
	frameKindRequest byte = 1 + iota
	frameKindResponse
	frameKindReqCancel
	frameKindReqBody
	frameKindReqBodyEnd
	frameKindRespBody
	frameKindRespBodyEnd
	frameKindWSOpen
	frameKindWSOpenAck
	frameKindWSData
	frameKindWSClose
	frameKindPing
	frameKindPong
	frameKindWorkerCtrl
	frameKindError
	frameKindClose
)

// Message is the top-level envelope exchanged on the tunnel WebSocket.
type Message struct {
	Kind       string         `json:"kind"`
	Request    *HTTPRequest   `json:"request,omitempty"`
	Response   *HTTPResponse  `json:"response,omitempty"`
	ReqCancel  *RequestCancel `json:"req_cancel,omitempty"`
	BodyChunk  *BodyChunk     `json:"body_chunk,omitempty"`
	WSOpen     *WSOpen        `json:"ws_open,omitempty"`
	WSOpenAck  *WSOpenAck     `json:"ws_open_ack,omitempty"`
	WSData     *WSData        `json:"ws_data,omitempty"`
	WSClose    *WSClose       `json:"ws_close,omitempty"`
	Stats      *Stats         `json:"stats,omitempty"`
	WorkerCtrl *WorkerControl `json:"worker_ctrl,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// HTTPRequest represents an inbound public HTTP request forwarded to the client.
type HTTPRequest struct {
	ID        string              `json:"id"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Query     string              `json:"query,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	BodyB64   string              `json:"body_b64,omitempty"`
	Body      []byte              `json:"-"`
	Streamed  bool                `json:"streamed,omitempty"`
	TimeoutMs int                 `json:"timeout_ms,omitempty"`
}

// HTTPResponse is the client's reply to a forwarded [HTTPRequest].
type HTTPResponse struct {
	ID       string              `json:"id"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers,omitempty"`
	BodyB64  string              `json:"body_b64,omitempty"`
	Body     []byte              `json:"-"`
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

type WorkerControl struct {
	Desired int `json:"desired,omitempty"`
}

type encodedFrame struct {
	kind          byte
	id            string
	wsMessageType int
	meta          []byte
	payload       []byte
}

type requestMeta struct {
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Query     string              `json:"query,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Streamed  bool                `json:"streamed,omitempty"`
	TimeoutMs int                 `json:"timeout_ms,omitempty"`
}

type responseMeta struct {
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers,omitempty"`
	Streamed bool                `json:"streamed,omitempty"`
}

type wsOpenMeta struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type wsOpenAckMeta struct {
	OK          bool   `json:"ok"`
	Status      int    `json:"status,omitempty"`
	Subprotocol string `json:"subprotocol,omitempty"`
	Error       string `json:"error,omitempty"`
}

type wsCloseMeta struct {
	Code int    `json:"code,omitempty"`
	Text string `json:"text,omitempty"`
}

type pongMeta struct {
	Stats *Stats `json:"stats,omitempty"`
}

type errorMeta struct {
	Error string `json:"error,omitempty"`
}

type workerControlMeta struct {
	Desired int `json:"desired,omitempty"`
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

// Payload returns the decoded bytes for an inline request body regardless of
// whether it arrived as a raw payload or JSON base64.
func (r *HTTPRequest) Payload() ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if r.Body != nil {
		return r.Body, nil
	}
	return DecodeBody(r.BodyB64)
}

// Payload returns the decoded bytes for an inline response body regardless of
// whether it arrived as a raw payload or JSON base64.
func (r *HTTPResponse) Payload() ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	if r.Body != nil {
		return r.Body, nil
	}
	return DecodeBody(r.BodyB64)
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
// message. The runtime sends binary frames exclusively; text JSON remains as a
// fallback for older tests and ad hoc peers.
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

// WriteMessage writes a unified binary tunnel frame.
func WriteMessage(w io.Writer, msg Message) error {
	enc, err := encodeMessageFrame(msg)
	if err != nil {
		return err
	}
	return writeEncodedFrame(w, enc)
}

// WriteBinaryFrame writes a compact binary tunnel frame for high-volume data.
func WriteBinaryFrame(w io.Writer, frameKind byte, id string, wsMessageType int, payload []byte) error {
	switch frameKind {
	case BinaryFrameReqBody:
		return WriteMessage(w, Message{
			Kind:      KindReqBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		})
	case BinaryFrameRespBody:
		return WriteMessage(w, Message{
			Kind:      KindRespBody,
			BodyChunk: &BodyChunk{ID: id, Data: payload},
		})
	case BinaryFrameWSData:
		return WriteMessage(w, Message{
			Kind: KindWSData,
			WSData: &WSData{
				ID:          id,
				MessageType: wsMessageType,
				Data:        payload,
			},
		})
	default:
		return fmt.Errorf("unsupported binary frame kind: %d", frameKind)
	}
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
	metaLen := int(binary.BigEndian.Uint32(data[6:10]))
	payloadLen := int(binary.BigEndian.Uint32(data[10:14]))

	total := binaryFrameHeader + idLen + metaLen + payloadLen
	if total != len(data) {
		return Message{}, fmt.Errorf("binary frame length mismatch: got %d want %d", len(data), total)
	}
	if idLen < 0 || metaLen < 0 || payloadLen < 0 {
		return Message{}, errors.New("invalid binary frame lengths")
	}

	offset := binaryFrameHeader
	id := ""
	if idLen > 0 {
		id = string(data[offset : offset+idLen])
		offset += idLen
	}
	meta := data[offset : offset+metaLen]
	offset += metaLen
	payload := data[offset : offset+payloadLen]

	return decodeFrameParts(frameKind, id, wsMsgType, meta, payload)
}

func encodeMessageFrame(msg Message) (encodedFrame, error) {
	switch msg.Kind {
	case KindRequest:
		if msg.Request == nil {
			return encodedFrame{}, errors.New("request payload is required")
		}
		body, err := msg.Request.Payload()
		if err != nil {
			return encodedFrame{}, err
		}
		meta, err := json.Marshal(requestMeta{
			Method:    msg.Request.Method,
			Path:      msg.Request.Path,
			Query:     msg.Request.Query,
			Headers:   msg.Request.Headers,
			Streamed:  msg.Request.Streamed,
			TimeoutMs: msg.Request.TimeoutMs,
		})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindRequest, msg.Request.ID, 0, meta, body)
	case KindResponse:
		if msg.Response == nil {
			return encodedFrame{}, errors.New("response payload is required")
		}
		body, err := msg.Response.Payload()
		if err != nil {
			return encodedFrame{}, err
		}
		meta, err := json.Marshal(responseMeta{
			Status:   msg.Response.Status,
			Headers:  msg.Response.Headers,
			Streamed: msg.Response.Streamed,
		})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindResponse, msg.Response.ID, 0, meta, body)
	case KindReqCancel:
		if msg.ReqCancel == nil {
			return encodedFrame{}, errors.New("request cancel payload is required")
		}
		return newEncodedFrame(frameKindReqCancel, msg.ReqCancel.ID, 0, nil, nil)
	case KindReqBody:
		if msg.BodyChunk == nil {
			return encodedFrame{}, errors.New("body chunk payload is required")
		}
		payload, err := msg.BodyChunk.Payload()
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindReqBody, msg.BodyChunk.ID, 0, nil, payload)
	case KindReqBodyEnd:
		if msg.BodyChunk == nil {
			return encodedFrame{}, errors.New("body chunk payload is required")
		}
		return newEncodedFrame(frameKindReqBodyEnd, msg.BodyChunk.ID, 0, nil, nil)
	case KindRespBody:
		if msg.BodyChunk == nil {
			return encodedFrame{}, errors.New("body chunk payload is required")
		}
		payload, err := msg.BodyChunk.Payload()
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindRespBody, msg.BodyChunk.ID, 0, nil, payload)
	case KindRespBodyEnd:
		if msg.BodyChunk == nil {
			return encodedFrame{}, errors.New("body chunk payload is required")
		}
		return newEncodedFrame(frameKindRespBodyEnd, msg.BodyChunk.ID, 0, nil, nil)
	case KindWSOpen:
		if msg.WSOpen == nil {
			return encodedFrame{}, errors.New("ws open payload is required")
		}
		meta, err := json.Marshal(wsOpenMeta{
			Method:  msg.WSOpen.Method,
			Path:    msg.WSOpen.Path,
			Query:   msg.WSOpen.Query,
			Headers: msg.WSOpen.Headers,
		})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindWSOpen, msg.WSOpen.ID, 0, meta, nil)
	case KindWSOpenAck:
		if msg.WSOpenAck == nil {
			return encodedFrame{}, errors.New("ws open ack payload is required")
		}
		meta, err := json.Marshal(wsOpenAckMeta{
			OK:          msg.WSOpenAck.OK,
			Status:      msg.WSOpenAck.Status,
			Subprotocol: msg.WSOpenAck.Subprotocol,
			Error:       msg.WSOpenAck.Error,
		})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindWSOpenAck, msg.WSOpenAck.ID, 0, meta, nil)
	case KindWSData:
		if msg.WSData == nil {
			return encodedFrame{}, errors.New("ws data payload is required")
		}
		payload, err := msg.WSData.Payload()
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindWSData, msg.WSData.ID, msg.WSData.MessageType, nil, payload)
	case KindWSClose:
		if msg.WSClose == nil {
			return encodedFrame{}, errors.New("ws close payload is required")
		}
		meta, err := json.Marshal(wsCloseMeta{
			Code: msg.WSClose.Code,
			Text: msg.WSClose.Text,
		})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindWSClose, msg.WSClose.ID, 0, meta, nil)
	case KindPing:
		return newEncodedFrame(frameKindPing, "", 0, nil, nil)
	case KindPong:
		var meta []byte
		var err error
		if msg.Stats != nil {
			meta, err = json.Marshal(pongMeta{Stats: msg.Stats})
			if err != nil {
				return encodedFrame{}, err
			}
		}
		return newEncodedFrame(frameKindPong, "", 0, meta, nil)
	case KindWorkerCtrl:
		if msg.WorkerCtrl == nil {
			return encodedFrame{}, errors.New("worker control payload is required")
		}
		meta, err := json.Marshal(workerControlMeta{Desired: msg.WorkerCtrl.Desired})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindWorkerCtrl, "", 0, meta, nil)
	case KindError:
		meta, err := json.Marshal(errorMeta{Error: msg.Error})
		if err != nil {
			return encodedFrame{}, err
		}
		return newEncodedFrame(frameKindError, "", 0, meta, nil)
	case KindClose:
		return newEncodedFrame(frameKindClose, "", 0, nil, nil)
	default:
		return encodedFrame{}, fmt.Errorf("unsupported message kind: %q", msg.Kind)
	}
}

func newEncodedFrame(kind byte, id string, wsMessageType int, meta, payload []byte) (encodedFrame, error) {
	if len(id) > maxBinaryFrameID {
		return encodedFrame{}, errors.New("binary frame id is too long")
	}
	if wsMessageType < 0 || wsMessageType > 255 {
		return encodedFrame{}, fmt.Errorf("invalid websocket message type for binary frame: %d", wsMessageType)
	}
	return encodedFrame{
		kind:          kind,
		id:            id,
		wsMessageType: wsMessageType,
		meta:          meta,
		payload:       payload,
	}, nil
}

func writeEncodedFrame(w io.Writer, enc encodedFrame) error {
	var header [binaryFrameHeader]byte
	header[0] = binaryFrameVersion
	header[1] = enc.kind
	header[2] = byte(enc.wsMessageType)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(enc.id)))
	binary.BigEndian.PutUint32(header[6:10], uint32(len(enc.meta)))
	binary.BigEndian.PutUint32(header[10:14], uint32(len(enc.payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if enc.id != "" {
		if _, err := io.WriteString(w, enc.id); err != nil {
			return err
		}
	}
	if len(enc.meta) > 0 {
		if _, err := w.Write(enc.meta); err != nil {
			return err
		}
	}
	if len(enc.payload) == 0 {
		return nil
	}
	_, err := w.Write(enc.payload)
	return err
}

func encodedFrameLen(enc encodedFrame) int {
	return binaryFrameHeader + len(enc.id) + len(enc.meta) + len(enc.payload)
}

func decodeFrameParts(frameKind byte, id string, wsMsgType int, meta, payload []byte) (Message, error) {
	switch frameKind {
	case frameKindRequest:
		var request requestMeta
		if err := decodeFrameMeta(meta, &request); err != nil {
			return Message{}, err
		}
		return Message{
			Kind: KindRequest,
			Request: &HTTPRequest{
				ID:        id,
				Method:    request.Method,
				Path:      request.Path,
				Query:     request.Query,
				Headers:   request.Headers,
				Body:      payload,
				Streamed:  request.Streamed,
				TimeoutMs: request.TimeoutMs,
			},
		}, nil
	case frameKindResponse:
		var response responseMeta
		if err := decodeFrameMeta(meta, &response); err != nil {
			return Message{}, err
		}
		return Message{
			Kind: KindResponse,
			Response: &HTTPResponse{
				ID:       id,
				Status:   response.Status,
				Headers:  response.Headers,
				Body:     payload,
				Streamed: response.Streamed,
			},
		}, nil
	case frameKindReqCancel:
		return Message{Kind: KindReqCancel, ReqCancel: &RequestCancel{ID: id}}, nil
	case frameKindReqBody:
		return Message{Kind: KindReqBody, BodyChunk: &BodyChunk{ID: id, Data: payload}}, nil
	case frameKindReqBodyEnd:
		return Message{Kind: KindReqBodyEnd, BodyChunk: &BodyChunk{ID: id}}, nil
	case frameKindRespBody:
		return Message{Kind: KindRespBody, BodyChunk: &BodyChunk{ID: id, Data: payload}}, nil
	case frameKindRespBodyEnd:
		return Message{Kind: KindRespBodyEnd, BodyChunk: &BodyChunk{ID: id}}, nil
	case frameKindWSOpen:
		var open wsOpenMeta
		if err := decodeFrameMeta(meta, &open); err != nil {
			return Message{}, err
		}
		return Message{
			Kind: KindWSOpen,
			WSOpen: &WSOpen{
				ID:      id,
				Method:  open.Method,
				Path:    open.Path,
				Query:   open.Query,
				Headers: open.Headers,
			},
		}, nil
	case frameKindWSOpenAck:
		var ack wsOpenAckMeta
		if err := decodeFrameMeta(meta, &ack); err != nil {
			return Message{}, err
		}
		return Message{
			Kind: KindWSOpenAck,
			WSOpenAck: &WSOpenAck{
				ID:          id,
				OK:          ack.OK,
				Status:      ack.Status,
				Subprotocol: ack.Subprotocol,
				Error:       ack.Error,
			},
		}, nil
	case frameKindWSData:
		return Message{
			Kind: KindWSData,
			WSData: &WSData{
				ID:          id,
				MessageType: wsMsgType,
				Data:        payload,
			},
		}, nil
	case frameKindWSClose:
		var closeMsg wsCloseMeta
		if err := decodeFrameMeta(meta, &closeMsg); err != nil {
			return Message{}, err
		}
		return Message{
			Kind: KindWSClose,
			WSClose: &WSClose{
				ID:   id,
				Code: closeMsg.Code,
				Text: closeMsg.Text,
			},
		}, nil
	case frameKindPing:
		return Message{Kind: KindPing}, nil
	case frameKindPong:
		var pong pongMeta
		if err := decodeFrameMeta(meta, &pong); err != nil {
			return Message{}, err
		}
		return Message{Kind: KindPong, Stats: pong.Stats}, nil
	case frameKindWorkerCtrl:
		var ctrl workerControlMeta
		if err := decodeFrameMeta(meta, &ctrl); err != nil {
			return Message{}, err
		}
		return Message{Kind: KindWorkerCtrl, WorkerCtrl: &WorkerControl{Desired: ctrl.Desired}}, nil
	case frameKindError:
		var errMeta errorMeta
		if err := decodeFrameMeta(meta, &errMeta); err != nil {
			return Message{}, err
		}
		return Message{Kind: KindError, Error: errMeta.Error}, nil
	case frameKindClose:
		return Message{Kind: KindClose}, nil
	default:
		return Message{}, fmt.Errorf("unsupported binary frame kind: %d", frameKind)
	}
}

func decodeFrameMeta(meta []byte, dst any) error {
	if len(meta) == 0 {
		return nil
	}
	return json.Unmarshal(meta, dst)
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

// ShallowCloneHeaders copies the header map but reuses the existing value
// slices. Use it only when callers mutate keys, delete entries, or replace
// whole header values without appending to existing slices in-place.
func ShallowCloneHeaders(h map[string][]string) map[string][]string {
	if len(h) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// Package tunnelproto defines the JSON wire protocol exchanged between the
// expose server and its tunnel clients over a WebSocket connection.
package tunnelproto

import (
	"encoding/base64"
)

// Message kinds identify the type of payload carried by a [Message].
const (
	KindRequest   = "request"
	KindResponse  = "response"
	KindWSOpen    = "ws_open"
	KindWSOpenAck = "ws_open_ack"
	KindWSData    = "ws_data"
	KindWSClose   = "ws_close"
	KindPing      = "ping"
	KindPong      = "pong"
	KindError     = "error"
	KindClose     = "close"
)

// Message is the top-level envelope exchanged on the tunnel WebSocket.
type Message struct {
	Kind      string        `json:"kind"`
	Request   *HTTPRequest  `json:"request,omitempty"`
	Response  *HTTPResponse `json:"response,omitempty"`
	WSOpen    *WSOpen       `json:"ws_open,omitempty"`
	WSOpenAck *WSOpenAck    `json:"ws_open_ack,omitempty"`
	WSData    *WSData       `json:"ws_data,omitempty"`
	WSClose   *WSClose      `json:"ws_close,omitempty"`
	Error     string        `json:"error,omitempty"`
}

// HTTPRequest represents an inbound public HTTP request forwarded to the client.
type HTTPRequest struct {
	ID      string              `json:"id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	BodyB64 string              `json:"body_b64,omitempty"`
}

// HTTPResponse is the client's reply to a forwarded [HTTPRequest].
type HTTPResponse struct {
	ID      string              `json:"id"`
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers,omitempty"`
	BodyB64 string              `json:"body_b64,omitempty"`
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
}

// WSClose notifies websocket stream closure.
type WSClose struct {
	ID   string `json:"id"`
	Code int    `json:"code,omitempty"`
	Text string `json:"text,omitempty"`
}

// EncodeBody base64-encodes a byte slice for JSON transport.
func EncodeBody(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeBody decodes a base64-encoded body string.
func DecodeBody(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
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

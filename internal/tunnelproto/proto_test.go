package tunnelproto

import (
	"bytes"
	"testing"
)

func TestBinaryReqBodyFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	payload := []byte("hello binary")
	if err := WriteBinaryFrame(&buf, BinaryFrameReqBody, "req_1", 0, payload); err != nil {
		t.Fatal(err)
	}

	msg, err := decodeBinaryFrame(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Kind != KindReqBody {
		t.Fatalf("expected kind %q, got %q", KindReqBody, msg.Kind)
	}
	if msg.BodyChunk == nil {
		t.Fatal("expected body chunk")
	}
	if msg.BodyChunk.ID != "req_1" {
		t.Fatalf("expected id req_1, got %q", msg.BodyChunk.ID)
	}
	got, err := msg.BodyChunk.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", string(got), string(payload))
	}
}

func TestBinaryWSDataFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	payload := []byte{0x00, 0x01, 0x02, 0x7f}
	if err := WriteBinaryFrame(&buf, BinaryFrameWSData, "ws_1", 2, payload); err != nil {
		t.Fatal(err)
	}

	msg, err := decodeBinaryFrame(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if msg.Kind != KindWSData {
		t.Fatalf("expected kind %q, got %q", KindWSData, msg.Kind)
	}
	if msg.WSData == nil {
		t.Fatal("expected ws_data payload")
	}
	if msg.WSData.ID != "ws_1" {
		t.Fatalf("expected id ws_1, got %q", msg.WSData.ID)
	}
	if msg.WSData.MessageType != 2 {
		t.Fatalf("expected message type 2, got %d", msg.WSData.MessageType)
	}
	got, err := msg.WSData.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %v, want %v", got, payload)
	}
}

func TestWriteMessageRequestResponseRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []Message{
		{
			Kind: KindRequest,
			Request: &HTTPRequest{
				ID:        "req_42",
				Method:    "POST",
				Path:      "/submit",
				RawPath:   "/submit/%2Fencoded",
				Query:     "x=1",
				Headers:   map[string][]string{"Content-Type": {"application/json"}},
				Body:      []byte(`{"ok":true}`),
				TimeoutMs: 1500,
			},
		},
		{
			Kind: KindResponse,
			Response: &HTTPResponse{
				ID:      "req_42",
				Status:  202,
				Headers: map[string][]string{"X-Test": {"yes"}},
				Body:    []byte("accepted"),
			},
		},
		{
			Kind: KindWSOpen,
			WSOpen: &WSOpen{
				ID:      "ws_1",
				Method:  "GET",
				Path:    "/socket",
				RawPath: "/socket/%2Fencoded",
				Headers: map[string][]string{"Upgrade": {"websocket"}},
			},
		},
		{
			Kind:    KindWSClose,
			WSClose: &WSClose{ID: "ws_1", Code: 1000, Text: "done"},
		},
		{
			Kind:  KindPong,
			Stats: &Stats{WAFBlocked: 3},
		},
	}

	for _, want := range tests {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, want); err != nil {
			t.Fatalf("write %s: %v", want.Kind, err)
		}

		got, err := decodeBinaryFrame(buf.Bytes())
		if err != nil {
			t.Fatalf("decode %s: %v", want.Kind, err)
		}

		if got.Kind != want.Kind {
			t.Fatalf("expected kind %q, got %q", want.Kind, got.Kind)
		}
		switch want.Kind {
		case KindRequest:
			payload, _ := got.Request.Payload()
			if got.Request.ID != want.Request.ID || got.Request.RawPath != want.Request.RawPath || string(payload) != string(want.Request.Body) {
				t.Fatalf("unexpected request round-trip: %+v", got.Request)
			}
		case KindResponse:
			payload, _ := got.Response.Payload()
			if got.Response.ID != want.Response.ID || string(payload) != string(want.Response.Body) {
				t.Fatalf("unexpected response round-trip: %+v", got.Response)
			}
		case KindWSOpen:
			if got.WSOpen == nil || got.WSOpen.ID != want.WSOpen.ID || got.WSOpen.Path != want.WSOpen.Path || got.WSOpen.RawPath != want.WSOpen.RawPath {
				t.Fatalf("unexpected ws open round-trip: %+v", got.WSOpen)
			}
		case KindWSClose:
			if got.WSClose == nil || got.WSClose.ID != want.WSClose.ID || got.WSClose.Code != want.WSClose.Code {
				t.Fatalf("unexpected ws close round-trip: %+v", got.WSClose)
			}
		case KindPong:
			if got.Stats == nil || got.Stats.WAFBlocked != want.Stats.WAFBlocked {
				t.Fatalf("unexpected pong stats round-trip: %+v", got.Stats)
			}
		}
	}
}

func TestPayloadFallbackToBase64(t *testing.T) {
	t.Parallel()

	chunk := &BodyChunk{ID: "req_1", DataB64: EncodeBody([]byte("abc"))}
	gotChunk, err := chunk.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotChunk) != "abc" {
		t.Fatalf("unexpected body chunk payload %q", string(gotChunk))
	}

	wsData := &WSData{ID: "ws_1", MessageType: 1, DataB64: EncodeBody([]byte("xyz"))}
	gotWS, err := wsData.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotWS) != "xyz" {
		t.Fatalf("unexpected ws data payload %q", string(gotWS))
	}
}

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

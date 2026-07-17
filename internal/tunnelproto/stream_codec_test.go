package tunnelproto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestStreamV2WireCompatibility(t *testing.T) {
	t.Parallel()

	const goldenHex = "03010000001002060000000100000000000000017278"
	var buf bytes.Buffer
	if err := WriteStreamBinaryFrameV2(&buf, BinaryFrameRespBody, "r", 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != goldenHex {
		t.Fatalf("wire frame = %s, want %s", got, goldenHex)
	}

	wire, err := hex.DecodeString(goldenHex)
	if err != nil {
		t.Fatal(err)
	}
	var msg Message
	if err := ReadStreamMessageV2(bytes.NewReader(wire), 1024, &msg); err != nil {
		t.Fatal(err)
	}
	payload, err := msg.BodyChunk.Payload()
	if err != nil || msg.Kind != KindRespBody || msg.BodyChunk.ID != "r" || string(payload) != "x" {
		t.Fatalf("decoded golden frame = %+v payload=%q err=%v", msg, payload, err)
	}
}

func TestStreamCodecRoundTripJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	want := Message{Kind: KindPing}
	if err := WriteStreamJSON(&buf, want); err != nil {
		t.Fatal(err)
	}

	var got Message
	if err := ReadStreamMessage(&buf, 1024, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != want.Kind {
		t.Fatalf("expected kind %q, got %q", want.Kind, got.Kind)
	}
}

func TestStreamCodecRoundTripBinary(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	wantPayload := []byte("hello")
	if err := WriteStreamBinaryFrame(&buf, BinaryFrameRespBody, "req_1", 0, wantPayload); err != nil {
		t.Fatal(err)
	}

	var got Message
	if err := ReadStreamMessage(&buf, 1024, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindRespBody || got.BodyChunk == nil {
		t.Fatalf("unexpected message: %+v", got)
	}
	if got.BodyChunk.ID != "req_1" {
		t.Fatalf("expected req_1, got %q", got.BodyChunk.ID)
	}
	payload, err := got.BodyChunk.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != string(wantPayload) {
		t.Fatalf("expected payload %q, got %q", string(wantPayload), string(payload))
	}
}

func TestStreamCodecRoundTripBinaryV2(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	wantPayload := []byte("hello-v2")
	if err := WriteStreamBinaryFrameV2(&buf, BinaryFrameRespBody, "req_v2", 0, wantPayload); err != nil {
		t.Fatal(err)
	}

	var got Message
	if err := ReadStreamMessageV2(&buf, 1024, &got); err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindRespBody || got.BodyChunk == nil {
		t.Fatalf("unexpected message: %+v", got)
	}
	payload, err := got.BodyChunk.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if got.BodyChunk.ID != "req_v2" {
		t.Fatalf("expected req_v2, got %q", got.BodyChunk.ID)
	}
	if string(payload) != string(wantPayload) {
		t.Fatalf("expected payload %q, got %q", string(wantPayload), string(payload))
	}
}

package tunnelproto

import (
	"bytes"
	"testing"
)

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

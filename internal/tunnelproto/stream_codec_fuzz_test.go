package tunnelproto

import (
	"bytes"
	"testing"
)

// FuzzReadStreamMessage feeds arbitrary bytes into ReadStreamMessage.
// It must never panic — all malformed input should return an error.
func FuzzReadStreamMessage(f *testing.F) {
	// Seed with a valid v2 stream record (ping).
	var seed bytes.Buffer
	_ = WriteStreamJSON(&seed, Message{Kind: KindPing})
	f.Add(seed.Bytes())

	// Seed with a valid binary stream record.
	var binSeed bytes.Buffer
	_ = WriteStreamBinaryFrame(&binSeed, BinaryFrameRespBody, "r1", 0, []byte("data"))
	f.Add(binSeed.Bytes())

	// Seed with truncated header.
	f.Add([]byte{0x02, 0x01})

	// Seed with empty.
	f.Add([]byte{})

	// Seed with wrong version.
	f.Add([]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x14})

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		// Must not panic. Errors are expected.
		err := ReadStreamMessage(bytes.NewReader(data), 1<<20, &msg)
		if err != nil {
			return
		}
		if msg.Kind == "" {
			t.Fatal("decoded message has empty Kind")
		}
	})
}

// FuzzReadStreamMessageV2 targets the V2 stream codec path.
func FuzzReadStreamMessageV2(f *testing.F) {
	// Seed with valid V2 JSON record.
	var seed bytes.Buffer
	_ = WriteStreamJSONV2(&seed, Message{Kind: KindPong, Stats: &Stats{WAFBlocked: 5}})
	f.Add(seed.Bytes())

	// Seed with valid V2 binary frame.
	var binSeed bytes.Buffer
	_ = WriteStreamBinaryFrameV2(&binSeed, BinaryFrameReqBody, "r2", 0, []byte("v2-data"))
	f.Add(binSeed.Bytes())

	// Seed with empty.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var msg Message
		// Must not panic.
		err := ReadStreamMessageV2(bytes.NewReader(data), 1<<20, &msg)
		if err != nil {
			return
		}
		if msg.Kind == "" {
			t.Fatal("decoded message has empty Kind")
		}
	})
}

// FuzzStreamCodecRoundTrip writes a message through the stream codec and
// reads it back, verifying the kind is preserved.
func FuzzStreamCodecRoundTrip(f *testing.F) {
	f.Add(byte(BinaryFrameReqBody), "req_1", 0, []byte("hello"))
	f.Add(byte(BinaryFrameRespBody), "resp_1", 0, []byte("world"))
	f.Add(byte(BinaryFrameWSData), "ws_1", 1, []byte{0x00, 0xff})
	f.Add(byte(BinaryFrameReqBody), "r", 0, []byte{})

	f.Fuzz(func(t *testing.T, frameKind byte, id string, wsMsgType int, payload []byte) {
		if len(id) > maxBinaryFrameID || len(id) == 0 {
			return
		}
		if wsMsgType < 0 || wsMsgType > 255 {
			return
		}
		// Only test known binary frame kinds.
		switch frameKind {
		case BinaryFrameReqBody, BinaryFrameRespBody, BinaryFrameWSData:
		default:
			return
		}

		// Test V1 roundtrip.
		var buf bytes.Buffer
		if err := WriteStreamBinaryFrame(&buf, frameKind, id, wsMsgType, payload); err != nil {
			return
		}
		var got Message
		if err := ReadStreamMessage(&buf, int64(buf.Len()+1), &got); err != nil {
			t.Fatalf("V1 roundtrip read failed: %v", err)
		}
		if got.Kind == "" {
			t.Fatal("V1 round-tripped message has empty Kind")
		}

		// Test V2 roundtrip.
		buf.Reset()
		if err := WriteStreamBinaryFrameV2(&buf, frameKind, id, wsMsgType, payload); err != nil {
			return
		}
		var gotV2 Message
		if err := ReadStreamMessageV2(&buf, int64(buf.Len()+1), &gotV2); err != nil {
			t.Fatalf("V2 roundtrip read failed: %v", err)
		}
		if gotV2.Kind == "" {
			t.Fatal("V2 round-tripped message has empty Kind")
		}
	})
}

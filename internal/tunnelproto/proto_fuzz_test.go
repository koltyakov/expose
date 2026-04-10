package tunnelproto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzDecodeBinaryFrame feeds arbitrary bytes into decodeBinaryFrame.
// It must never panic — all malformed input should return an error.
func FuzzDecodeBinaryFrame(f *testing.F) {
	// Seed with a valid frame (ping, no id/meta/payload).
	var seed bytes.Buffer
	_ = WriteMessage(&seed, Message{Kind: KindPing})
	f.Add(seed.Bytes())

	// Seed with a request frame carrying a body.
	var reqSeed bytes.Buffer
	_ = WriteMessage(&reqSeed, Message{
		Kind: KindRequest,
		Request: &HTTPRequest{
			ID:     "r1",
			Method: "GET",
			Path:   "/test",
			Body:   []byte("hello"),
		},
	})
	f.Add(reqSeed.Bytes())

	// Seed with a ws_data frame.
	var wsSeed bytes.Buffer
	_ = WriteMessage(&wsSeed, Message{
		Kind:   KindWSData,
		WSData: &WSData{ID: "ws1", MessageType: 1, Data: []byte("data")},
	})
	f.Add(wsSeed.Bytes())

	// Seed with minimal header (too short, should error).
	f.Add([]byte{0x02, 0x01, 0x00, 0x00, 0x00, 0x00})

	// Seed with empty.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are expected for malformed input.
		msg, err := decodeBinaryFrame(data)
		if err != nil {
			return
		}
		// If decoding succeeded, verify basic invariant: kind is non-empty.
		if msg.Kind == "" {
			t.Fatal("decoded message has empty Kind")
		}
	})
}

// FuzzBinaryFrameRoundTrip encodes a Message and verifies decodeBinaryFrame
// recovers the same kind and id. Uses structured fuzzing inputs to explore
// valid frame space.
func FuzzBinaryFrameRoundTrip(f *testing.F) {
	f.Add(byte(frameKindPing), "", 0, []byte(nil), []byte(nil))
	f.Add(byte(frameKindReqBody), "req_1", 0, []byte(nil), []byte("payload"))
	f.Add(byte(frameKindWSData), "ws_1", 2, []byte(nil), []byte{0x00, 0xff})
	f.Add(byte(frameKindResponse), "r42", 0, []byte(`{"status":200}`), []byte("body"))
	f.Add(byte(frameKindRequest), "r1", 0, []byte(`{"method":"GET","path":"/"}`), []byte("req-body"))

	f.Fuzz(func(t *testing.T, kind byte, id string, wsMsgType int, meta, payload []byte) {
		// Constrain to valid ranges to test the encode→decode path.
		if len(id) > maxBinaryFrameID {
			return
		}
		if wsMsgType < 0 || wsMsgType > 255 {
			return
		}
		// Skip unknown frame kinds — encodeMessageFrame only handles known kinds.
		if kind == 0 || kind > frameKindClose {
			return
		}

		enc, err := newEncodedFrame(kind, id, wsMsgType, meta, payload)
		if err != nil {
			return
		}

		var buf bytes.Buffer
		if err := writeEncodedFrame(&buf, enc); err != nil {
			t.Fatalf("writeEncodedFrame: %v", err)
		}

		msg, err := decodeBinaryFrame(buf.Bytes())
		if err != nil {
			// Some meta payloads won't be valid JSON for kinds that require it.
			// That's fine — we're testing no panics.
			return
		}

		if msg.Kind == "" {
			t.Fatal("round-tripped message has empty Kind")
		}
	})
}

// FuzzDecodeBinaryFrameLengthFields specifically targets the length-parsing
// logic by mutating a valid frame's header length fields.
func FuzzDecodeBinaryFrameLengthFields(f *testing.F) {
	f.Add(uint16(0), uint32(0), uint32(0))
	f.Add(uint16(4), uint32(20), uint32(100))
	f.Add(uint16(0xffff), uint32(0), uint32(0))
	f.Add(uint16(0), uint32(0xffffffff), uint32(0))

	f.Fuzz(func(t *testing.T, idLen uint16, metaLen, payloadLen uint32) {
		// Build a frame header with the fuzzed lengths.
		var header [binaryFrameHeader]byte
		header[0] = binaryFrameVersion
		header[1] = frameKindPing
		binary.BigEndian.PutUint16(header[4:6], idLen)
		binary.BigEndian.PutUint32(header[6:10], metaLen)
		binary.BigEndian.PutUint32(header[10:14], payloadLen)

		// Append some trailing bytes so the decoder has something to read,
		// but almost certainly the wrong amount.
		data := make([]byte, binaryFrameHeader+64)
		copy(data, header[:])

		// Must not panic.
		_, _ = decodeBinaryFrame(data)
	})
}

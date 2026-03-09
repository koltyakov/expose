package tunnelproto

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func BenchmarkEncodeBody(b *testing.B) {
	payload := make([]byte, 16*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	b.ReportAllocs()

	for b.Loop() {
		s := EncodeBody(payload)
		if len(s) == 0 {
			b.Fatal("unexpected empty result")
		}
	}
}

func BenchmarkDecodeBody(b *testing.B) {
	payload := make([]byte, 16*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	encoded := EncodeBody(payload)
	b.ReportAllocs()

	for b.Loop() {
		_, _ = DecodeBody(encoded)
	}
}

func BenchmarkEncodeBodySmall(b *testing.B) {
	payload := []byte("hello world")
	b.ReportAllocs()

	for b.Loop() {
		EncodeBody(payload)
	}
}

func BenchmarkCompatibilityModeWSVsH3Stream(b *testing.B) {
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	b.Run("ws_binary_frame_roundtrip", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			if err := WriteBinaryFrame(&buf, BinaryFrameRespBody, "req_1", 0, payload); err != nil {
				b.Fatal(err)
			}
			msg, err := decodeBinaryFrame(buf.Bytes())
			if err != nil {
				b.Fatal(err)
			}
			if msg.Kind != KindRespBody {
				b.Fatalf("unexpected kind %q", msg.Kind)
			}
		}
	})

	b.Run("h3_compat_stream_roundtrip", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			if err := WriteStreamBinaryFrame(&buf, BinaryFrameRespBody, "req_1", 0, payload); err != nil {
				b.Fatal(err)
			}
			var msg Message
			if err := ReadStreamMessage(&buf, 2<<20, &msg); err != nil {
				b.Fatal(err)
			}
			if msg.Kind != KindRespBody {
				b.Fatalf("unexpected kind %q", msg.Kind)
			}
		}
	})
}

func BenchmarkPhase1VsPhase2PacketLossMixedLoad(b *testing.B) {
	for _, lossPercent := range []int{0, 2, 5} {
		b.Run(fmt.Sprintf("loss_%dpct", lossPercent), func(b *testing.B) {
			b.Run("phase1_single_stream", func(b *testing.B) {
				benchmarkMixedLoadMode(b, lossPercent, true)
			})
			b.Run("phase2_multistream", func(b *testing.B) {
				benchmarkMixedLoadMode(b, lossPercent, false)
			})
		})
	}
}

func benchmarkMixedLoadMode(b *testing.B, lossPercent int, phase1 bool) {
	var seq atomic.Uint64
	var sharedMu sync.Mutex
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		var local bytes.Buffer
		for pb.Next() {
			n := seq.Add(1)
			size := mixedLoadPayloadSize(n)
			payload := make([]byte, size)
			if phase1 {
				sharedMu.Lock()
				if packetLossHit(n, lossPercent) {
					mixedLoadLossPenalty(payload)
				}
				local.Reset()
				_ = WriteStreamBinaryFrame(&local, BinaryFrameRespBody, "req_1", 0, payload)
				sharedMu.Unlock()
				continue
			}

			if packetLossHit(n, lossPercent) {
				mixedLoadLossPenalty(payload)
			}
			local.Reset()
			_ = WriteStreamBinaryFrame(&local, BinaryFrameRespBody, "req_1", 0, payload)
		}
	})
}

func packetLossHit(seq uint64, lossPercent int) bool {
	if lossPercent <= 0 {
		return false
	}
	return int(seq%100) < lossPercent
}

func mixedLoadPayloadSize(seq uint64) int {
	// Mixed load profile: 70% small HTTP, 20% medium HTTP, 10% websocket bursts.
	switch seq % 10 {
	case 0:
		return 48 * 1024
	case 1, 2:
		return 8 * 1024
	default:
		return 1024
	}
}

func mixedLoadLossPenalty(payload []byte) {
	// CPU-only penalty to model retransmission and crypto work without sleeping.
	var v byte
	for i := 0; i < len(payload); i += 97 {
		v ^= byte(i)
	}
	if v == 255 {
		payload[0] = v
	}
}

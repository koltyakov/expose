package tunnelproto

import "testing"

func BenchmarkEncodeBody(b *testing.B) {
	payload := make([]byte, 16*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeBody(encoded)
	}
}

func BenchmarkEncodeBodySmall(b *testing.B) {
	payload := []byte("hello world")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncodeBody(payload)
	}
}

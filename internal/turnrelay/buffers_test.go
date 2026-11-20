package turnrelay

import (
	"net"
	"testing"
	"time"
)

func TestTuneUDPBuffersKeepsSocketsUsable(t *testing.T) {
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = receiver.Close() }()
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	// Oversized requests are clamped or halved, never fatal.
	tuneUDPBuffers(receiver, 1<<30)
	tuneUDPBuffers(sender, relaySocketBuffer)
	tuneUDPBuffers(nil, relaySocketBuffer)
	if _, err := sender.WriteTo([]byte("ping"), receiver.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := receiver.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("tuned socket lost datagram: %q, %v", buf[:n], err)
	}
}

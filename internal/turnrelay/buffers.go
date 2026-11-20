package turnrelay

import "net"

// TURN carries WebRTC traffic that reacts to every lost datagram by shrinking
// its congestion window. Operating-system defaults, 208 KiB on Linux, overflow
// during bursts toward one-vCPU receivers, so request larger buffers. The
// shared listener carries every client's traffic. The kernel allocates only
// queued datagrams, and unprivileged requests are clamped to net.core.rmem_max
// and net.core.wmem_max; see docs/turn-relay.md for sizing them.
const (
	listenerSocketBuffer = 8 << 20
	relaySocketBuffer    = 4 << 20
	minSocketBuffer      = 256 << 10
)

// tuneUDPBuffers is best effort. Linux clamps oversized requests, while macOS
// rejects them, so halve a rejected request instead of giving up.
func tuneUDPBuffers(conn net.PacketConn, size int) {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return
	}
	for request := size; request >= minSocketBuffer; request /= 2 {
		if udp.SetReadBuffer(request) == nil {
			break
		}
	}
	for request := size; request >= minSocketBuffer; request /= 2 {
		if udp.SetWriteBuffer(request) == nil {
			break
		}
	}
}

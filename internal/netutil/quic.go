package netutil

import (
	"time"

	"github.com/quic-go/quic-go"
)

const (
	defaultTunnelQUICMaxIdleTimeout = 2 * time.Minute
	defaultTunnelQUICKeepAlive      = 15 * time.Second
)

// TunnelQUICConfig returns a QUIC config suitable for long-lived idle tunnel
// sessions, avoiding the quic-go 30s default idle timeout.
func TunnelQUICConfig(maxIdle time.Duration) *quic.Config {
	if maxIdle <= 0 {
		maxIdle = defaultTunnelQUICMaxIdleTimeout
	}

	keepAlive := defaultTunnelQUICKeepAlive
	halfIdle := maxIdle / 2
	if halfIdle <= 0 {
		halfIdle = maxIdle
	}
	if keepAlive > halfIdle {
		keepAlive = halfIdle
	}

	return &quic.Config{
		MaxIdleTimeout:  maxIdle,
		KeepAlivePeriod: keepAlive,
		// Larger receive windows than the quic-go defaults (512KB/6MB stream,
		// 768KB/15MB connection) keep 256KB tunnel chunks flowing on
		// high-bandwidth-delay links instead of stalling on flow control.
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
	}
}

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
	}
}

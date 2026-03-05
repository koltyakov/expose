package netutil

import (
	"testing"
	"time"
)

func TestTunnelQUICConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := TunnelQUICConfig(0)
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg.MaxIdleTimeout != defaultTunnelQUICMaxIdleTimeout {
		t.Fatalf("MaxIdleTimeout = %s, want %s", cfg.MaxIdleTimeout, defaultTunnelQUICMaxIdleTimeout)
	}
	if cfg.KeepAlivePeriod != defaultTunnelQUICKeepAlive {
		t.Fatalf("KeepAlivePeriod = %s, want %s", cfg.KeepAlivePeriod, defaultTunnelQUICKeepAlive)
	}
}

func TestTunnelQUICConfigCapsKeepAliveToHalfIdle(t *testing.T) {
	t.Parallel()

	cfg := TunnelQUICConfig(20 * time.Second)
	if cfg == nil {
		t.Fatal("expected config")
	}
	if cfg.MaxIdleTimeout != 20*time.Second {
		t.Fatalf("MaxIdleTimeout = %s, want %s", cfg.MaxIdleTimeout, 20*time.Second)
	}
	if cfg.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("KeepAlivePeriod = %s, want %s", cfg.KeepAlivePeriod, 10*time.Second)
	}
}

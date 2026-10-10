package config

import (
	"strings"
	"testing"
	"time"
)

func TestTURNConfig(t *testing.T) {
	for _, key := range []string{"EXPOSE_TURN_ENABLE", "EXPOSE_TURN_SECRET", "EXPOSE_TURN_PUBLIC_IP", "EXPOSE_TURN_LISTEN_UDP", "EXPOSE_TURN_LISTEN_TCP", "EXPOSE_TURN_LISTEN_TLS", "EXPOSE_TURN_HOST", "EXPOSE_TURN_REALM"} {
		t.Setenv(key, "")
	}
	cfg, err := ParseServerFlags([]string{"--domain=example.com"})
	if err != nil || cfg.TURN.Enabled {
		t.Fatalf("TURN should be disabled by default: %+v, %v", cfg.TURN, err)
	}
	t.Setenv("EXPOSE_TURN_SECRET", strings.Repeat("s", 32))
	t.Setenv("EXPOSE_TURN_PUBLIC_IP", "203.0.113.10")
	t.Setenv("EXPOSE_TURN_ENABLE", "true")
	t.Setenv("EXPOSE_TURN_LISTEN_TLS", "5349")
	cfg, err = ParseServerFlags([]string{"--domain=example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TURN.Enabled || cfg.TURN.Host != "example.com" || cfg.TURN.Realm != "example.com" || cfg.TURN.ListenTLS != ":5349" || cfg.TURN.CredentialTTL != time.Hour {
		t.Fatalf("unexpected TURN defaults: %+v", cfg.TURN)
	}
	cfg, err = ParseServerFlags([]string{"--domain=example.com", "--turn-listen-udp=off", "--turn-listen-tcp=off", "--turn-credential-ttl=5m", "--turn-host=relay.example.com"})
	if err != nil || cfg.TURN.ListenUDP != "" || cfg.TURN.ListenTCP != "" || cfg.TURN.CredentialTTL != 5*time.Minute || cfg.TURN.Host != "relay.example.com" {
		t.Fatalf("TURN flag overrides: %+v, %v", cfg.TURN, err)
	}
}

func TestTURNConfigRejectsUnsafeSettings(t *testing.T) {
	t.Setenv("EXPOSE_TURN_SECRET", strings.Repeat("s", 32))
	t.Setenv("EXPOSE_TURN_ENABLE", "true")
	t.Setenv("EXPOSE_TURN_PUBLIC_IP", "203.0.113.10")
	for _, args := range [][]string{
		{"--turn-public-ip=invalid"}, {"--turn-public-ip=::1"}, {"--turn-public-ip=0.0.0.0"},
		{"--turn-public-ip=224.0.0.1"}, {"--turn-public-ip=255.255.255.255"},
		{"--turn-min-port=0"}, {"--turn-min-port=50000", "--turn-max-port=49000"}, {"--turn-max-port=65536"},
		{"--turn-max-allocations=0"}, {"--turn-max-connections=-1"},
		{"--turn-credential-ttl=0s"}, {"--turn-credential-ttl=25h"},
		{"--turn-host=https://relay.example.com"}, {"--turn-host=relay.example.com:3478"},
		{"--turn-listen-tls=:3478"}, {"--turn-listen-tcp=invalid"}, {"--turn-listen-udp=:65536"},
		{"--turn-listen-udp=off", "--turn-listen-tcp=off"}, {"--turn-relay-address=::"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := ParseServerFlags(append([]string{"--domain=example.com"}, args...)); err == nil {
				t.Fatal("accepted invalid TURN config")
			}
		})
	}
	t.Setenv("EXPOSE_TURN_SECRET", "short")
	if _, err := ParseServerFlags([]string{"--domain=example.com"}); err == nil {
		t.Fatal("accepted weak TURN secret")
	}
	t.Setenv("EXPOSE_TURN_ENABLE", "typo")
	if _, err := ParseServerFlags([]string{"--domain=example.com"}); err == nil {
		t.Fatal("accepted malformed boolean")
	}
}

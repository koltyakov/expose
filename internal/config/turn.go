package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TURNConfig configures the optional public WebRTC relay, independent of HTTP tunnels.
type TURNConfig struct {
	Enabled        bool
	ListenUDP      string
	ListenTCP      string
	ListenTLS      string
	PublicIP       string
	Host           string
	Secret         string
	Realm          string
	RelayAddress   string
	MinPort        int
	MaxPort        int
	MaxAllocations int
	MaxConnections int
	CredentialTTL  time.Duration
}

func turnConfigFromEnv(errs *[]error) TURNConfig {
	return TURNConfig{
		Enabled:        envBool("EXPOSE_TURN_ENABLE", false, errs),
		ListenUDP:      EnvOrDefault("EXPOSE_TURN_LISTEN_UDP", ":3478"),
		ListenTCP:      EnvOrDefault("EXPOSE_TURN_LISTEN_TCP", ":3478"),
		ListenTLS:      EnvOrDefault("EXPOSE_TURN_LISTEN_TLS", ""),
		PublicIP:       EnvOrDefault("EXPOSE_TURN_PUBLIC_IP", ""),
		Host:           EnvOrDefault("EXPOSE_TURN_HOST", ""),
		Secret:         EnvOrDefault("EXPOSE_TURN_SECRET", ""),
		Realm:          EnvOrDefault("EXPOSE_TURN_REALM", ""),
		RelayAddress:   EnvOrDefault("EXPOSE_TURN_RELAY_ADDRESS", "0.0.0.0"),
		MinPort:        envInt("EXPOSE_TURN_MIN_PORT", 49160, errs),
		MaxPort:        envInt("EXPOSE_TURN_MAX_PORT", 49200, errs),
		MaxAllocations: envInt("EXPOSE_TURN_MAX_ALLOCATIONS", 128, errs),
		MaxConnections: envInt("EXPOSE_TURN_MAX_CONNECTIONS", 128, errs),
		CredentialTTL:  envDuration("EXPOSE_TURN_CREDENTIAL_TTL", time.Hour, errs),
	}
}

func (c *TURNConfig) registerFlags(fs *flag.FlagSet) {
	fs.BoolVar(&c.Enabled, "turn", c.Enabled, "Enable the public TURN relay")
	fs.StringVar(&c.ListenUDP, "turn-listen-udp", c.ListenUDP, "TURN UDP listen address (off disables)")
	fs.StringVar(&c.ListenTCP, "turn-listen-tcp", c.ListenTCP, "TURN TCP listen address (off disables)")
	fs.StringVar(&c.ListenTLS, "turn-listen-tls", c.ListenTLS, "Optional TURN TLS listen address, separate from HTTPS")
	fs.StringVar(&c.PublicIP, "turn-public-ip", c.PublicIP, "Public IPv4 advertised in TURN allocations")
	fs.StringVar(&c.Host, "turn-host", c.Host, "Public TURN hostname (default: base domain)")
	fs.StringVar(&c.Realm, "turn-realm", c.Realm, "TURN authentication realm (default: base domain)")
	fs.StringVar(&c.RelayAddress, "turn-relay-address", c.RelayAddress, "Local IPv4 address for relay sockets")
	fs.IntVar(&c.MinPort, "turn-min-port", c.MinPort, "First UDP relay allocation port")
	fs.IntVar(&c.MaxPort, "turn-max-port", c.MaxPort, "Last UDP relay allocation port")
	fs.IntVar(&c.MaxAllocations, "turn-max-allocations", c.MaxAllocations, "Maximum concurrent TURN allocations")
	fs.IntVar(&c.MaxConnections, "turn-max-connections", c.MaxConnections, "Maximum concurrent TURN TCP/TLS connections")
	fs.DurationVar(&c.CredentialTTL, "turn-credential-ttl", c.CredentialTTL, "Lifetime of issued TURN credentials (1m to 24h)")
}

func (c *TURNConfig) normalizeAndValidate(baseDomain string) error {
	c.Host = strings.ToLower(trimOrDefault(c.Host, baseDomain))
	c.Realm = trimOrDefault(c.Realm, baseDomain)
	c.PublicIP = strings.TrimSpace(c.PublicIP)
	c.RelayAddress = strings.TrimSpace(c.RelayAddress)
	c.Secret = strings.TrimSpace(c.Secret)
	for _, addr := range []*string{&c.ListenUDP, &c.ListenTCP, &c.ListenTLS} {
		*addr = normalizeListenAddr(*addr)
		if strings.EqualFold(*addr, "off") {
			*addr = ""
		}
	}
	if !c.Enabled {
		return nil
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("TURN config: %w", err)
	}
	return nil
}

// Validate is also used by relay startup, so programmatic callers cannot bypass checks.
func (c TURNConfig) Validate() error {
	if len(c.Secret) < 32 {
		return errors.New("EXPOSE_TURN_SECRET must contain at least 32 characters")
	}
	ip := net.ParseIP(c.PublicIP)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return errors.New("turn public IP must be a unicast IPv4 address")
	}
	bind := net.ParseIP(c.RelayAddress)
	if bind == nil || bind.To4() == nil || bind.IsMulticast() || bind.Equal(net.IPv4bcast) {
		return errors.New("turn relay address must be a local IPv4 address")
	}
	if err := ValidateDomainHost(c.Host); err != nil || strings.ContainsAny(c.Host, ":/") {
		return errors.New("turn host must be a hostname or IPv4 address, without a scheme or port")
	}
	if c.Realm == "" || len(c.Realm) > 128 {
		return errors.New("turn realm must contain 1 to 128 characters")
	}
	if c.MinPort < 1024 || c.MaxPort > 65535 || c.MaxPort < c.MinPort {
		return errors.New("turn relay ports must be an ordered range between 1024 and 65535")
	}
	if c.MaxAllocations <= 0 || c.MaxConnections <= 0 {
		return errors.New("turn allocation and connection limits must be > 0")
	}
	if c.CredentialTTL < time.Minute || c.CredentialTTL > 24*time.Hour {
		return errors.New("turn credential TTL must be between 1m and 24h")
	}
	if c.ListenUDP == "" && c.ListenTCP == "" && c.ListenTLS == "" {
		return errors.New("at least one TURN listener must be enabled")
	}
	for _, addr := range []string{c.ListenUDP, c.ListenTCP, c.ListenTLS} {
		if addr == "" {
			continue
		}
		_, port, err := net.SplitHostPort(addr)
		p, numErr := strconv.Atoi(port)
		if err != nil || numErr != nil || p < 0 || p > 65535 {
			return fmt.Errorf("invalid turn listen address %q", addr)
		}
	}
	if c.ListenTCP != "" && c.ListenTCP == c.ListenTLS && !strings.HasSuffix(c.ListenTCP, ":0") {
		return errors.New("TURN TCP and TLS listeners must use different addresses")
	}
	return nil
}

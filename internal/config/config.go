// Package config defines the configuration structs and flag/env parsing
// for the expose server and client.
package config

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/netutil"
)

// ClientConfig holds all settings required by the tunnel client.
type ClientConfig struct {
	ServerURL    string
	APIKey       string
	User         string
	Password     string
	Protect      bool
	LocalPort    int
	Name         string
	Timeout      time.Duration
	PingInterval time.Duration
}

// ServerConfig holds all settings required by the expose HTTPS server.
type ServerConfig struct {
	ListenHTTPS            string
	ListenHTTP             string
	DBPath                 string
	DBMaxOpenConns         int
	DBMaxIdleConns         int
	BaseDomain             string
	APIKeyPepper           string
	TLSMode                string
	CertCacheDir           string
	TLSCertFile            string
	TLSKeyFile             string
	LogLevel               string
	RequestTimeout         time.Duration
	MaxBodyBytes           int64
	ConnectTokenTTL        time.Duration
	MaxActivePerKey        int
	ClientPingTimeout      time.Duration
	HeartbeatCheckInterval time.Duration
	CleanupInterval        time.Duration
	TempRetention          time.Duration
	WAFEnabled             bool

	// Timeout and pool tuning (optional — zero values fall back to sane
	// defaults defined in the server package).
	HTTPSReadTimeout  time.Duration
	HTTPSWriteTimeout time.Duration
	HTTPSIdleTimeout  time.Duration
	ShutdownDrainTime time.Duration
	ShutdownWaitTime  time.Duration
}

const defaultClientPingInterval = 30 * time.Second
const defaultServerClientPingTimeout = 3 * time.Minute
const defaultServerHeartbeatCheckInterval = 30 * time.Second
const defaultServerCleanupInterval = 10 * time.Minute
const defaultServerTempRetention = 24 * time.Hour
const defaultServerHTTPSListen = ":10443"
const defaultServerHTTPChallengeListen = ":10080"
const defaultServerDBPath = "./expose.db"
const defaultServerCertCacheDir = "./cert"

// ParseClientFlags parses CLI flags and env vars into a [ClientConfig].
func ParseClientFlags(args []string) (ClientConfig, error) {
	cfg := ClientConfig{
		ServerURL:    envOrDefault("EXPOSE_DOMAIN", ""),
		APIKey:       envOrDefault("EXPOSE_API_KEY", ""),
		User:         envOrDefault("EXPOSE_USER", "admin"),
		Password:     envOrDefault("EXPOSE_PASSWORD", ""),
		LocalPort:    envIntOrDefault("EXPOSE_PORT", 0),
		Name:         envOrDefault("EXPOSE_SUBDOMAIN", ""),
		Timeout:      30 * time.Second,
		PingInterval: defaultClientPingInterval,
	}

	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server public URL (e.g. https://example.com)")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.BoolVar(&cfg.Protect, "protect", cfg.Protect, "Protect this tunnel with a password challenge")
	fs.IntVar(&cfg.LocalPort, "port", cfg.LocalPort, "Local upstream port on 127.0.0.1")
	fs.StringVar(&cfg.Name, "domain", cfg.Name, "Requested tunnel subdomain (e.g. myapp)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.User = trimOrDefault(cfg.User, "admin")
	cfg.Password = strings.TrimSpace(cfg.Password)
	if cfg.LocalPort == 0 {
		return cfg, errors.New("missing --port or EXPOSE_PORT")
	}
	if cfg.LocalPort <= 0 || cfg.LocalPort > 65535 {
		return cfg, errors.New("local port must be between 1 and 65535")
	}
	if len(cfg.Password) > 256 {
		return cfg, errors.New("password must be at most 256 characters")
	}
	cfg.Protect = cfg.Protect || cfg.Password != ""

	return cfg, nil
}

// ParseServerFlags parses CLI flags and env vars into a [ServerConfig].
func ParseServerFlags(args []string) (ServerConfig, error) {
	cfg := ServerConfig{
		ListenHTTPS:            envOrDefault("EXPOSE_LISTEN_HTTPS", defaultServerHTTPSListen),
		ListenHTTP:             envOrDefault("EXPOSE_LISTEN_HTTP_CHALLENGE", defaultServerHTTPChallengeListen),
		DBPath:                 envOrDefault("EXPOSE_DB_PATH", defaultServerDBPath),
		DBMaxOpenConns:         envIntOrDefault("EXPOSE_DB_MAX_OPEN_CONNS", 1),
		DBMaxIdleConns:         envIntOrDefault("EXPOSE_DB_MAX_IDLE_CONNS", 1),
		BaseDomain:             envOrDefault("EXPOSE_DOMAIN", ""),
		APIKeyPepper:           envOrDefault("EXPOSE_API_KEY_PEPPER", ""),
		TLSMode:                envOrDefault("EXPOSE_TLS_MODE", "auto"),
		CertCacheDir:           envOrDefault("EXPOSE_CERT_CACHE_DIR", defaultServerCertCacheDir),
		TLSCertFile:            envOrDefault("EXPOSE_TLS_CERT_FILE", ""),
		TLSKeyFile:             envOrDefault("EXPOSE_TLS_KEY_FILE", ""),
		LogLevel:               envOrDefault("EXPOSE_LOG_LEVEL", "info"),
		RequestTimeout:         30 * time.Second,
		MaxBodyBytes:           10 * 1024 * 1024,
		ConnectTokenTTL:        60 * time.Second,
		MaxActivePerKey:        5,
		ClientPingTimeout:      defaultServerClientPingTimeout,
		HeartbeatCheckInterval: defaultServerHeartbeatCheckInterval,
		CleanupInterval:        defaultServerCleanupInterval,
		TempRetention:          defaultServerTempRetention,
		WAFEnabled:             envBoolOrDefault("EXPOSE_WAF_ENABLE", true),
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.ListenHTTPS, "listen", cfg.ListenHTTPS, "HTTPS listen address")
	fs.StringVar(&cfg.ListenHTTP, "http-challenge-listen", cfg.ListenHTTP, "HTTP-01 challenge listen address")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	fs.IntVar(&cfg.DBMaxOpenConns, "db-max-open-conns", cfg.DBMaxOpenConns, "SQLite max open connections")
	fs.IntVar(&cfg.DBMaxIdleConns, "db-max-idle-conns", cfg.DBMaxIdleConns, "SQLite max idle connections")
	fs.StringVar(&cfg.BaseDomain, "domain", cfg.BaseDomain, "Public base domain, e.g. example.com")
	fs.StringVar(&cfg.APIKeyPepper, "api-key-pepper", cfg.APIKeyPepper, "API key hash pepper override")
	fs.StringVar(&cfg.TLSMode, "tls-mode", cfg.TLSMode, "TLS mode: auto|dynamic|wildcard")
	fs.StringVar(&cfg.CertCacheDir, "cert-cache-dir", cfg.CertCacheDir, "TLS cert cache dir")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert-file", cfg.TLSCertFile, "Static TLS cert PEM file (optional, DNS-01 wildcard)")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key-file", cfg.TLSKeyFile, "Static TLS key PEM file (optional, DNS-01 wildcard)")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.ListenHTTPS = normalizeListenAddr(cfg.ListenHTTPS)
	cfg.ListenHTTP = normalizeListenAddr(cfg.ListenHTTP)

	cfg.BaseDomain = normalizeDomainHost(cfg.BaseDomain)
	if cfg.BaseDomain == "" {
		return cfg, errors.New("missing --domain or EXPOSE_DOMAIN")
	}
	cfg.TLSMode = normalizeLowerOrDefault(cfg.TLSMode, "auto")
	switch cfg.TLSMode {
	case "auto", "dynamic", "wildcard":
	default:
		return cfg, errors.New("tls mode must be one of: auto, dynamic, wildcard")
	}
	if cfg.ClientPingTimeout <= 0 {
		return cfg, errors.New("client ping timeout must be > 0")
	}
	if cfg.HeartbeatCheckInterval <= 0 {
		return cfg, errors.New("heartbeat check interval must be > 0")
	}
	if cfg.CleanupInterval <= 0 {
		return cfg, errors.New("cleanup interval must be > 0")
	}
	if cfg.TempRetention <= 0 {
		return cfg, errors.New("temp retention must be > 0")
	}
	if cfg.DBMaxOpenConns <= 0 {
		return cfg, errors.New("db max open conns must be > 0")
	}
	if cfg.DBMaxIdleConns <= 0 {
		return cfg, errors.New("db max idle conns must be > 0")
	}
	if cfg.DBMaxIdleConns > cfg.DBMaxOpenConns {
		return cfg, errors.New("db max idle conns must be <= db max open conns")
	}

	return cfg, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func trimOrDefault(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}

func envBoolOrDefault(key string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func normalizeLowerOrDefault(v, def string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return def
	}
	return v
}

// normalizeListenAddr accepts a listen address in several forms and returns
// a canonical "host:port" (or ":port") string suitable for net.Listen:
//
//	"10443"           → ":10443"
//	":10443"          → ":10443"
//	"0.0.0.0:10443"   → "0.0.0.0:10443"
//	"[::1]:10443"     → "[::1]:10443"
func normalizeListenAddr(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	// Already contains a colon that is part of host:port — leave as-is,
	// but if the entire value is digits-only it's a bare port number.
	if isAllDigits(v) {
		return ":" + v
	}
	if strings.HasPrefix(v, ":") {
		return v // e.g. ":10443"
	}
	// Could be "host:port" or an IPv6 bracketed address — pass through.
	return v
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func normalizeDomainHost(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		v = "https://" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return netutil.NormalizeHost(v)
	}
	if u.Host == "" {
		return netutil.NormalizeHost(u.Path)
	}
	return netutil.NormalizeHost(u.Host)
}

package config

import (
	"errors"
	"flag"
	"os"
	"strconv"
	"strings"
	"time"
)

type ClientConfig struct {
	ServerURL    string
	APIKey       string
	LocalPort    int
	Name         string
	Permanent    bool
	Timeout      time.Duration
	PingInterval time.Duration
}

type ServerConfig struct {
	ListenHTTPS            string
	ListenHTTP             string
	DBPath                 string
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
}

const defaultClientPingInterval = 5 * time.Minute
const defaultServerClientPingTimeout = 12 * time.Minute
const defaultServerHeartbeatCheckInterval = 30 * time.Second
const defaultServerCleanupInterval = 10 * time.Minute
const defaultServerTempRetention = 24 * time.Hour
const defaultServerHTTPSListen = ":10443"
const defaultServerHTTPChallengeListen = ":10080"
const defaultServerDBPath = "./expose.db"
const defaultServerCertCacheDir = "./cert"

func ParseClientFlags(args []string) (ClientConfig, error) {
	cfg := ClientConfig{
		ServerURL:    envOrDefault("EXPOSE_DOMAIN", ""),
		APIKey:       envOrDefault("EXPOSE_API_KEY", ""),
		LocalPort:    envIntOrDefault("EXPOSE_PORT", 0),
		Name:         envOrDefault("EXPOSE_SUBDOMAIN", ""),
		Timeout:      30 * time.Second,
		PingInterval: defaultClientPingInterval,
	}

	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server public URL (e.g. https://example.com)")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.IntVar(&cfg.LocalPort, "port", cfg.LocalPort, "Local upstream port on 127.0.0.1")
	fs.StringVar(&cfg.Name, "name", cfg.Name, "Requested tunnel name (subdomain)")
	fs.StringVar(&cfg.Name, "subdomain", cfg.Name, "Requested tunnel name (subdomain)")
	fs.BoolVar(&cfg.Permanent, "permanent", false, "Reserve tunnel/domain permanently")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.Name = strings.TrimSpace(cfg.Name)
	if cfg.Name != "" {
		cfg.Permanent = true
	}
	if cfg.Permanent && cfg.Name == "" {
		return cfg, errors.New("permanent tunnel requires --name")
	}
	if cfg.LocalPort == 0 {
		return cfg, errors.New("missing --port or EXPOSE_PORT")
	}
	if cfg.LocalPort <= 0 || cfg.LocalPort > 65535 {
		return cfg, errors.New("local port must be between 1 and 65535")
	}

	return cfg, nil
}

func ParseServerFlags(args []string) (ServerConfig, error) {
	cfg := ServerConfig{
		ListenHTTPS:            envOrDefault("EXPOSE_LISTEN_HTTPS", defaultServerHTTPSListen),
		ListenHTTP:             envOrDefault("EXPOSE_LISTEN_HTTP_CHALLENGE", defaultServerHTTPChallengeListen),
		DBPath:                 envOrDefault("EXPOSE_DB_PATH", defaultServerDBPath),
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
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.ListenHTTPS, "listen", cfg.ListenHTTPS, "HTTPS listen address")
	fs.StringVar(&cfg.ListenHTTP, "http-challenge-listen", cfg.ListenHTTP, "HTTP-01 challenge listen address")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
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

	cfg.BaseDomain = normalizeDomainHost(cfg.BaseDomain)
	if cfg.BaseDomain == "" {
		return cfg, errors.New("missing --domain or EXPOSE_DOMAIN")
	}
	cfg.TLSMode = strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	if cfg.TLSMode == "" {
		cfg.TLSMode = "auto"
	}
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

func normalizeDomainHost(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	if idx := strings.Index(v, "/"); idx >= 0 {
		v = v[:idx]
	}
	if strings.Contains(v, ":") {
		parts := strings.Split(v, ":")
		v = parts[0]
	}
	return strings.TrimSuffix(v, ".")
}

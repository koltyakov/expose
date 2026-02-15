package config

import (
	"errors"
	"flag"
	"os"
	"strings"
	"time"
)

type ClientConfig struct {
	ServerURL string
	APIKey    string
	LocalURL  string
	Subdomain string
	Domain    string
	Permanent bool
	Timeout   time.Duration
}

type ServerConfig struct {
	ListenHTTPS       string
	ListenHTTP        string
	DBPath            string
	BaseDomain        string
	PublicURL         string
	APIKeyPepper      string
	CertCacheDir      string
	LogLevel          string
	RequestTimeout    time.Duration
	MaxBodyBytes      int64
	ConnectTokenTTL   time.Duration
	MaxActivePerKey   int
	AllowInsecureHTTP bool
}

func ParseClientFlags(args []string) (ClientConfig, error) {
	cfg := ClientConfig{
		ServerURL: envOrDefault("EXPOSE_SERVER_URL", ""),
		APIKey:    envOrDefault("EXPOSE_API_KEY", ""),
		LocalURL:  envOrDefault("EXPOSE_LOCAL_URL", "http://127.0.0.1:3000"),
		Subdomain: envOrDefault("EXPOSE_SUBDOMAIN", ""),
		Domain:    envOrDefault("EXPOSE_DOMAIN", ""),
		Timeout:   30 * time.Second,
	}

	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	fs.StringVar(&cfg.ServerURL, "server", cfg.ServerURL, "Server public URL (e.g. https://tunnel.example.com)")
	fs.StringVar(&cfg.APIKey, "api-key", cfg.APIKey, "API key")
	fs.StringVar(&cfg.LocalURL, "local", cfg.LocalURL, "Local upstream URL")
	fs.StringVar(&cfg.Subdomain, "subdomain", cfg.Subdomain, "Requested subdomain")
	fs.StringVar(&cfg.Domain, "domain", cfg.Domain, "Requested custom domain")
	fs.BoolVar(&cfg.Permanent, "permanent", false, "Reserve tunnel/domain permanently")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.ServerURL == "" {
		return cfg, errors.New("missing --server or EXPOSE_SERVER_URL")
	}
	if cfg.APIKey == "" {
		return cfg, errors.New("missing --api-key or EXPOSE_API_KEY")
	}
	if cfg.Permanent && cfg.Subdomain == "" && cfg.Domain == "" {
		return cfg, errors.New("permanent tunnel requires --subdomain or --domain")
	}

	return cfg, nil
}

func ParseServerFlags(args []string) (ServerConfig, error) {
	cfg := ServerConfig{
		ListenHTTPS:     envOrDefault("EXPOSE_LISTEN_HTTPS", ":443"),
		ListenHTTP:      envOrDefault("EXPOSE_LISTEN_HTTP_CHALLENGE", ":80"),
		DBPath:          envOrDefault("EXPOSE_DB_PATH", "./expose.db"),
		BaseDomain:      envOrDefault("EXPOSE_BASE_DOMAIN", ""),
		PublicURL:       envOrDefault("EXPOSE_PUBLIC_URL", ""),
		APIKeyPepper:    envOrDefault("EXPOSE_API_KEY_PEPPER", ""),
		CertCacheDir:    envOrDefault("EXPOSE_CERT_CACHE_DIR", "./cert-cache"),
		LogLevel:        envOrDefault("EXPOSE_LOG_LEVEL", "info"),
		RequestTimeout:  30 * time.Second,
		MaxBodyBytes:    10 * 1024 * 1024,
		ConnectTokenTTL: 60 * time.Second,
		MaxActivePerKey: 5,
	}

	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.ListenHTTPS, "listen", cfg.ListenHTTPS, "HTTPS listen address")
	fs.StringVar(&cfg.ListenHTTP, "http-challenge-listen", cfg.ListenHTTP, "HTTP-01 challenge listen address")
	fs.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	fs.StringVar(&cfg.BaseDomain, "base-domain", cfg.BaseDomain, "Base domain")
	fs.StringVar(&cfg.PublicURL, "public-url", cfg.PublicURL, "Public server URL")
	fs.StringVar(&cfg.APIKeyPepper, "api-key-pepper", cfg.APIKeyPepper, "API key hash pepper")
	fs.StringVar(&cfg.CertCacheDir, "cert-cache-dir", cfg.CertCacheDir, "TLS cert cache dir")
	fs.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level: debug|info|warn|error")
	fs.BoolVar(&cfg.AllowInsecureHTTP, "insecure-http", false, "Run HTTP only (no ACME/TLS)")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.BaseDomain == "" {
		return cfg, errors.New("missing --base-domain or EXPOSE_BASE_DOMAIN")
	}
	if cfg.APIKeyPepper == "" {
		return cfg, errors.New("missing --api-key-pepper or EXPOSE_API_KEY_PEPPER")
	}
	if cfg.PublicURL == "" {
		scheme := "https://"
		if cfg.AllowInsecureHTTP {
			scheme = "http://"
		}
		cfg.PublicURL = scheme + strings.TrimPrefix(cfg.BaseDomain, "*.")
	}

	return cfg, nil
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

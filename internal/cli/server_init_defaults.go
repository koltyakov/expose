package cli

import (
	"context"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

func loadServerInitDefaults(envFile string) serverInitAnswers {
	fileValues := loadEnvFileValues(envFile)
	valueOrDefault := func(key, def string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		if v := strings.TrimSpace(fileValues[key]); v != "" {
			return v
		}
		return def
	}

	tlsMode := normalizeWizardTLSMode(valueOrDefault("EXPOSE_TLS_MODE", "dynamic"))
	switch tlsMode {
	case "dynamic", "wildcard":
	default:
		tlsMode = "dynamic"
	}
	pepper := strings.TrimSpace(valueOrDefault("EXPOSE_API_KEY_PEPPER", ""))
	if pepper == "" {
		pepper = strings.TrimSpace(detectInitMachineID())
	}

	return serverInitAnswers{
		BaseDomain:   normalizeWizardDomain(valueOrDefault("EXPOSE_DOMAIN", "")),
		ListenHTTPS:  strings.TrimSpace(valueOrDefault("EXPOSE_LISTEN_HTTPS", ":10443")),
		ListenHTTP:   strings.TrimSpace(valueOrDefault("EXPOSE_LISTEN_HTTP_CHALLENGE", ":10080")),
		DBPath:       strings.TrimSpace(valueOrDefault("EXPOSE_DB_PATH", "./expose.db")),
		TLSMode:      tlsMode,
		CertCacheDir: strings.TrimSpace(valueOrDefault("EXPOSE_CERT_CACHE_DIR", "./cert")),
		TLSCertFile:  strings.TrimSpace(valueOrDefault("EXPOSE_TLS_CERT_FILE", "./cert/wildcard.crt")),
		TLSKeyFile:   strings.TrimSpace(valueOrDefault("EXPOSE_TLS_KEY_FILE", "./cert/wildcard.key")),
		LogLevel:     normalizeWizardLogLevel(valueOrDefault("EXPOSE_LOG_LEVEL", "info")),
		APIKeyPepper: pepper,
	}
}

func detectInitMachineID() string {
	return detectMachineID()
}

func resolveInitPepperDefault(ctx context.Context, dbPath, fallback string) string {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return strings.TrimSpace(fallback)
	}
	store, err := sqlite.Open(dbPath)
	if err != nil {
		return strings.TrimSpace(fallback)
	}
	defer func() { _ = store.Close() }()

	if current, exists, err := store.GetServerPepper(ctx); err == nil && exists {
		if v := strings.TrimSpace(current); v != "" {
			return v
		}
	}
	return strings.TrimSpace(fallback)
}

func createInitAPIKey(ctx context.Context, dbPath, pepper, name string) (string, error) {
	store, err := sqlite.Open(dbPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = store.Close() }()

	resolvedPepper, err := resolveServerPepper(ctx, store, pepper)
	if err != nil {
		return "", err
	}

	plain, err := auth.GenerateAPIKey()
	if err != nil {
		return "", err
	}
	if _, err := store.CreateAPIKey(ctx, strings.TrimSpace(name), auth.HashAPIKey(plain, resolvedPepper)); err != nil {
		return "", err
	}
	return plain, nil
}

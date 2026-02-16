package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/koltyakov/expose/internal/config"
)

func TestLoadServerEnvFromDotEnvLoadsMissingExposeVars(t *testing.T) {
	clearServerEnvVarsForTest(t)
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("EXPOSE_DOMAIN=from-file.example.com\nOTHER_VAR=skip\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loadServerEnvFromDotEnv(envPath)

	if got := os.Getenv("EXPOSE_DOMAIN"); got != "from-file.example.com" {
		t.Fatalf("expected EXPOSE_DOMAIN loaded from file, got %q", got)
	}
	if got := os.Getenv("OTHER_VAR"); got != "" {
		t.Fatalf("expected non-EXPOSE var not to be loaded, got %q", got)
	}
}

func TestLoadServerEnvFromDotEnvKeepsExistingEnv(t *testing.T) {
	clearServerEnvVarsForTest(t)
	t.Setenv("EXPOSE_DOMAIN", "from-env.example.com")
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("EXPOSE_DOMAIN=from-file.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loadServerEnvFromDotEnv(envPath)

	if got := os.Getenv("EXPOSE_DOMAIN"); got != "from-env.example.com" {
		t.Fatalf("expected existing env to win, got %q", got)
	}
}

func TestServerConfigPrefersCLIFlagsOverDotEnv(t *testing.T) {
	clearServerEnvVarsForTest(t)
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("EXPOSE_DOMAIN=from-file.example.com\nEXPOSE_DB_PATH=./from-file.db\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loadServerEnvFromDotEnv(envPath)
	cfg, err := config.ParseServerFlags([]string{"--domain", "from-cli.example.com", "--db", "./from-cli.db"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseDomain != "from-cli.example.com" {
		t.Fatalf("expected CLI domain to win, got %q", cfg.BaseDomain)
	}
	if cfg.DBPath != "./from-cli.db" {
		t.Fatalf("expected CLI db path to win, got %q", cfg.DBPath)
	}
}

func clearServerEnvVarsForTest(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"EXPOSE_DOMAIN",
		"EXPOSE_LISTEN_HTTPS",
		"EXPOSE_LISTEN_HTTP_CHALLENGE",
		"EXPOSE_DB_PATH",
		"EXPOSE_TLS_MODE",
		"EXPOSE_CERT_CACHE_DIR",
		"EXPOSE_TLS_CERT_FILE",
		"EXPOSE_TLS_KEY_FILE",
		"EXPOSE_LOG_LEVEL",
		"EXPOSE_API_KEY_PEPPER",
		"OTHER_VAR",
	} {
		t.Setenv(k, "")
	}
}

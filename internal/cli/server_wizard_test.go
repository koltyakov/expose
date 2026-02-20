package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/store/sqlite"
)

func TestBuildWizardEnvEntriesDynamic(t *testing.T) {
	entries := buildWizardEnvEntries(serverWizardAnswers{
		BaseDomain:   "example.com",
		ListenHTTPS:  ":10443",
		ListenHTTP:   ":10080",
		DBPath:       "./expose.db",
		TLSMode:      "dynamic",
		CertCacheDir: "./cert",
		LogLevel:     "info",
		APIKeyPepper: "machine-id",
	})

	if !hasEnvEntry(entries, "EXPOSE_LISTEN_HTTP_CHALLENGE") {
		t.Fatalf("expected EXPOSE_LISTEN_HTTP_CHALLENGE for non-wildcard mode")
	}
	if hasEnvEntry(entries, "EXPOSE_TLS_CERT_FILE") {
		t.Fatalf("did not expect EXPOSE_TLS_CERT_FILE for non-wildcard mode")
	}
	if hasEnvEntry(entries, "EXPOSE_TLS_KEY_FILE") {
		t.Fatalf("did not expect EXPOSE_TLS_KEY_FILE for non-wildcard mode")
	}

	gotOrder := envEntryKeys(entries)
	wantOrder := []string{
		"EXPOSE_DOMAIN",
		"EXPOSE_LISTEN_HTTPS",
		"EXPOSE_TLS_MODE",
		"EXPOSE_LISTEN_HTTP_CHALLENGE",
		"EXPOSE_DB_PATH",
		"EXPOSE_CERT_CACHE_DIR",
		"EXPOSE_LOG_LEVEL",
		"EXPOSE_API_KEY_PEPPER",
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("unexpected dynamic entry order\nwant=%v\ngot=%v", wantOrder, gotOrder)
	}
}

func TestBuildWizardEnvEntriesWildcard(t *testing.T) {
	entries := buildWizardEnvEntries(serverWizardAnswers{
		BaseDomain:   "example.com",
		ListenHTTPS:  ":10443",
		DBPath:       "./expose.db",
		TLSMode:      "wildcard",
		CertCacheDir: "./cert",
		TLSCertFile:  "./cert/wildcard.crt",
		TLSKeyFile:   "./cert/wildcard.key",
		LogLevel:     "info",
		APIKeyPepper: "machine-id",
	})

	if hasEnvEntry(entries, "EXPOSE_LISTEN_HTTP_CHALLENGE") {
		t.Fatalf("did not expect EXPOSE_LISTEN_HTTP_CHALLENGE for wildcard mode")
	}
	if !hasEnvEntry(entries, "EXPOSE_TLS_CERT_FILE") {
		t.Fatalf("expected EXPOSE_TLS_CERT_FILE for wildcard mode")
	}
	if !hasEnvEntry(entries, "EXPOSE_TLS_KEY_FILE") {
		t.Fatalf("expected EXPOSE_TLS_KEY_FILE for wildcard mode")
	}

	gotOrder := envEntryKeys(entries)
	wantOrder := []string{
		"EXPOSE_DOMAIN",
		"EXPOSE_LISTEN_HTTPS",
		"EXPOSE_TLS_MODE",
		"EXPOSE_DB_PATH",
		"EXPOSE_CERT_CACHE_DIR",
		"EXPOSE_TLS_CERT_FILE",
		"EXPOSE_TLS_KEY_FILE",
		"EXPOSE_LOG_LEVEL",
		"EXPOSE_API_KEY_PEPPER",
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("unexpected wildcard entry order\nwant=%v\ngot=%v", wantOrder, gotOrder)
	}
}

func TestUpsertEnvFileUpdatesAndAppends(t *testing.T) {
	tmp := t.TempDir()
	envPath := filepath.Join(tmp, ".env")
	initial := "# existing\nEXPOSE_DOMAIN=old.example.com\nOTHER_KEEP=1\n"
	if err := os.WriteFile(envPath, []byte(initial), 0o644); err != nil {
		t.Fatal(err)
	}

	err := upsertEnvFile(envPath, []envEntry{
		{Key: "EXPOSE_DOMAIN", Value: "new.example.com"},
		{Key: "EXPOSE_DB_PATH", Value: "./expose.db"},
	})
	if err != nil {
		t.Fatal(err)
	}

	updated, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(updated)

	if !strings.Contains(content, "EXPOSE_DOMAIN=new.example.com") {
		t.Fatalf("expected updated domain in .env, got:\n%s", content)
	}
	if !strings.Contains(content, "OTHER_KEEP=1") {
		t.Fatalf("expected unrelated settings to be preserved, got:\n%s", content)
	}
	if !strings.Contains(content, "EXPOSE_DB_PATH=./expose.db") {
		t.Fatalf("expected new key to be appended, got:\n%s", content)
	}
}

func TestParseEnvAssignment(t *testing.T) {
	key, value, ok := parseEnvAssignment("export EXPOSE_DOMAIN=example.com")
	if !ok {
		t.Fatal("expected assignment to be parsed")
	}
	if key != "EXPOSE_DOMAIN" {
		t.Fatalf("expected EXPOSE_DOMAIN, got %s", key)
	}
	if value != "example.com" {
		t.Fatalf("expected example.com, got %s", value)
	}

	if _, _, ok := parseEnvAssignment("# comment"); ok {
		t.Fatal("expected comments to be ignored")
	}
}

func TestValidateWizardTLSMode(t *testing.T) {
	if err := validateWizardTLSMode("dynamic"); err != nil {
		t.Fatalf("expected dynamic to be valid: %v", err)
	}
	if err := validateWizardTLSMode("wildcard"); err != nil {
		t.Fatalf("expected wildcard to be valid: %v", err)
	}
	if err := validateWizardTLSMode("auto"); err == nil {
		t.Fatal("expected auto to be invalid in wizard")
	}
}

func TestLoadServerWizardDefaults(t *testing.T) {
	clearWizardEnvForTest(t)
	t.Setenv("EXPOSE_TLS_MODE", "")
	defaults := loadServerWizardDefaults(filepath.Join(t.TempDir(), ".env"))
	if defaults.TLSMode != "dynamic" {
		t.Fatalf("expected default TLS mode dynamic, got %s", defaults.TLSMode)
	}
	if defaults.BaseDomain != "" {
		t.Fatalf("expected empty default domain, got %q", defaults.BaseDomain)
	}
}

func TestLoadServerWizardDefaultsFromEnvFile(t *testing.T) {
	clearWizardEnvForTest(t)
	envPath := filepath.Join(t.TempDir(), ".env")
	envContent := strings.Join([]string{
		"EXPOSE_DOMAIN=from-file.example.com",
		"EXPOSE_TLS_MODE=wildcard",
		"EXPOSE_DB_PATH=./file.db",
		"EXPOSE_LISTEN_HTTPS=:443",
		"",
	}, "\n")
	if err := os.WriteFile(envPath, []byte(envContent), 0o644); err != nil {
		t.Fatal(err)
	}

	defaults := loadServerWizardDefaults(envPath)
	if defaults.BaseDomain != "from-file.example.com" {
		t.Fatalf("expected domain from .env file, got %q", defaults.BaseDomain)
	}
	if defaults.TLSMode != "wildcard" {
		t.Fatalf("expected tls mode wildcard from .env file, got %s", defaults.TLSMode)
	}
	if defaults.DBPath != "./file.db" {
		t.Fatalf("expected db path from .env file, got %s", defaults.DBPath)
	}
	if defaults.ListenHTTPS != ":443" {
		t.Fatalf("expected https listen from .env file, got %s", defaults.ListenHTTPS)
	}
}

func TestLoadServerWizardDefaultsEnvOverridesFile(t *testing.T) {
	clearWizardEnvForTest(t)
	envPath := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(envPath, []byte("EXPOSE_TLS_MODE=wildcard\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPOSE_TLS_MODE", "dynamic")

	defaults := loadServerWizardDefaults(envPath)
	if defaults.TLSMode != "dynamic" {
		t.Fatalf("expected process env to override .env file, got %s", defaults.TLSMode)
	}
}

func TestParseDarwinIOPlatformUUID(t *testing.T) {
	raw := `
{
  "IOPlatformUUID" = "4A1E0F6D-3E34-53FC-8D79-A99B6A36C8D0"
}
`
	got := parseDarwinIOPlatformUUID(raw)
	want := "4A1E0F6D-3E34-53FC-8D79-A99B6A36C8D0"
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}

	if got := parseDarwinIOPlatformUUID("no uuid here"); got != "" {
		t.Fatalf("expected empty result for missing uuid, got %s", got)
	}
}

func TestResolveWizardPepperDefaultFromDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "expose.db")
	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.ResolveServerPepper(ctx, "db-pepper"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	got := resolveWizardPepperDefault(ctx, dbPath, "fallback-pepper")
	if got != "db-pepper" {
		t.Fatalf("expected db pepper, got %q", got)
	}
}

func TestResolveWizardPepperDefaultFallback(t *testing.T) {
	ctx := context.Background()
	got := resolveWizardPepperDefault(ctx, filepath.Join(t.TempDir(), "missing.db"), "fallback-pepper")
	if got != "fallback-pepper" {
		t.Fatalf("expected fallback pepper, got %q", got)
	}
}

func TestRunServerWizardInteractiveCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	inR, inW := io.Pipe()
	defer func() { _ = inR.Close() }()
	defer func() { _ = inW.Close() }()

	var out bytes.Buffer
	err := runServerWizardInteractive(ctx, inR, &out, filepath.Join(t.TempDir(), ".env"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func hasEnvEntry(entries []envEntry, key string) bool {
	for _, e := range entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

func envEntryKeys(entries []envEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Key)
	}
	return out
}

func clearWizardEnvForTest(t *testing.T) {
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
	} {
		t.Setenv(k, "")
	}
}

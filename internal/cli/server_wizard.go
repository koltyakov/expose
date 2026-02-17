package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/netutil"
	"github.com/koltyakov/expose/internal/store/sqlite"
)

type serverWizardAnswers struct {
	BaseDomain    string
	ListenHTTPS   string
	ListenHTTP    string
	DBPath        string
	TLSMode       string
	CertCacheDir  string
	TLSCertFile   string
	TLSKeyFile    string
	LogLevel      string
	APIKeyPepper  string
	GenerateKey   bool
	APIKeyName    string
	GeneratedKey  string
	GeneratedName string
}

type envEntry struct {
	Key   string
	Value string
}

func runServerWizard(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("server-wizard", flag.ContinueOnError)
	envFile := ".env"
	fs.StringVar(&envFile, "env-file", envFile, "path to .env output file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: expose server wizard [--env-file=.env]")
		return 2
	}
	if !isInteractiveInput() {
		fmt.Fprintln(os.Stderr, "server wizard error: interactive terminal required")
		return 2
	}

	if err := runServerWizardInteractive(ctx, os.Stdin, os.Stdout, envFile); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "server wizard canceled")
			return 130
		}
		fmt.Fprintln(os.Stderr, "server wizard error:", err)
		return 1
	}
	return 0
}

func runServerWizardInteractive(ctx context.Context, in io.Reader, out io.Writer, envFile string) error {
	reader := bufio.NewReader(in)
	defaults := loadServerWizardDefaults(envFile)

	_, _ = fmt.Fprintln(out, "Expose Server Wizard")
	_, _ = fmt.Fprintln(out, "Press Enter to accept defaults. Values are saved to .env for future runs.")
	_, _ = fmt.Fprintln(out)

	domain, err := askWizardValue(ctx, reader, out,
		"Base domain",
		"Public base domain used by the server to issue tunnel URLs (required).",
		"Example: example.com -> tunnel URL looks like https://myapp.example.com",
		defaults.BaseDomain,
		normalizeWizardDomain,
		validateWizardDomain,
	)
	if err != nil {
		return err
	}

	listenHTTPS, err := askWizardValue(ctx, reader, out,
		"HTTPS listen address",
		"Address for public HTTPS traffic.",
		"Example: :10443 (then forward external 443 -> 10443)",
		defaults.ListenHTTPS,
		strings.TrimSpace,
		validateWizardNonEmpty,
	)
	if err != nil {
		return err
	}

	tlsMode, err := askWizardValue(ctx, reader, out,
		"TLS mode",
		"dynamic = per-host ACME, wildcard = static wildcard certs only.",
		"Allowed: dynamic | wildcard",
		defaults.TLSMode,
		normalizeWizardTLSMode,
		validateWizardTLSMode,
	)
	if err != nil {
		return err
	}

	listenHTTP := ""
	if tlsMode != "wildcard" {
		listenHTTP, err = askWizardValue(ctx, reader, out,
			"HTTP challenge listen address",
			"Address for ACME HTTP-01 challenges when using dynamic TLS.",
			"Example: :10080 (then forward external 80 -> 10080)",
			defaults.ListenHTTP,
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
	}

	dbPath, err := askWizardValue(ctx, reader, out,
		"SQLite DB path",
		"File path where API keys, domains, and tunnels are stored.",
		"Example: ./expose.db",
		defaults.DBPath,
		strings.TrimSpace,
		validateWizardNonEmpty,
	)
	if err != nil {
		return err
	}

	certCacheDir, err := askWizardValue(ctx, reader, out,
		"Certificate cache directory",
		"Directory used for ACME certificates and fallback cert files.",
		"Example: ./cert",
		defaults.CertCacheDir,
		strings.TrimSpace,
		validateWizardNonEmpty,
	)
	if err != nil {
		return err
	}

	tlsCertFile := ""
	tlsKeyFile := ""
	if tlsMode == "wildcard" {
		tlsCertFile, err = askWizardValue(ctx, reader, out,
			"Wildcard cert file",
			"PEM certificate for wildcard mode. Server uses this for all matching hosts.",
			"Example: ./cert/wildcard.crt",
			defaults.TLSCertFile,
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
		tlsKeyFile, err = askWizardValue(ctx, reader, out,
			"Wildcard key file",
			"PEM private key paired with the wildcard certificate.",
			"Example: ./cert/wildcard.key",
			defaults.TLSKeyFile,
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
	}

	logLevel, err := askWizardValue(ctx, reader, out,
		"Log level",
		"Verbosity for server logs.",
		"Allowed: debug | info | warn | error",
		defaults.LogLevel,
		normalizeWizardLogLevel,
		validateWizardLogLevel,
	)
	if err != nil {
		return err
	}

	apiKeyPepperDefault := resolveWizardPepperDefault(ctx, dbPath, defaults.APIKeyPepper)
	apiKeyPepper, err := askWizardValue(ctx, reader, out,
		"API key pepper",
		"Secret salt used when hashing API keys. Default is existing DB pepper (if set), otherwise this machine ID.",
		"Press Enter to accept default. Leave empty only if you intentionally want auto-resolution.",
		apiKeyPepperDefault,
		strings.TrimSpace,
		validateWizardAny,
	)
	if err != nil {
		return err
	}

	generateKey, err := askWizardYesNo(ctx, reader, out,
		"Generate API key now",
		"Creates and stores a new key in SQLite, then writes EXPOSE_API_KEY to .env.",
		true,
	)
	if err != nil {
		return err
	}

	apiKeyName := ""
	if generateKey {
		apiKeyName, err = askWizardValue(ctx, reader, out,
			"API key name",
			"Label to help identify the key later.",
			"Example: default",
			"default",
			strings.TrimSpace,
			validateWizardNonEmpty,
		)
		if err != nil {
			return err
		}
	}

	answers := serverWizardAnswers{
		BaseDomain:   domain,
		ListenHTTPS:  listenHTTPS,
		ListenHTTP:   listenHTTP,
		DBPath:       dbPath,
		TLSMode:      tlsMode,
		CertCacheDir: certCacheDir,
		TLSCertFile:  tlsCertFile,
		TLSKeyFile:   tlsKeyFile,
		LogLevel:     logLevel,
		APIKeyPepper: apiKeyPepper,
		GenerateKey:  generateKey,
		APIKeyName:   apiKeyName,
	}

	if answers.GenerateKey {
		plain, err := createWizardAPIKey(ctx, answers.DBPath, answers.APIKeyPepper, answers.APIKeyName)
		if err != nil {
			return fmt.Errorf("generate api key: %w", err)
		}
		answers.GeneratedKey = plain
		answers.GeneratedName = answers.APIKeyName
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintf(out, "Generated API key (%s).\n", answers.APIKeyName)
	}

	entries := buildWizardEnvEntries(answers)
	if err := upsertEnvFile(envFile, entries); err != nil {
		return fmt.Errorf("write %s: %w", envFile, err)
	}

	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Saved %d settings to %s\n", len(entries), envFile)
	printWizardNextSteps(out, answers)
	return nil
}

func loadServerWizardDefaults(envFile string) serverWizardAnswers {
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
		pepper = strings.TrimSpace(detectWizardMachineID())
	}

	return serverWizardAnswers{
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

func loadEnvFileValues(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	for _, line := range lines {
		key, value, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		out[key] = value
	}
	return out
}

func detectWizardMachineID() string {
	return detectMachineID()
}

func resolveWizardPepperDefault(ctx context.Context, dbPath, fallback string) string {
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

func createWizardAPIKey(ctx context.Context, dbPath, pepper, name string) (string, error) {
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

func buildWizardEnvEntries(a serverWizardAnswers) []envEntry {
	entries := []envEntry{
		{Key: "EXPOSE_DOMAIN", Value: a.BaseDomain},
		{Key: "EXPOSE_LISTEN_HTTPS", Value: a.ListenHTTPS},
		{Key: "EXPOSE_TLS_MODE", Value: a.TLSMode},
	}
	if a.TLSMode == "wildcard" {
		entries = append(entries,
			envEntry{Key: "EXPOSE_DB_PATH", Value: a.DBPath},
			envEntry{Key: "EXPOSE_CERT_CACHE_DIR", Value: a.CertCacheDir},
			envEntry{Key: "EXPOSE_TLS_CERT_FILE", Value: a.TLSCertFile},
			envEntry{Key: "EXPOSE_TLS_KEY_FILE", Value: a.TLSKeyFile},
		)
	} else {
		entries = append(entries,
			envEntry{Key: "EXPOSE_LISTEN_HTTP_CHALLENGE", Value: a.ListenHTTP},
			envEntry{Key: "EXPOSE_DB_PATH", Value: a.DBPath},
			envEntry{Key: "EXPOSE_CERT_CACHE_DIR", Value: a.CertCacheDir},
		)
	}
	entries = append(entries,
		envEntry{Key: "EXPOSE_LOG_LEVEL", Value: a.LogLevel},
		envEntry{Key: "EXPOSE_API_KEY_PEPPER", Value: a.APIKeyPepper},
	)
	if strings.TrimSpace(a.GeneratedKey) != "" {
		entries = append(entries, envEntry{Key: "EXPOSE_API_KEY", Value: a.GeneratedKey})
	}
	return entries
}

func upsertEnvFile(path string, entries []envEntry) error {
	byKey := make(map[string]string, len(entries))
	order := make([]string, 0, len(entries))
	for _, entry := range entries {
		key := strings.TrimSpace(entry.Key)
		if key == "" {
			continue
		}
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = sanitizeEnvValue(entry.Value)
	}

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	var lines []string
	if len(raw) > 0 {
		normalized := strings.ReplaceAll(string(raw), "\r\n", "\n")
		normalized = strings.TrimRight(normalized, "\n")
		if normalized != "" {
			lines = strings.Split(normalized, "\n")
		}
	}

	updated := make(map[string]bool, len(byKey))
	for i, line := range lines {
		key, _, ok := parseEnvAssignment(line)
		if !ok {
			continue
		}
		value, wanted := byKey[key]
		if !wanted {
			continue
		}
		lines[i] = formatEnvEntry(key, value)
		updated[key] = true
	}

	pending := make([]string, 0, len(order))
	for _, key := range order {
		if !updated[key] {
			pending = append(pending, key)
		}
	}
	if len(pending) > 0 {
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
			lines = append(lines, "")
		}
		lines = append(lines, "# Added by expose server wizard")
		for _, key := range pending {
			lines = append(lines, formatEnvEntry(key, byKey[key]))
		}
	}

	if len(lines) == 0 {
		lines = append(lines, "# Added by expose server wizard")
		for _, key := range order {
			lines = append(lines, formatEnvEntry(key, byKey[key]))
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}

func parseEnvAssignmentKey(line string) (string, bool) {
	key, _, ok := parseEnvAssignment(line)
	return key, ok
}

func parseEnvAssignment(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	if strings.HasPrefix(trimmed, "export ") {
		trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "export "))
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
			(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

func formatEnvEntry(key, value string) string {
	return key + "=" + value
}

func sanitizeEnvValue(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return strings.TrimSpace(v)
}

type wizardValidator func(string) error

type wizardNormalizer func(string) string

func askWizardValue(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details, sample, def string, normalize wizardNormalizer, validate wizardValidator) (string, error) {
	for {
		_, _ = fmt.Fprintf(out, "%s\n", title)
		_, _ = fmt.Fprintf(out, "  %s\n", details)
		if strings.TrimSpace(sample) != "" {
			_, _ = fmt.Fprintf(out, "  %s\n", sample)
		}
		labelDefault := strings.TrimSpace(def)
		if labelDefault == "" {
			_, _ = fmt.Fprint(out, "  Value: ")
		} else {
			_, _ = fmt.Fprintf(out, "  Value [%s]: ", labelDefault)
		}

		line, err := readWizardLine(ctx, reader)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(line) == "" {
			line = def
		}
		if normalize != nil {
			line = normalize(line)
		}
		if validate != nil {
			if err := validate(line); err != nil {
				_, _ = fmt.Fprintf(out, "  Invalid value: %v\n\n", err)
				continue
			}
		}
		_, _ = fmt.Fprintln(out)
		return line, nil
	}
}

func askWizardYesNo(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details string, def bool) (bool, error) {
	for {
		defaultLabel := "y/N"
		if def {
			defaultLabel = "Y/n"
		}
		_, _ = fmt.Fprintf(out, "%s\n", title)
		_, _ = fmt.Fprintf(out, "  %s\n", details)
		_, _ = fmt.Fprintf(out, "  Value [%s]: ", defaultLabel)

		line, err := readWizardLine(ctx, reader)
		if err != nil {
			return false, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			_, _ = fmt.Fprintln(out)
			return def, nil
		}
		switch line {
		case "y", "yes":
			_, _ = fmt.Fprintln(out)
			return true, nil
		case "n", "no":
			_, _ = fmt.Fprintln(out)
			return false, nil
		default:
			_, _ = fmt.Fprintln(out, "  Invalid value: enter y or n")
			_, _ = fmt.Fprintln(out)
		}
	}
}

func readWizardLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	select {
	case <-ctx.Done():
		return "", context.Canceled
	default:
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func validateWizardDomain(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("domain is required")
	}
	if strings.Contains(v, "/") {
		return errors.New("domain must be a host, not a URL path")
	}
	return nil
}

func validateWizardNonEmpty(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("value is required")
	}
	return nil
}

func validateWizardAny(string) error {
	return nil
}

func validateWizardTLSMode(v string) error {
	switch v {
	case "dynamic", "wildcard":
		return nil
	default:
		return errors.New("must be one of: dynamic, wildcard")
	}
}

func validateWizardLogLevel(v string) error {
	switch v {
	case "debug", "info", "warn", "error":
		return nil
	default:
		return errors.New("must be one of: debug, info, warn, error")
	}
}

func normalizeWizardDomain(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		raw = strings.TrimPrefix(raw, "https://")
		raw = strings.TrimPrefix(raw, "http://")
	}
	raw = strings.TrimSuffix(raw, "/")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return netutil.NormalizeHost(raw)
}

func normalizeWizardTLSMode(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeWizardLogLevel(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func printWizardNextSteps(out io.Writer, a serverWizardAnswers) {
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Next steps")
	_, _ = fmt.Fprintln(out, "  1) Start the server")
	_, _ = fmt.Fprintln(out, "     expose server")

	if strings.TrimSpace(a.GeneratedKey) != "" {
		_, _ = fmt.Fprintln(out, "  2) Login client (API key was generated and saved to .env)")
		_, _ = fmt.Fprintf(out, "     expose login --server %s --api-key %s\n", a.BaseDomain, a.GeneratedKey)
	} else {
		_, _ = fmt.Fprintln(out, "  2) Create API key, then login client")
		_, _ = fmt.Fprintln(out, "     expose apikey create --name default")
		_, _ = fmt.Fprintf(out, "     expose login --server %s --api-key <PASTE_KEY>\n", a.BaseDomain)
	}
	_, _ = fmt.Fprintln(out, "  3) Expose a local app")
	_, _ = fmt.Fprintln(out, "     expose http 3000")
}

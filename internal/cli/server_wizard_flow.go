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

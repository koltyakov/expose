package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/config"
)

// clientCredSources records where each client credential came from so a
// server URL supplied by an untrusted ./.env file can never silently be
// combined with the operator's saved API key.
type clientCredSources struct {
	serverFlag       bool
	apiKeyFlag       bool
	serverConfigFile bool
	apiKeyConfigFile bool
	serverEnv        bool
	apiKeyEnv        bool
	serverDotEnv     bool
	apiKeyDotEnv     bool
	serverSettings   bool
	apiKeySettings   bool
	settingsLoaded   bool
	storedServer     string
}

// captureClientCredSources snapshots credential provenance. preEnv reports
// whether the variable existed in the real environment before ./.env was
// loaded; dotEnvKeys is the set returned by loadClientEnvFromDotEnv.
func captureClientCredSources(args []string, dotEnvKeys map[string]string, preEnvServer, preEnvAPIKey bool) clientCredSources {
	_, dotEnvServer := dotEnvKeys["EXPOSE_DOMAIN"]
	_, dotEnvAPIKey := dotEnvKeys["EXPOSE_API_KEY"]
	return clientCredSources{
		serverFlag:   cliFlagPassed(args, "server"),
		apiKeyFlag:   cliFlagPassed(args, "api-key"),
		serverEnv:    preEnvServer,
		apiKeyEnv:    preEnvAPIKey,
		serverDotEnv: dotEnvServer,
		apiKeyDotEnv: dotEnvAPIKey,
	}
}

// capturePreDotEnv records whether the credential variables were present in
// the real environment, and must be called before ./.env is loaded.
func capturePreDotEnv() (preEnvServer, preEnvAPIKey bool) {
	return hasNonEmpty(os.Getenv("EXPOSE_DOMAIN")), hasNonEmpty(os.Getenv("EXPOSE_API_KEY"))
}

// resolveClientCredentials fills any missing credentials from the saved
// settings file and then verifies that the resulting combination is
// trustworthy. Every command that consumes client credentials must go
// through here so a ./.env file can never redirect the saved API key.
func resolveClientCredentials(ctx context.Context, cfg *config.ClientConfig, src clientCredSources) error {
	src, err := mergeClientSettingsWithSources(cfg, src)
	if err != nil {
		return err
	}
	return verifyClientCredentialTrust(ctx, cfg.ServerURL, src)
}

func cliFlagPassed(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == "--"+name || arg == "-"+name ||
				strings.HasPrefix(arg, "--"+name+"=") || strings.HasPrefix(arg, "-"+name+"=") {
				return true
			}
		}
	}
	return false
}

func (s clientCredSources) describeServer() string {
	switch {
	case s.serverFlag:
		return "command-line flag --server"
	case s.serverConfigFile:
		return "up config file (server)"
	case s.serverEnv:
		return "environment variable EXPOSE_DOMAIN"
	case s.serverDotEnv:
		return "./.env file (EXPOSE_DOMAIN)"
	case s.serverSettings:
		return "saved settings file"
	default:
		return "unknown source"
	}
}

func (s clientCredSources) describeAPIKey() string {
	switch {
	case s.apiKeyFlag:
		return "command-line flag --api-key"
	case s.apiKeyConfigFile:
		return "up config file (apiKey)"
	case s.apiKeyEnv:
		return "environment variable EXPOSE_API_KEY"
	case s.apiKeyDotEnv:
		return "./.env file (EXPOSE_API_KEY)"
	case s.apiKeySettings:
		return "saved settings file"
	default:
		return "unknown source"
	}
}

func normalizedServerForCompare(raw string) string {
	normalized, err := normalizeServerURL(raw)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return normalized
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func sameClientCredentialSource(src clientCredSources) bool {
	return (src.serverFlag && src.apiKeyFlag) ||
		(src.serverConfigFile && src.apiKeyConfigFile) ||
		(src.serverEnv && src.apiKeyEnv) ||
		(src.serverDotEnv && src.apiKeyDotEnv) ||
		(src.serverSettings && src.apiKeySettings)
}

// verifyClientCredentialTrust guards against credential mixing: an API key
// must never be sent silently to a server that came from a ./.env file in
// the working directory. Mixed sources always produce a prominent warning; a
// ./.env-supplied server that differs from the saved one additionally
// requires interactive confirmation, and fails hard when non-interactive.
func verifyClientCredentialTrust(ctx context.Context, serverURL string, src clientCredSources) error {
	if sameClientCredentialSource(src) {
		return nil
	}

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "WARNING: server and API key come from different sources.")
	_, _ = fmt.Fprintf(os.Stderr, "  Server:  %s (from %s)\n", serverURL, src.describeServer())
	_, _ = fmt.Fprintf(os.Stderr, "  API key: %s\n", src.describeAPIKey())
	_, _ = fmt.Fprintln(os.Stderr, "")

	effective := normalizedServerForCompare(serverURL)
	stored := normalizedServerForCompare(src.storedServer)
	redirected := !src.apiKeySettings || (effective != "" && effective != stored)
	dotEnvRedirect := src.serverDotEnv && !src.serverFlag && !src.serverConfigFile && !src.serverEnv
	if !dotEnvRedirect || src.apiKeyDotEnv || !redirected {
		return nil
	}
	if !isInteractiveInput() {
		return fmt.Errorf("refusing to send the API key to %s taken from ./.env; pass --server %s (or set EXPOSE_DOMAIN) explicitly to confirm", serverURL, serverURL)
	}
	reader := bufio.NewReader(os.Stdin)
	answer, err := promptContext(ctx, reader, fmt.Sprintf("Send the API key to %s? Type 'yes' to continue: ", serverURL))
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "yes") {
		return errors.New("aborted: server from ./.env was not confirmed")
	}
	return nil
}

// loadStoredClientSettings loads the saved credentials, marks the provenance
// flags for values still missing from cfg, and surfaces the settings file
// permission warning.
func loadStoredClientSettings(cfg *config.ClientConfig, src *clientCredSources) error {
	stored, warning, err := settings.LoadChecked()
	if err != nil {
		return missingClientCredentialsError(err)
	}
	if warning != "" {
		_, _ = fmt.Fprintln(os.Stderr, "WARNING: "+warning)
	}
	src.settingsLoaded = true
	src.storedServer = stored.ServerURL
	if !hasNonEmpty(cfg.ServerURL) {
		cfg.ServerURL = stored.ServerURL
		src.serverSettings = true
	}
	if !hasNonEmpty(cfg.APIKey) {
		cfg.APIKey = stored.APIKey
		src.apiKeySettings = true
	}
	if !hasNonEmpty(cfg.ServerURL) || !hasNonEmpty(cfg.APIKey) {
		return missingClientCredentialsError(nil)
	}
	return nil
}

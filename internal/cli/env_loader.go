package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/config"
)

func loadServerEnvFromDotEnv(path string) {
	loadExposeEnvFromDotEnv(path)
}

// loadClientEnvFromDotEnv loads EXPOSE_* variables from a dotenv file and
// returns the keys that were actually set in the process environment (keys
// already present in the real environment are left untouched and excluded).
// Callers use the returned key set to detect credentials originating from a
// potentially untrusted .env file in the working directory.
func loadClientEnvFromDotEnv(path string) map[string]string {
	return loadExposeEnvFromDotEnv(path)
}

func loadExposeEnvFromDotEnv(path string) map[string]string {
	loaded := map[string]string{}
	values := loadEnvFileValues(path)
	for key, value := range values {
		if !strings.HasPrefix(key, "EXPOSE_") {
			continue
		}
		if existing := strings.TrimSpace(os.Getenv(key)); existing != "" {
			continue
		}
		if err := os.Setenv(key, value); err == nil {
			loaded[key] = value
		}
	}
	return loaded
}

func envOr(key, def string) string {
	return config.EnvOrDefault(key, def)
}

// envRequestLogs reports EXPOSE_LOG_REQUESTS, which defaults to true.
func envRequestLogs() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EXPOSE_LOG_REQUESTS"))) {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func parseIntEnv(key string, def int) int {
	return config.EnvIntOrDefault(key, def)
}

func parseDurationEnv(key string, def time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return def, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return def, fmt.Errorf("invalid %s %q: want a duration such as 30s", key, value)
	}
	return d, nil
}

// flagParseExitCode maps a FlagSet parse error to an exit code: --help is a
// successful request for usage (exit 0); anything else is a usage error.
func flagParseExitCode(err error, prefix string) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if prefix != "" {
		fmt.Fprintln(os.Stderr, prefix, err)
	}
	return 2
}

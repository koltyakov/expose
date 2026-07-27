package cli

import (
	"os"
	"strings"

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

func parseIntEnv(key string, def int) int {
	return config.EnvIntOrDefault(key, def)
}

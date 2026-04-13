package cli

import (
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/config"
)

func loadServerEnvFromDotEnv(path string) {
	loadExposeEnvFromDotEnv(path)
}

func loadClientEnvFromDotEnv(path string) {
	loadExposeEnvFromDotEnv(path)
}

func loadExposeEnvFromDotEnv(path string) {
	values := loadEnvFileValues(path)
	for key, value := range values {
		if !strings.HasPrefix(key, "EXPOSE_") {
			continue
		}
		if existing := strings.TrimSpace(os.Getenv(key)); existing != "" {
			continue
		}
		_ = os.Setenv(key, value)
	}
}

func envOr(key, def string) string {
	return config.EnvOrDefault(key, def)
}

func parseIntEnv(key string, def int) int {
	return config.EnvIntOrDefault(key, def)
}

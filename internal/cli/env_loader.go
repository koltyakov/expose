package cli

import (
	"os"
	"strconv"
	"strings"
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
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseIntEnv(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

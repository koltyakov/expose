// Package log provides a minimal factory for structured slog loggers.
package log

import (
	"log/slog"
	"os"
)

// New creates a [slog.Logger] that writes to stdout at the given level
// (one of "debug", "info", "warn", "error"; defaults to info).
func New(level string) *slog.Logger {
	return newLogger(os.Stdout, level)
}

// NewStderr creates a [slog.Logger] that writes to stderr at the given level.
// This is useful when stdout is reserved for interactive display output.
func NewStderr(level string) *slog.Logger {
	return newLogger(os.Stderr, level)
}

func newLogger(w *os.File, level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: lvl,
	}))
}

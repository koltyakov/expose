// Package log provides a minimal factory for structured slog loggers.
package log

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New creates a [slog.Logger] that writes text records to stdout at the given
// level (one of "debug", "info", "warn", "error"; defaults to info).
func New(level string) *slog.Logger {
	return newLogger(os.Stdout, level, FormatText)
}

// NewFormat is [New] with an explicit record format: [FormatText] (logfmt)
// or [FormatJSON] (one JSON object per line). Unknown formats use text.
func NewFormat(level, format string) *slog.Logger {
	return newLogger(os.Stdout, level, format)
}

// NewStderr creates a [slog.Logger] that writes to stderr at the given level.
// This is useful when stdout is reserved for interactive display output.
func NewStderr(level string) *slog.Logger {
	return newLogger(os.Stderr, level, FormatText)
}

// Record formats accepted by [NewFormat].
const (
	FormatText = "text"
	FormatJSON = "json"
)

// NormalizeFormat maps a configured format to [FormatText] or [FormatJSON].
func NormalizeFormat(format string) string {
	if strings.EqualFold(strings.TrimSpace(format), FormatJSON) {
		return FormatJSON
	}
	return FormatText
}

func newLogger(w io.Writer, level, format string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	opts := &slog.HandlerOptions{Level: lvl}
	if NormalizeFormat(format) == FormatJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

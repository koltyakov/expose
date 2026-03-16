package log

import (
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestNewAndNewStderr(t *testing.T) {
	t.Parallel()

	if New("info") == nil {
		t.Fatal("New() returned nil")
	}
	if NewStderr("warn") == nil {
		t.Fatal("NewStderr() returned nil")
	}
}

func TestNewLoggerAppliesLevelFiltering(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "logger-*.log")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer file.Close()

	logger := newLogger(file, "warn")
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	if err := file.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	output := string(raw)
	if strings.Contains(output, "debug message") {
		t.Fatalf("output unexpectedly contains debug message: %q", output)
	}
	if strings.Contains(output, "info message") {
		t.Fatalf("output unexpectedly contains info message: %q", output)
	}
	if !strings.Contains(output, "warn message") {
		t.Fatalf("output missing warn message: %q", output)
	}
	if !strings.Contains(output, "error message") {
		t.Fatalf("output missing error message: %q", output)
	}
}

func TestNewLoggerDefaultsToInfoLevel(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "logger-*.log")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	defer file.Close()

	logger := newLogger(file, "invalid")
	logger.Log(nil, slog.LevelInfo, "info message")
	logger.Debug("debug message")

	if err := file.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	output := string(raw)
	if !strings.Contains(output, "info message") {
		t.Fatalf("output missing info message: %q", output)
	}
	if strings.Contains(output, "debug message") {
		t.Fatalf("output unexpectedly contains debug message: %q", output)
	}
}

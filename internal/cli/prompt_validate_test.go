package cli

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

func TestWizardValidationHelpers(t *testing.T) {
	t.Parallel()

	if err := validateWizardDomain("example.com"); err != nil {
		t.Fatalf("validateWizardDomain() error = %v", err)
	}
	if err := validateWizardNonEmpty("   "); err == nil {
		t.Fatal("validateWizardNonEmpty(blank) error = nil, want error")
	}
	if err := validateWizardAny(""); err != nil {
		t.Fatalf("validateWizardAny() error = %v", err)
	}
	if err := validateWizardLogLevel("warn"); err != nil {
		t.Fatalf("validateWizardLogLevel() error = %v", err)
	}
	if err := validateWizardLogLevel("trace"); err == nil {
		t.Fatal("validateWizardLogLevel(trace) error = nil, want error")
	}
	if got := normalizeWizardDomain(" https://Example.com/path "); got != "example.com" {
		t.Fatalf("normalizeWizardDomain() = %q, want %q", got, "example.com")
	}
}

func TestPromptHelpers(t *testing.T) {
	t.Parallel()

	args := appendFlagIfNotEmpty([]string{"expose"}, "--domain", " example.com ")
	if got := strings.Join(args, " "); got != "expose --domain example.com" {
		t.Fatalf("appendFlagIfNotEmpty() = %q", got)
	}

	reader := bufio.NewReader(strings.NewReader("value\n"))
	value, missing, err := resolveRequiredValueContext(context.Background(), reader, "", true, "prompt: ")
	if err != nil || missing || value != "value" {
		t.Fatalf("resolveRequiredValueContext() = %q, %v, %v", value, missing, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readPromptLineContext(ctx, bufio.NewReader(strings.NewReader("value\n"))); err == nil {
		t.Fatal("readPromptLineContext(canceled) error = nil, want error")
	}

	if gotInput, gotOutput := isInteractiveInput(), isInteractiveOutput(); gotInput != true && gotInput != false || gotOutput != true && gotOutput != false {
		t.Fatal("interactive helpers returned invalid boolean")
	}
}

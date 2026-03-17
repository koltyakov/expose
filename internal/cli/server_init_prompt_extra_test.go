package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestAskWizardValueRetriesAndAppliesDefault(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReader(strings.NewReader("bad domain\n\n"))
	var out bytes.Buffer

	got, err := askWizardValue(
		context.Background(),
		reader,
		&out,
		"Base domain",
		"Used for public routes.",
		"example.com",
		" Example.com ",
		normalizeWizardDomain,
		validateWizardDomain,
	)
	if err != nil {
		t.Fatalf("askWizardValue() error = %v", err)
	}
	if got != "example.com" {
		t.Fatalf("askWizardValue() = %q, want %q", got, "example.com")
	}
	if !strings.Contains(out.String(), "Invalid value:") {
		t.Fatalf("expected retry output, got %q", out.String())
	}
}

func TestAskWizardYesNoHandlesRetryAndDefault(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReader(strings.NewReader("maybe\ny\n"))
	var out bytes.Buffer

	got, err := askWizardYesNo(context.Background(), reader, &out, "Enable TLS", "Use wildcard certs.", false)
	if err != nil {
		t.Fatalf("askWizardYesNo() error = %v", err)
	}
	if !got {
		t.Fatal("expected yes after retry")
	}
	if !strings.Contains(out.String(), "enter y or n") {
		t.Fatalf("expected invalid-answer prompt, got %q", out.String())
	}

	reader = bufio.NewReader(strings.NewReader("\n"))
	out.Reset()

	got, err = askWizardYesNo(context.Background(), reader, &out, "Enable TLS", "Use wildcard certs.", true)
	if err != nil {
		t.Fatalf("askWizardYesNo() default error = %v", err)
	}
	if !got {
		t.Fatal("expected default yes value")
	}
}

func TestReadWizardLineReturnsTrimmedEOFLine(t *testing.T) {
	t.Parallel()

	got, err := readWizardLine(context.Background(), bufio.NewReader(strings.NewReader(" value without newline ")))
	if err != nil {
		t.Fatalf("readWizardLine() error = %v", err)
	}
	if got != "value without newline" {
		t.Fatalf("readWizardLine() = %q, want %q", got, "value without newline")
	}
}

func TestReadWizardLineCanceledBeforeRead(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := readWizardLine(ctx, bufio.NewReader(strings.NewReader("unused\n")))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("readWizardLine() error = %v, want %v", err, context.Canceled)
	}
}

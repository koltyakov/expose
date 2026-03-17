package cli

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/config"
)

func TestPromptHelpersWithCapturedStdout(t *testing.T) {
	stdout := swapStdout(t)

	got, err := prompt(bufio.NewReader(strings.NewReader(" value \n")), "Label: ")
	if err != nil {
		t.Fatalf("prompt() error = %v", err)
	}
	if got != "value" {
		t.Fatalf("prompt() = %q, want %q", got, "value")
	}
	if out := stdout(); !strings.Contains(out, "Label: ") {
		t.Fatalf("prompt() output = %q, want prompt label", out)
	}

	stdout = swapStdout(t)
	got, err = promptContext(context.Background(), bufio.NewReader(strings.NewReader(" next \n")), "Next: ")
	if err != nil {
		t.Fatalf("promptContext() error = %v", err)
	}
	if got != "next" {
		t.Fatalf("promptContext() = %q, want %q", got, "next")
	}
	if out := stdout(); !strings.Contains(out, "Next: ") {
		t.Fatalf("promptContext() output = %q, want prompt label", out)
	}
}

func TestPromptSecretHelpers(t *testing.T) {
	restoreIO, output := swapPromptIO(t, " secret \n")
	defer restoreIO()

	got, err := promptSecret("Secret: ")
	if err != nil {
		t.Fatalf("promptSecret() error = %v", err)
	}
	if got != "secret" {
		t.Fatalf("promptSecret() = %q, want %q", got, "secret")
	}
	if out := output(); !strings.Contains(out, "Secret: ") {
		t.Fatalf("promptSecret() output = %q, want prompt label", out)
	}

	restoreIO, output = swapPromptIO(t, " secret2 \n")
	defer restoreIO()

	got, err = promptSecretContext(context.Background(), "Secret 2: ")
	if err != nil {
		t.Fatalf("promptSecretContext() error = %v", err)
	}
	if got != "secret2" {
		t.Fatalf("promptSecretContext() = %q, want %q", got, "secret2")
	}
	if out := output(); !strings.Contains(out, "Secret 2: ") {
		t.Fatalf("promptSecretContext() output = %q, want prompt label", out)
	}
}

func TestPromptClientPasswordIfNeededNonInteractive(t *testing.T) {
	restoreIO, _ := swapPromptIO(t, "")
	defer restoreIO()

	cfg := &config.ClientConfig{Protect: true}
	if err := promptClientPasswordIfNeeded(context.Background(), cfg); err == nil {
		t.Fatal("expected missing password error in non-interactive mode")
	}
	if cfg.User != "admin" {
		t.Fatalf("expected default user admin, got %q", cfg.User)
	}

	cfg = &config.ClientConfig{Protect: true, Password: "secret"}
	if err := promptClientPasswordIfNeeded(context.Background(), cfg); err != nil {
		t.Fatalf("promptClientPasswordIfNeeded() error = %v", err)
	}

	t.Setenv("EXPOSE_USER", "admin")
	t.Setenv("EXPOSE_PASSWORD", "from-env")
	cfg = &config.ClientConfig{Protect: true, Password: "inline"}
	if err := promptClientPasswordIfNeeded(context.Background(), cfg); err != nil {
		t.Fatalf("promptClientPasswordIfNeeded(env) error = %v", err)
	}

	if err := promptClientPasswordIfNeeded(context.Background(), nil); err != nil {
		t.Fatalf("promptClientPasswordIfNeeded(nil) error = %v", err)
	}
	if err := promptClientPasswordIfNeeded(context.Background(), &config.ClientConfig{}); err != nil {
		t.Fatalf("promptClientPasswordIfNeeded(unprotected) error = %v", err)
	}
}

func TestSetTerminalEchoReturnsErrorWithoutTTY(t *testing.T) {
	if err := setTerminalEcho(false); err == nil {
		t.Fatal("expected setTerminalEcho() to fail without a tty in tests")
	}
}

func swapStdout(t *testing.T) func() string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	return func() string {
		_ = w.Close()
		os.Stdout = origStdout
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		return string(b)
	}
}

func swapPromptIO(t *testing.T, input string) (func(), func() string) {
	t.Helper()

	origStdin := os.Stdin
	origStdout := os.Stdout

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(inW, input); err != nil {
		t.Fatal(err)
	}
	_ = inW.Close()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	os.Stdin = inR
	os.Stdout = outW

	restore := func() {
		_ = inR.Close()
		_ = outW.Close()
		os.Stdin = origStdin
		os.Stdout = origStdout
	}
	readOutput := func() string {
		_ = outW.Close()
		b, err := io.ReadAll(outR)
		if err != nil {
			t.Fatal(err)
		}
		_ = outR.Close()
		return string(b)
	}
	return restore, readOutput
}

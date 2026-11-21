package cli

import (
	"context"
	"testing"
)

func TestRunClientCommandDispatch(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")
	t.Setenv("EXPOSE_PORT", "")

	if code := runClientCommand(testContext(t), []string{"static", "--domain", "incorrect one"}); code != 2 {
		t.Fatalf("runClientCommand(static) = %d, want 2", code)
	}
	if code := runClientCommand(testContext(t), []string{}); code != 2 {
		t.Fatalf("runClientCommand(default) = %d, want 2", code)
	}
}

func TestRunDispatchesClientCommands(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")
	t.Setenv("EXPOSE_PORT", "")

	if code := Run([]string{"client", "static", "--domain", "incorrect one"}); code != 2 {
		t.Fatalf("Run(client static) = %d, want 2", code)
	}
	if code := Run([]string{}); code != 0 {
		t.Fatalf("Run(default help) = %d, want 0", code)
	}
}

func TestRunDispatchesOtherEarlyErrorCommands(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")
	t.Setenv("EXPOSE_PORT", "")

	if code := Run([]string{"http", "0"}); code != 2 {
		t.Fatalf("Run(http invalid port) = %d, want 2", code)
	}
	if code := Run([]string{"static", "--domain", "incorrect one"}); code != 2 {
		t.Fatalf("Run(static invalid domain) = %d, want 2", code)
	}
	if code := Run([]string{"up", "--bad-flag"}); code != 2 {
		t.Fatalf("Run(up bad flag) = %d, want 2", code)
	}
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

func TestRunRejectsUnknownCommands(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("EXPOSE_PORT", "13000")
	// A mistyped command must not start a tunnel from EXPOSE_PORT.
	if code := Run([]string{"lsit", "--json"}); code != 2 {
		t.Fatalf("Run(lsit) = %d, want 2", code)
	}
}

func TestRunUpdateParsesFlagsBeforeNetwork(t *testing.T) {
	// --help and bad flags return before any release check or download.
	if code := runUpdate(testContext(t), []string{"--help"}); code != 0 {
		t.Fatalf("update --help = %d, want 0", code)
	}
	if code := runUpdate(testContext(t), []string{"--bogus"}); code != 2 {
		t.Fatalf("update --bogus = %d, want 2", code)
	}
	if code := runUpdate(testContext(t), []string{"now"}); code != 2 {
		t.Fatalf("update now = %d, want 2", code)
	}
}

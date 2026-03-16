package cli

import "testing"

func TestRunVersionAndHelp(t *testing.T) {
	if code := Run([]string{"version"}); code != 0 {
		t.Fatalf("expected version command exit code 0, got %d", code)
	}
	if code := Run([]string{"help"}); code != 0 {
		t.Fatalf("expected help command exit code 0, got %d", code)
	}
}

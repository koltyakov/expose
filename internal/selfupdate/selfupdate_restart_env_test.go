package selfupdate

import (
	"os"
	"slices"
	"testing"
)

func TestRestartEnvMarksReplacementOnce(t *testing.T) {
	got := restartEnv([]string{"A=1", restartedEnv + "=1", "B=2"})
	want := []string{"A=1", "B=2", restartedEnv + "=1"}
	if !slices.Equal(got, want) {
		t.Fatalf("restartEnv = %q, want %q", got, want)
	}
}

func TestConsumeRestartMarker(t *testing.T) {
	t.Setenv(restartedEnv, "1")
	if !consumeRestartMarker() {
		t.Fatal("marker not detected")
	}
	if _, ok := os.LookupEnv(restartedEnv); ok {
		t.Fatal("marker left in the environment for child processes")
	}
	if consumeRestartMarker() {
		t.Fatal("marker detected twice")
	}
	t.Setenv(restartedEnv, "0")
	if consumeRestartMarker() {
		t.Fatal("non-1 marker accepted")
	}
}

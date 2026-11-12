package selfupdate

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestValidateBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err = validateBinary(binary); err != nil {
		t.Fatalf("current executable rejected: %v", err)
	}
	marker := []byte("GOOS=" + runtime.GOOS)
	wrong := bytes.ReplaceAll(binary, marker, []byte("GOOS="+strings.Repeat("x", len(runtime.GOOS))))
	if err = validateBinary(wrong); err == nil {
		t.Fatal("accepted executable for the wrong OS")
	}
	if err = validateBinary([]byte("not an executable")); err == nil {
		t.Fatal("accepted invalid executable")
	}
}

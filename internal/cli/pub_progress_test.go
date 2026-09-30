package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestPubProgressRedirectedOutput(t *testing.T) {
	var out bytes.Buffer
	p := &pubProgress{out: &out}
	p.start("Uploading 4.0 B...")
	r := &pubUploadReader{r: strings.NewReader("test"), progress: p, total: 4}
	data, err := io.ReadAll(r)
	if err != nil || string(data) != "test" || r.sent != 4 {
		t.Fatalf("reader changed upload: %q, %d, %v", data, r.sent, err)
	}
	p.finish("Uploaded 4.0 B (100%)")
	p.close()
	if got, want := out.String(), "Uploading 4.0 B...\nUploaded 4.0 B (100%)\n"; got != want {
		t.Fatalf("output: %q, want %q", got, want)
	}
}

func TestPubProgressInteractiveUpload(t *testing.T) {
	var out bytes.Buffer
	p := &pubProgress{out: &out, interactive: true}
	p.start("Uploading 4.0 B...")
	p.lastUpdate = time.Now().Add(-time.Second)
	r := &pubUploadReader{r: strings.NewReader("test"), progress: p, total: 4}
	if _, err := r.Read(make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Uploading: 2.0 B / 4.0 B (50%)") {
		t.Fatalf("missing upload progress: %q", out.String())
	}
	p.finish("Uploaded 4.0 B (100%)")
	finished := out.String()
	p.lastUpdate = time.Now().Add(-time.Second)
	p.update("late update")
	p.close()
	if out.String() != finished || !strings.HasSuffix(finished, "Uploaded 4.0 B (100%)\n") {
		t.Fatalf("late progress changed final output: %q", out.String())
	}
}

func TestPubProgressFailureEndsTerminalLine(t *testing.T) {
	var out bytes.Buffer
	p := &pubProgress{out: &out, interactive: true}
	p.start("Uploading...")
	p.close()
	if !strings.HasSuffix(out.String(), "Uploading...\n") || strings.Contains(out.String(), "Uploaded") {
		t.Fatalf("unexpected failure output: %q", out.String())
	}
}

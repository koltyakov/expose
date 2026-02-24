package cli

import (
	"bufio"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestReadPromptLineContextCanceledWhileWaiting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inR, inW := io.Pipe()
	defer func() { _ = inR.Close() }()
	defer func() { _ = inW.Close() }()

	reader := bufio.NewReader(inR)
	errCh := make(chan error, 1)
	go func() {
		_, err := readPromptLineContext(ctx, reader)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context canceled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for canceled prompt read to return")
	}
}

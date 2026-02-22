package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const clientHotkeyUpdateByte = 0x15 // Ctrl+U

// startClientUpdateHotkeyListener enables a minimal raw terminal mode and
// emits on the returned channel when Ctrl+U is pressed.
func startClientUpdateHotkeyListener() (<-chan struct{}, func(), error) {
	state, err := sttyOutput("-g")
	if err != nil {
		return nil, func() {}, err
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, func() {}, errors.New("stty returned empty terminal state")
	}
	if err := runStty("-icanon", "-echo", "min", "1", "time", "0"); err != nil {
		return nil, func() {}, err
	}

	updateCh := make(chan struct{}, 1)
	go func() {
		var b [1]byte
		for {
			n, err := os.Stdin.Read(b[:])
			if err != nil || n == 0 {
				return
			}
			if b[0] != clientHotkeyUpdateByte {
				continue
			}
			select {
			case updateCh <- struct{}{}:
			default:
			}
		}
	}()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = runStty(state)
		})
	}
	return updateCh, cleanup, nil
}

func sttyOutput(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out.String(), nil
}

func runStty(args ...string) error {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

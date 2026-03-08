package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const (
	clientHotkeyToggleSessionDetailsByte = 0x09 // Ctrl+I
	clientHotkeyUpdateByte               = 0x15 // Ctrl+U
)

// startClientHotkeyListener enables a minimal raw terminal mode and emits on
// the returned channel when a supported dashboard hotkey is pressed.
func startClientHotkeyListener() (<-chan byte, func(), error) {
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

	hotkeyCh := make(chan byte, 1)
	go func() {
		var b [1]byte
		for {
			n, err := os.Stdin.Read(b[:])
			if err != nil || n == 0 {
				return
			}
			switch b[0] {
			case clientHotkeyToggleSessionDetailsByte, clientHotkeyUpdateByte:
			default:
				continue
			}
			select {
			case hotkeyCh <- b[0]:
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
	return hotkeyCh, cleanup, nil
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

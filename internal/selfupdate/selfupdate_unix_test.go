//go:build !windows

package selfupdate

import "testing"

func observeRestartParent([]string) (func() error, error) {
	return func() error { return nil }, nil
}

func prepareRestartParent() (func() error, error) {
	return func() error { return nil }, nil
}

func assertRestartPID(t *testing.T, current, previous int) {
	t.Helper()
	if current != previous {
		t.Fatalf("exec changed PID from %d to %d", previous, current)
	}
}

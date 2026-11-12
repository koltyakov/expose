package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

type restartResult struct {
	PID      int
	Previous int
	Args     []string
	Token    string
}

func TestMain(m *testing.M) {
	if result := os.Getenv("EXPOSE_TEST_RESTART_RESULT"); result != "" {
		if err := runRestartFixture(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runRestartFixture(result string) error {
	verifyParent, err := observeRestartParent(os.Args[1:])
	if err != nil {
		return err
	}
	args, err := ResumeRestart(os.Args[1:])
	if err != nil {
		return err
	}
	if err = verifyParent(); err != nil {
		return err
	}
	if !reflect.DeepEqual(args, os.Args[1:]) {
		return fmt.Errorf("restart did not restore os.Args: %v != %v", args, os.Args[1:])
	}
	exe, err := executablePath()
	if err != nil {
		return err
	}
	lock, err := lockExecutable(exe)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	stage := os.Getenv("EXPOSE_TEST_RESTART_STAGE")
	if stage != "after" {
		binary, err := os.ReadFile(exe)
		if err != nil {
			return err
		}
		if err = replaceBinaryAtContext(context.Background(), exe, binary); err != nil {
			return err
		}
		next := "after"
		if stage == "before" {
			next = "middle"
			if err = os.Setenv("EXPOSE_TEST_RESTART_PID", strconv.Itoa(os.Getpid())); err != nil {
				return err
			}
		}
		if err = os.Setenv("EXPOSE_TEST_RESTART_STAGE", next); err != nil {
			return err
		}
		afterRestart, err := prepareRestartParent()
		if err != nil {
			return err
		}
		// Deliberately retain the lock until exec/exit. It must not be inherited.
		if err = Restart(); err != nil {
			return err
		}
		return afterRestart()
	}
	previous, err := strconv.Atoi(os.Getenv("EXPOSE_TEST_RESTART_PID"))
	if err != nil {
		return err
	}
	data, err := json.Marshal(restartResult{PID: os.Getpid(), Previous: previous, Args: args, Token: os.Getenv("EXPOSE_TEST_RESTART_TOKEN")})
	if err != nil {
		return err
	}
	return os.WriteFile(result, data, 0o600)
}

func TestReplaceRunningExecutableAndRestart(t *testing.T) {
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "expose.exe")
	if err = os.WriteFile(exe, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(dir, "result.json")
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	args := []string{"http", "--domain", "name with spaces", "8080"}
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append(os.Environ(), "EXPOSE_TEST_RESTART_RESULT="+result, "EXPOSE_TEST_RESTART_TOKEN=preserved", "EXPOSE_TEST_RESTART_STAGE=before")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restart: %v\n%s", err, output)
	}
	if len(output) > 0 {
		t.Logf("handoff observations:\n%s", output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var got restartResult
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Previous != cmd.Process.Pid || got.Token != "preserved" || !reflect.DeepEqual(got.Args, args) {
		t.Fatalf("restart did not preserve invocation: %+v", got)
	}
	assertRestartPID(t, got.PID, got.Previous)
	entries, err := filepath.Glob(filepath.Join(dir, ".expose-update-*"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("update staging remains: %v, error = %v", entries, err)
	}
}

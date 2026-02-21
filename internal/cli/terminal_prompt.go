package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/koltyakov/expose/internal/config"
)

func isInteractiveInput() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func isInteractiveOutput() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func prompt(reader *bufio.Reader, label string) (string, error) {
	if _, err := fmt.Fprint(os.Stdout, label); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func resolveRequiredValue(reader *bufio.Reader, value string, canPrompt bool, promptLabel string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if value != "" {
		return value, false, nil
	}
	if !canPrompt {
		return "", true, nil
	}
	v, err := prompt(reader, promptLabel)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(v), false, nil
}

func appendFlagIfNotEmpty(args []string, flagName, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return args
	}
	return append(args, flagName, value)
}

func promptClientPasswordIfNeeded(cfg *config.ClientConfig) error {
	if cfg == nil || !cfg.Protect {
		return nil
	}
	if strings.TrimSpace(cfg.User) == "" {
		cfg.User = "admin"
	}
	hasPassword := strings.TrimSpace(cfg.Password) != ""
	hasUserFromEnv := strings.TrimSpace(os.Getenv("EXPOSE_USER")) != ""
	hasPasswordFromEnv := strings.TrimSpace(os.Getenv("EXPOSE_PASSWORD")) != ""
	if hasUserFromEnv && hasPasswordFromEnv && hasPassword {
		return nil
	}
	if !isInteractiveInput() {
		if !hasPassword {
			return errors.New("missing password: provide EXPOSE_PASSWORD or run interactively with --protect")
		}
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	if !hasUserFromEnv {
		label := fmt.Sprintf("Public user (default %s): ", cfg.User)
		v, err := prompt(reader, label)
		if err != nil {
			return err
		}
		if strings.TrimSpace(v) != "" {
			cfg.User = strings.TrimSpace(v)
		}
	}
	if !hasPassword {
		password, err := promptSecret("Public password (required): ")
		if err != nil {
			return err
		}
		cfg.Password = strings.TrimSpace(password)
		if cfg.Password == "" {
			return errors.New("password is required when --protect is set")
		}
	}
	return nil
}

func promptSecret(label string) (string, error) {
	if _, err := fmt.Fprint(os.Stdout, label); err != nil {
		return "", err
	}
	if isInteractiveInput() {
		echoDisabled := false
		if err := setTerminalEcho(false); err == nil {
			echoDisabled = true
		}
		defer func() {
			if echoDisabled {
				_ = setTerminalEcho(true)
			}
			_, _ = fmt.Fprintln(os.Stdout)
		}()
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func setTerminalEcho(enable bool) error {
	arg := "-echo"
	if enable {
		arg = "echo"
	}
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

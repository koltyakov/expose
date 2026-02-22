package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

type wizardValidator func(string) error

type wizardNormalizer func(string) string

type wizardReadResult struct {
	line string
	err  error
}

func askWizardValue(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details, sample, def string, normalize wizardNormalizer, validate wizardValidator) (string, error) {
	ui := newWizardTUI()
	for {
		ui.printQuestion(out, title, details, sample)
		labelDefault := strings.TrimSpace(def)
		if labelDefault == "" {
			_, _ = fmt.Fprintf(out, "  %s: ", ui.promptLabel("Value"))
		} else {
			_, _ = fmt.Fprintf(out, "  %s [%s]: ", ui.promptLabel("Value"), ui.dim(labelDefault))
		}

		line, err := readWizardLine(ctx, reader)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(line) == "" {
			line = def
		}
		if normalize != nil {
			line = normalize(line)
		}
		if validate != nil {
			if err := validate(line); err != nil {
				ui.printInvalid(out, err.Error())
				continue
			}
		}
		_, _ = fmt.Fprintln(out)
		return line, nil
	}
}

func askWizardYesNo(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details string, def bool) (bool, error) {
	ui := newWizardTUI()
	for {
		defaultLabel := "y/N"
		if def {
			defaultLabel = "Y/n"
		}
		ui.printQuestion(out, title, details, "")
		_, _ = fmt.Fprintf(out, "  %s [%s]: ", ui.promptLabel("Value"), ui.dim(defaultLabel))

		line, err := readWizardLine(ctx, reader)
		if err != nil {
			return false, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			_, _ = fmt.Fprintln(out)
			return def, nil
		}
		switch line {
		case "y", "yes":
			_, _ = fmt.Fprintln(out)
			return true, nil
		case "n", "no":
			_, _ = fmt.Fprintln(out)
			return false, nil
		default:
			ui.printInvalid(out, "enter y or n")
		}
	}
}

func readWizardLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	select {
	case <-ctx.Done():
		return "", context.Canceled
	default:
	}

	resultCh := make(chan wizardReadResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		resultCh <- wizardReadResult{line: line, err: err}
	}()

	select {
	case <-ctx.Done():
		return "", context.Canceled
	case res := <-resultCh:
		if res.err != nil {
			if errors.Is(res.err, io.EOF) && res.line != "" {
				return strings.TrimSpace(res.line), nil
			}
			return "", res.err
		}
		return strings.TrimSpace(res.line), nil
	}
}

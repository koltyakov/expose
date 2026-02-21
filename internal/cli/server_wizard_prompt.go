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

func askWizardValue(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details, sample, def string, normalize wizardNormalizer, validate wizardValidator) (string, error) {
	for {
		_, _ = fmt.Fprintf(out, "%s\n", title)
		_, _ = fmt.Fprintf(out, "  %s\n", details)
		if strings.TrimSpace(sample) != "" {
			_, _ = fmt.Fprintf(out, "  %s\n", sample)
		}
		labelDefault := strings.TrimSpace(def)
		if labelDefault == "" {
			_, _ = fmt.Fprint(out, "  Value: ")
		} else {
			_, _ = fmt.Fprintf(out, "  Value [%s]: ", labelDefault)
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
				_, _ = fmt.Fprintf(out, "  Invalid value: %v\n\n", err)
				continue
			}
		}
		_, _ = fmt.Fprintln(out)
		return line, nil
	}
}

func askWizardYesNo(ctx context.Context, reader *bufio.Reader, out io.Writer, title, details string, def bool) (bool, error) {
	for {
		defaultLabel := "y/N"
		if def {
			defaultLabel = "Y/n"
		}
		_, _ = fmt.Fprintf(out, "%s\n", title)
		_, _ = fmt.Fprintf(out, "  %s\n", details)
		_, _ = fmt.Fprintf(out, "  Value [%s]: ", defaultLabel)

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
			_, _ = fmt.Fprintln(out, "  Invalid value: enter y or n")
			_, _ = fmt.Fprintln(out)
		}
	}
}

func readWizardLine(ctx context.Context, reader *bufio.Reader) (string, error) {
	select {
	case <-ctx.Done():
		return "", context.Canceled
	default:
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

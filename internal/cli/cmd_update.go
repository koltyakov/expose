package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/versionutil"
)

// updateAvailableExitCode lets scripts tell "update available" from errors.
const updateAvailableExitCode = 10

func runUpdate(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage: expose update [--check] [--yes]")
		_, _ = fmt.Fprintln(fs.Output(), "Update to the latest signed release. Interactive terminals are asked to confirm.")
		fs.PrintDefaults()
	}
	checkOnly := fs.Bool("check", false, "Only report whether an update is available; exit 10 when one is")
	assumeYes := fs.Bool("yes", false, "Apply without asking for confirmation")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "update error: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	fmt.Printf("Current version: %s\n", Version)
	fmt.Println("Checking for updates...")

	rel, err := selfupdate.Check(ctx, Version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update check failed:", err)
		return 1
	}
	if rel == nil {
		fmt.Println("Already up to date.")
		return 0
	}

	fmt.Printf("New version available: %s\n", versionutil.EnsureVPrefix(rel.TagName))
	if *checkOnly {
		return updateAvailableExitCode
	}

	if !*assumeYes && isInteractiveInput() {
		reader := bufio.NewReader(os.Stdin)
		answer, err := prompt(reader, "Do you want to update? [y/N] ")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			fmt.Println("Update cancelled.")
			return 0
		}
	}

	fmt.Println("Downloading...")
	res, err := selfupdate.Apply(ctx, rel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "update failed:", err)
		return 1
	}

	fmt.Printf("Updated to %s (%s)\n", versionutil.EnsureVPrefix(res.LatestVersion), res.AssetName)
	return 0
}

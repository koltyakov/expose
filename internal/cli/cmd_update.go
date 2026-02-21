package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/koltyakov/expose/internal/selfupdate"
	"github.com/koltyakov/expose/internal/versionutil"
)

func runUpdate(ctx context.Context) int {
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

	if isInteractiveInput() {
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

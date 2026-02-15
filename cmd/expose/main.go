package main

import (
	"os"

	"github.com/koltyakov/expose/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}

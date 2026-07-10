//go:build !windows

package settings

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}

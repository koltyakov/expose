//go:build windows

package settings

import "golang.org/x/sys/windows"

func replaceFile(source, destination string) error {
	return windows.MoveFileEx(
		windows.StringToUTF16Ptr(source),
		windows.StringToUTF16Ptr(destination),
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}

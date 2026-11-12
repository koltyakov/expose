package selfupdate

import (
	"bytes"
	"debug/buildinfo"
	"fmt"
	"runtime"
)

// Check the executable without running uninstalled code or starting a helper.
// The release checksum authenticates these build settings along with the bytes.
func validateBinary(binary []byte) error {
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil {
		return fmt.Errorf("read Go executable: %w", err)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH {
		return fmt.Errorf("executable platform %s/%s does not match %s/%s", settings["GOOS"], settings["GOARCH"], runtime.GOOS, runtime.GOARCH)
	}
	return nil
}

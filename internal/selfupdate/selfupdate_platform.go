package selfupdate

import (
	"fmt"
	"runtime"
)

// assetNameForPlatform returns the expected archive file name
// matching the goreleaser naming template for the current OS/arch.
func assetNameForPlatform() (string, error) {
	osName, err := goosToAssetOS(runtime.GOOS)
	if err != nil {
		return "", err
	}
	archName, err := goarchToAssetArch(runtime.GOARCH)
	if err != nil {
		return "", err
	}

	ext := ".tar.gz"
	if runtime.GOOS == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("expose_%s_%s%s", osName, archName, ext), nil
}

func goosToAssetOS(goos string) (string, error) {
	switch goos {
	case "darwin":
		return "Darwin", nil
	case "linux":
		return "Linux", nil
	case "windows":
		return "Windows", nil
	default:
		return "", fmt.Errorf("unsupported OS: %s", goos)
	}
}

func goarchToAssetArch(goarch string) (string, error) {
	switch goarch {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture: %s", goarch)
	}
}

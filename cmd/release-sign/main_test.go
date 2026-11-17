package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/releasesign"
)

func configure(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"release-2026-11-17": base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RELEASE_SIGNING_PUBLIC_KEYS", string(raw))
	t.Setenv("RELEASE_SIGNING_KEY_ID", "release-2026-11-17")
	t.Setenv("RELEASE_SIGNING_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	return key
}

func TestSigningTool(t *testing.T) {
	t.Chdir("../..")
	configure(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "checksums.txt")
	signature := manifest + ".sig"
	if err := os.WriteFile(manifest, []byte("abc  archive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"check", "sign", "verify", "prepare", "ldflags"} {
		if err := run(mode, manifest, signature, "v1.2.3", "release-2026-11-17", dir); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	for _, name := range []string{"install.sh", "install.ps1"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || bytes.Contains(body, []byte("EXPOSE_PINNED_RELEASE_KEYS")) ||
			!bytes.Contains(body, []byte(os.Getenv("RELEASE_SIGNING_PUBLIC_KEYS"))) {
			t.Fatalf("installer key pinning failed: %v", err)
		}
		if bytes.Contains(body, []byte(os.Getenv("RELEASE_SIGNING_PRIVATE_KEY"))) {
			t.Fatal("private key leaked into installer")
		}
	}
	if err := run("verify", manifest, signature, "v1.2.4", "release-2026-11-17", dir); err == nil {
		t.Fatal("verification accepted wrong tag")
	}
	if err := run("sign", manifest, signature, "v1.2.3", "unknown", dir); err == nil {
		t.Fatal("signer accepted unpinned key")
	}
	if err := run("check", manifest, signature, "v1.2.3", "", dir); err == nil {
		t.Fatal("accepted missing active key ID")
	}
	t.Setenv("RELEASE_SIGNING_PRIVATE_KEY", "")
	if err := run("check", manifest, signature, "v1.2.3", "release-2026-11-17", dir); err == nil {
		t.Fatal("accepted missing private key")
	}
	t.Setenv("RELEASE_SIGNING_PUBLIC_KEYS", "{}")
	if err := run("prepare", manifest, signature, "v1.2.3", "release-2026-11-17", dir); err == nil {
		t.Fatal("prepared installers without trust")
	}
}

// Both installers exercise real OpenSSL verification. Only their download
// transport is substituted, with fixed local fixtures and no network access.
func TestPreparedInstallers(t *testing.T) {
	t.Chdir("../..")
	key := configure(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		if os.Getenv("EXPOSE_TEST_REQUIRE_INSTALLERS") == "1" {
			t.Fatal("OpenSSL is required for installer verification")
		}
		t.Skip("OpenSSL is unavailable")
	}
	for _, scriptName := range []string{"install.sh", "install.ps1"} {
		t.Run(scriptName, func(t *testing.T) {
			runner := "sh"
			if scriptName == "install.sh" {
				if runtime.GOOS == "windows" {
					t.Skip("POSIX installer")
				}
				if _, err := exec.LookPath("jq"); err != nil {
					if os.Getenv("EXPOSE_TEST_REQUIRE_INSTALLERS") == "1" {
						t.Fatal("jq is required for installer verification")
					}
					t.Skip("jq is unavailable")
				}
			} else {
				runner = "pwsh"
				if runtime.GOOS == "windows" {
					runner = "powershell"
				}
				if _, err := exec.LookPath(runner); err != nil {
					if os.Getenv("EXPOSE_TEST_REQUIRE_INSTALLERS") == "1" {
						t.Fatal("PowerShell is required for installer verification")
					}
					t.Skip("PowerShell is unavailable")
				}
			}
			for _, scenario := range []string{"valid", "altered manifest", "wrong key", "missing signature", "invalid signature", "oversized signature", "wrong repository", "checksum mismatch"} {
				t.Run(scenario, func(t *testing.T) {
					dir := filepath.Join(t.TempDir(), "installer fixtures")
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := run("prepare", "", "", "", "", dir); err != nil {
						t.Fatal(err)
					}
					asset, archive, installed := installerArchive(t, scriptName)
					if err := os.WriteFile(filepath.Join(dir, asset), archive, 0o600); err != nil {
						t.Fatal(err)
					}
					sum := sha256.Sum256(archive)
					manifest := []byte(hex.EncodeToString(sum[:]) + "  " + asset + "\n")
					if scenario == "checksum mismatch" {
						manifest = []byte(strings.Repeat("0", 64) + "  " + asset + "\n")
					}
					signature, err := releasesign.Sign("v1.2.3", "release-2026-11-17", manifest, key)
					if err != nil {
						t.Fatal(err)
					}
					switch scenario {
					case "altered manifest":
						manifest = append([]byte(" "), manifest...)
					case "wrong key":
						_, wrong, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						signature, err = releasesign.Sign("v1.2.3", "release-2026-11-17", manifest, wrong)
						if err != nil {
							t.Fatal(err)
						}
					case "invalid signature":
						signature = []byte(`{}`)
					case "oversized signature":
						signature = bytes.Repeat([]byte("x"), releasesign.MaxSignatureBytes+1)
					case "wrong repository":
						signature = bytes.ReplaceAll(signature, []byte(releasesign.Repository), []byte("attacker/expose"))
					}
					if err := os.WriteFile(filepath.Join(dir, "checksums.txt"), manifest, 0o600); err != nil {
						t.Fatal(err)
					}
					if scenario != "missing signature" {
						if err := os.WriteFile(filepath.Join(dir, releasesign.AssetName), signature, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					t.Setenv("HOME", dir)
					t.Setenv("LOCALAPPDATA", dir)
					t.Setenv("PROCESSOR_ARCHITECTURE", "AMD64")
					t.Setenv("EXPOSE_TEST_FIXTURES", dir)
					// Explicitly prove the legacy opt-out is not honored.
					t.Setenv("EXPOSE_REQUIRE_SIGNATURE", "false")
					path := filepath.Join(dir, scriptName)
					var cmd *exec.Cmd
					if scriptName == "install.sh" {
						mock := `#!/bin/sh
set -eu
url=
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    https://*) url="$1" ;;
    -o) shift; out="$1" ;;
  esac
  shift
done
printf '%s\n' "$url" >> "$EXPOSE_TEST_FIXTURES/requests"
case "$url" in
  https://github.com/koltyakov/expose/releases/latest/download/checksums.txt.sig) ;;
  https://github.com/koltyakov/expose/releases/download/v1.2.3/*) ;;
  *) exit 1 ;;
esac
cp "$EXPOSE_TEST_FIXTURES/${url##*/}" "$out"
`
						if err := os.WriteFile(filepath.Join(dir, "curl"), []byte(mock), 0o755); err != nil {
							t.Fatal(err)
						}
						t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
						cmd = exec.CommandContext(t.Context(), runner, path)
					} else {
						script, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						mock := `[IO.File]::AppendAllText((Join-Path $env:EXPOSE_TEST_FIXTURES 'requests'), "$Url` + "`n" + `")
    if ($Url -cne 'https://github.com/koltyakov/expose/releases/latest/download/checksums.txt.sig' -and
        -not $Url.StartsWith('https://github.com/koltyakov/expose/releases/download/v1.2.3/')) { throw 'Unexpected URL' }
    [IO.File]::Copy((Join-Path $env:EXPOSE_TEST_FIXTURES ([Uri]$Url).Segments[-1]), $Out, $true)`
						script = bytes.ReplaceAll(script, []byte("Invoke-WebRequest -Uri $Url -OutFile $Out -UseBasicParsing"), []byte(mock))
						// Never mutate the test machine's persistent user PATH.
						script = bytes.ReplaceAll(script, []byte(`[Environment]::SetEnvironmentVariable('PATH', "$userPath;$installDir", 'User')`), []byte("$null = $userPath"))
						if err := os.WriteFile(path, script, 0o600); err != nil {
							t.Fatal(err)
						}
						cmd = exec.CommandContext(t.Context(), runner, "-NoProfile", "-NonInteractive", "-File", path)
						if runtime.GOOS == "windows" {
							// CI can launch Go from PowerShell 7. Let Windows
							// PowerShell initialize its own compatible module paths.
							cmd.Env = windowsPowerShellEnv(cmd.Environ())
						}
					}
					output, err := cmd.CombinedOutput()
					target := filepath.Join(dir, installed)
					if scenario == "valid" {
						if err != nil {
							t.Fatalf("installer: %v\n%s", err, output)
						}
						got, err := os.ReadFile(target)
						if err != nil || string(got) != "fixture executable" {
							t.Fatalf("incorrect installed payload: %q, %v", got, err)
						}
					} else {
						if err == nil {
							t.Fatalf("installer accepted %s\n%s", scenario, output)
						}
						if scenario == "checksum mismatch" && !strings.Contains(strings.ToLower(string(output)), "checksum mismatch") {
							t.Fatalf("expected checksum rejection, got:\n%s", output)
						}
						if _, err := os.Stat(target); !os.IsNotExist(err) {
							t.Fatal("failed verification created an installation")
						}
					}
					requests, err := os.ReadFile(filepath.Join(dir, "requests"))
					if err != nil {
						t.Fatal(err)
					}
					wantRequests := []string{"https://github.com/koltyakov/expose/releases/latest/download/checksums.txt.sig"}
					if scenario == "valid" || scenario == "altered manifest" || scenario == "wrong key" || scenario == "checksum mismatch" {
						wantRequests = append(wantRequests, "https://github.com/koltyakov/expose/releases/download/v1.2.3/checksums.txt")
					}
					if scenario == "valid" || scenario == "checksum mismatch" {
						wantRequests = append(wantRequests, "https://github.com/koltyakov/expose/releases/download/v1.2.3/"+asset)
					}
					if got := strings.Fields(string(requests)); !slices.Equal(got, wantRequests) {
						t.Fatalf("download sequence = %v, want %v", got, wantRequests)
					}
				})
			}
		})
	}
}

func windowsPowerShellEnv(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		return strings.EqualFold(name, "PSModulePath")
	})
}

func TestWindowsPowerShellEnv(t *testing.T) {
	env := []string{
		"PATH=tools", "PSModulePath=PowerShell7", "psmodulepath=other",
		"PSExecutionPolicyPreference=RemoteSigned", "EXPOSE_TEST_FIXTURES=fixtures",
	}
	original := slices.Clone(env)
	want := []string{"PATH=tools", "PSExecutionPolicyPreference=RemoteSigned", "EXPOSE_TEST_FIXTURES=fixtures"}
	if got := windowsPowerShellEnv(env); !slices.Equal(got, want) {
		t.Fatalf("environment = %v, want %v", got, want)
	}
	if !slices.Equal(env, original) {
		t.Fatal("modified the caller's environment")
	}
}

func installerArchive(t *testing.T, script string) (string, []byte, string) {
	t.Helper()
	var buf bytes.Buffer
	if script == "install.ps1" {
		w := zip.NewWriter(&buf)
		f, err := w.Create("expose.exe")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("fixture executable")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return "expose_Windows_x86_64.zip", buf.Bytes(), filepath.Join("Programs", "expose", "expose.exe")
	}
	gz := gzip.NewWriter(&buf)
	w := tar.NewWriter(gz)
	if err := w.WriteHeader(&tar.Header{Name: "expose", Size: int64(len("fixture executable")), Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("fixture executable")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	osName, arch := "Linux", "arm64"
	if runtime.GOOS == "darwin" {
		osName = "Darwin"
	}
	if runtime.GOARCH == "amd64" {
		arch = "x86_64"
	}
	return fmt.Sprintf("expose_%s_%s.tar.gz", osName, arch), buf.Bytes(), filepath.Join(".local", "bin", "expose")
}

package cli

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/client/settings"
)

// writeUpCredTrustFixture stages a working directory whose ./.env redirects
// EXPOSE_DOMAIN at an attacker-controlled host, plus a saved settings file
// holding the operator's real credentials for a different server.
func writeUpCredTrustFixture(t *testing.T, dotEnv string) string {
	t.Helper()

	clearClientEnvVarsForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := settings.Save(settings.Credentials{
		ServerURL: "https://home.example.com",
		APIKey:    "k_operator_secret",
	}); err != nil {
		t.Fatalf("settings.Save() error = %v", err)
	}

	workdir := t.TempDir()
	t.Chdir(workdir)
	if dotEnv != "" {
		if err := os.WriteFile(filepath.Join(workdir, ".env"), []byte(dotEnv), 0o600); err != nil {
			t.Fatalf("write .env error = %v", err)
		}
	}
	return workdir
}

func TestRunUpFromFileRefusesDotEnvServerRedirect(t *testing.T) {
	workdir := writeUpCredTrustFixture(t, "EXPOSE_DOMAIN=evil.example.com\n")

	configPath := filepath.Join(workdir, "expose.yaml")
	body := "version: 1\ntunnels:\n  - name: app\n    subdomain: myapp\n    port: 3000\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config error = %v", err)
	}

	// Non-interactive stdin: the saved API key must never be sent to a
	// server that a ./.env file in the working directory chose.
	if code := runUpFromFile(context.Background(), configPath); code != 2 {
		t.Fatalf("runUpFromFile() = %d, want 2 (refused .env server redirect)", code)
	}
}

func TestRunSoakRefusesDotEnvServerRedirect(t *testing.T) {
	writeUpCredTrustFixture(t, "EXPOSE_DOMAIN=evil.example.com\n")

	if code := runSoak(context.Background(), []string{"--port", "3000", "--count", "1"}); code != 2 {
		t.Fatalf("runSoak() = %d, want 2 (refused .env server redirect)", code)
	}
}

// TestClientCredentialsAlwaysTrustChecked is a structural guard: the merge
// helper fills in the saved API key without validating where the server URL
// came from, so every caller must reach it through resolveClientCredentials.
// A command that calls it directly silently reintroduces the ./.env
// credential-redirect hole that resolveClientCredentials exists to close.
func TestClientCredentialsAlwaysTrustChecked(t *testing.T) {
	t.Parallel()

	const (
		mergeFn   = "mergeClientSettingsWithSources"
		wrapperFn = "resolveClientCredentials"
	)

	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob error = %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s error = %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name == wrapperFn {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == mergeFn {
					offenders = append(offenders, path+":"+fn.Name.Name)
				}
				return true
			})
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("%s called outside %s by %v; credentials would skip the trust check",
			mergeFn, wrapperFn, offenders)
	}
}

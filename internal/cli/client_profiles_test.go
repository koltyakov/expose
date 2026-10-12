package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func setupClientProfiles(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	clearClientEnvVarsForTest(t)
	for profile, creds := range map[string]settings.Credentials{
		"":     {ServerURL: "https://default.example.com", APIKey: "default-key"},
		"work": {ServerURL: "https://work.example.com", APIKey: "work-key"},
	} {
		if err := settings.SaveProfile(profile, creds); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClientProfileCredentialResolution(t *testing.T) {
	setupClientProfiles(t)
	cases := []struct {
		name    string
		cfg     config.ClientConfig
		src     clientCredSources
		server  string
		key     string
		wantErr bool
	}{
		{name: "omitted uses legacy default", server: "https://default.example.com", key: "default-key"},
		{name: "omitted preserves env priority", cfg: config.ClientConfig{ServerURL: "env.example.com", APIKey: "env-key"}, src: clientCredSources{serverEnv: true, apiKeyEnv: true}, server: "https://env.example.com", key: "env-key"},
		{name: "omitted preserves dotenv priority", cfg: config.ClientConfig{ServerURL: "project.example.com", APIKey: "project-key"}, src: clientCredSources{serverDotEnv: true, apiKeyDotEnv: true}, server: "https://project.example.com", key: "project-key"},
		{name: "omitted preserves up config priority", cfg: config.ClientConfig{ServerURL: "project.example.com", APIKey: "project-key"}, src: clientCredSources{serverConfigFile: true, apiKeyConfigFile: true}, server: "https://project.example.com", key: "project-key"},
		{name: "named selects own pair", cfg: config.ClientConfig{Profile: "work"}, server: "https://work.example.com", key: "work-key"},
		{name: "profile overrides env", cfg: config.ClientConfig{Profile: "work", ServerURL: "env.example.com", APIKey: "env-key"}, src: clientCredSources{serverEnv: true, apiKeyEnv: true}, server: "https://work.example.com", key: "work-key"},
		{name: "profile overrides dotenv redirect", cfg: config.ClientConfig{Profile: "work", ServerURL: "evil.example.com"}, src: clientCredSources{serverDotEnv: true}, server: "https://work.example.com", key: "work-key"},
		{name: "profile overrides up config", cfg: config.ClientConfig{Profile: "work", ServerURL: "project.example.com", APIKey: "project-key"}, src: clientCredSources{serverConfigFile: true, apiKeyConfigFile: true}, server: "https://work.example.com", key: "work-key"},
		{name: "explicit default overrides env", cfg: config.ClientConfig{Profile: "default", ServerURL: "env.example.com", APIKey: "env-key"}, src: clientCredSources{serverEnv: true, apiKeyEnv: true}, server: "https://default.example.com", key: "default-key"},
		{name: "server flag overrides profile", cfg: config.ClientConfig{Profile: "work", ServerURL: "override.example.com"}, src: clientCredSources{serverFlag: true}, server: "https://override.example.com", key: "work-key"},
		{name: "key flag overrides profile", cfg: config.ClientConfig{Profile: "work", APIKey: "override-key"}, src: clientCredSources{apiKeyFlag: true}, server: "https://work.example.com", key: "override-key"},
		{name: "both flags override profile", cfg: config.ClientConfig{Profile: "work", ServerURL: "override.example.com", APIKey: "override-key"}, src: clientCredSources{serverFlag: true, apiKeyFlag: true}, server: "https://override.example.com", key: "override-key"},
		{name: "missing never falls back", cfg: config.ClientConfig{Profile: "missing"}, wantErr: true},
		{name: "missing with env never falls back", cfg: config.ClientConfig{Profile: "missing", ServerURL: "env.example.com", APIKey: "env-key"}, src: clientCredSources{serverEnv: true, apiKeyEnv: true}, wantErr: true},
		{name: "missing with flags still fails", cfg: config.ClientConfig{Profile: "missing", ServerURL: "override.example.com", APIKey: "override-key"}, src: clientCredSources{serverFlag: true, apiKeyFlag: true}, wantErr: true},
		{name: "invalid name", cfg: config.ClientConfig{Profile: "../work"}, wantErr: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			err := resolveClientCredentials(context.Background(), &cfg, tt.src)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && (cfg.ServerURL != tt.server || cfg.APIKey != tt.key) {
				t.Fatalf("got %s / %s, want %s / %s", cfg.ServerURL, cfg.APIKey, tt.server, tt.key)
			}
		})
	}
}

func TestLoginProfilePreservesDefault(t *testing.T) {
	setupClientProfiles(t)
	before, err := os.ReadFile(settings.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range [][]string{{"login"}, {"client", "login"}} {
		args := append(prefix, "--profile", "work", "--server", "new.example.com", "--api-key", "new-key")
		if code := Run(args); code != 0 {
			t.Fatalf("%v: exit code %d", args, code)
		}
	}
	after, err := os.ReadFile(settings.Path())
	if err != nil || string(before) != string(after) {
		t.Fatalf("named login changed default: %s, error %v", after, err)
	}
	got, _, err := settings.LoadProfileChecked("work")
	if err != nil || got.ServerURL != "https://new.example.com" || got.APIKey != "new-key" {
		t.Fatalf("named login: %#v, error %v", got, err)
	}
	if code := runClientLogin(context.Background(), []string{"--profile", "../bad", "--server", "example.com", "--api-key", "key"}); code != 2 {
		t.Fatalf("invalid profile login = %d", code)
	}
	// Both the original command and explicit default update the original file
	// without altering the named login.
	for _, profileArgs := range [][]string{nil, {"--profile", "default"}} {
		args := append([]string{"--server", "default2.example.com", "--api-key", "default2-key"}, profileArgs...)
		if code := runClientLogin(context.Background(), args); code != 0 {
			t.Fatalf("default login = %d", code)
		}
		creds, err := settings.Load()
		if err != nil || creds.ServerURL != "https://default2.example.com" || creds.APIKey != "default2-key" {
			t.Fatalf("default login: %#v, error %v", creds, err)
		}
		work, _, err := settings.LoadProfileChecked("work")
		if err != nil || work != got {
			t.Fatalf("default login changed work profile: %#v, error %v", work, err)
		}
	}
}

func TestProfileRoutesListAndPub(t *testing.T) {
	setupClientProfiles(t)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer work-key" {
			t.Errorf("unexpected key %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != serviceapi.Exposures && r.URL.Path != serviceapi.Sites {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, "[]")
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	if err := settings.SaveProfile("work", settings.Credentials{ServerURL: server.URL, APIKey: "work-key"}); err != nil {
		t.Fatal(err)
	}
	// Even a project with its own server/key pair must not redirect this profile.
	if err := os.WriteFile(".env", []byte("EXPOSE_DOMAIN=wrong.example.com\nEXPOSE_API_KEY=wrong-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"list", "--profile", "work", "--json"},
		{"client", "list", "--profile=work", "--json"},
		{"pub", "list", "--profile", "work", "--json"},
		{"client", "pub", "list", "--profile=work", "--json"},
	} {
		if code := Run(args); code != 0 {
			t.Fatalf("%v: exit code %d", args, code)
		}
	}
	if requests != 4 {
		t.Fatalf("requests = %d, want 4", requests)
	}
}

func TestHTTPProfileDoesNotForwardEnvAsFlags(t *testing.T) {
	setupClientProfiles(t)
	t.Setenv("EXPOSE_DOMAIN", "env.example.com")
	t.Setenv("EXPOSE_API_KEY", "env-key")
	// A missing profile must fail during credential resolution, not start a
	// client using environment credentials forwarded by the HTTP wrapper.
	if code := runHTTP(context.Background(), []string{"3000", "--profile", "missing"}); code != 2 {
		t.Fatalf("missing profile HTTP = %d", code)
	}
	// Use a deliberately invalid saved URL so resolution fails before network
	// access. If the wrapper promotes env credentials to flags, it would run.
	if err := settings.SaveProfile("work", settings.Credentials{ServerURL: "http://work.example.com", APIKey: "work-key"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"3000", "--profile=work"}, {"--profile", "work", "3000"}, {"3000", "--profile", " "}, {"3000", "--profile", " work "}} {
		if code := runHTTP(context.Background(), args); code != 2 {
			t.Fatalf("%v: exit code %d", args, code)
		}
	}
}

func TestProfileFlagAcceptedByClients(t *testing.T) {
	setupClientProfiles(t)
	ctx := context.Background()
	if _, err := config.ParseClientFlags([]string{"--port", "3000", "--profile", "work"}); err != nil {
		t.Fatal(err)
	}
	if code := runStatic(ctx, []string{"--profile", "missing"}); code != 2 {
		t.Fatalf("static missing profile = %d", code)
	}
	if code := runSoak(ctx, []string{"--port", "3000", "--profile", "missing"}); code != 2 {
		t.Fatalf("soak missing profile = %d", code)
	}
	if err := os.WriteFile("expose.yml", []byte("version: 1\ntunnels:\n  - name: app\n    subdomain: myapp\n    port: 3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runUp(ctx, []string{"--profile", "missing"}); code != 2 {
		t.Fatalf("up missing profile = %d", code)
	}
	if err := listCommand(ctx, []string{"--profile", "missing"}, io.Discard); err == nil || !strings.Contains(err.Error(), `profile "missing"`) {
		t.Fatalf("missing profile diagnostic: %v", err)
	}
}

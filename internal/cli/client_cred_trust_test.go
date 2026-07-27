package cli

import (
	"context"
	"testing"
)

func TestCliFlagPassed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		args []string
		want bool
	}{
		{args: []string{"--server", "https://a.example"}, want: true},
		{args: []string{"--server=https://a.example"}, want: true},
		{args: []string{"-server", "https://a.example"}, want: true},
		{args: []string{"--port", "3000"}, want: false},
		{args: []string{"--serverx", "1"}, want: false},
		{args: nil, want: false},
	}
	for _, tt := range cases {
		if got := cliFlagPassed(tt.args, "server"); got != tt.want {
			t.Fatalf("cliFlagPassed(%v) = %v, want %v", tt.args, got, tt.want)
		}
	}
}

func TestVerifyClientCredentialTrust(t *testing.T) {
	t.Parallel()

	settingsSrc := clientCredSources{
		settingsLoaded: true,
		storedServer:   "https://home.example.com",
		serverSettings: true,
		apiKeySettings: true,
	}

	cases := []struct {
		name      string
		serverURL string
		src       clientCredSources
		wantErr   bool
	}{
		{
			name:      "both from settings",
			serverURL: "https://home.example.com",
			src:       settingsSrc,
		},
		{
			name:      "settings not loaded",
			serverURL: "https://evil.example.com",
			src:       clientCredSources{serverDotEnv: true, apiKeyDotEnv: true},
		},
		{
			name:      "dotenv server with environment key fails non-interactively",
			serverURL: "https://evil.example.com",
			src:       clientCredSources{serverDotEnv: true, apiKeyEnv: true},
			wantErr:   true,
		},
		{
			name:      "mixed but server matches stored",
			serverURL: "https://home.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverDotEnv:   true,
				apiKeySettings: true,
			},
		},
		{
			name:      "flag server with saved key warns only",
			serverURL: "https://other.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverFlag:     true,
				apiKeySettings: true,
			},
		},
		{
			name:      "env server with saved key warns only",
			serverURL: "https://other.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverEnv:      true,
				apiKeySettings: true,
			},
		},
		{
			name:      "dotenv server with saved key fails non-interactively",
			serverURL: "https://evil.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverDotEnv:   true,
				apiKeySettings: true,
			},
			wantErr: true,
		},
		{
			name:      "dotenv server made explicit by flag warns only",
			serverURL: "https://evil.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverDotEnv:   true,
				serverFlag:     true,
				apiKeySettings: true,
			},
		},
		{
			name:      "saved server with dotenv key warns only",
			serverURL: "https://home.example.com",
			src: clientCredSources{
				settingsLoaded: true,
				storedServer:   "https://home.example.com",
				serverSettings: true,
				apiKeyDotEnv:   true,
			},
		},
		{
			name:      "dotenv server made explicit by up config file warns only",
			serverURL: "https://other.example.com",
			src: clientCredSources{
				settingsLoaded:   true,
				storedServer:     "https://home.example.com",
				serverDotEnv:     true,
				serverConfigFile: true,
				apiKeySettings:   true,
			},
		},
	}
	for _, tt := range cases {
		err := verifyClientCredentialTrust(context.Background(), tt.serverURL, tt.src)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: verifyClientCredentialTrust() err = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestNormalizedServerForCompare(t *testing.T) {
	t.Parallel()

	if got := normalizedServerForCompare("Home.Example.COM"); got != "https://home.example.com" {
		t.Fatalf("normalizedServerForCompare() = %q", got)
	}
	if got := normalizedServerForCompare("https://home.example.com/"); got != "https://home.example.com" {
		t.Fatalf("normalizedServerForCompare() = %q", got)
	}
	if got := normalizedServerForCompare("https://HOME.example.com/TenantA?Key=Value"); got != "https://home.example.com/TenantA?Key=Value" {
		t.Fatalf("normalizedServerForCompare() changed case-sensitive URL components: %q", got)
	}
	if normalizedServerForCompare("https://home.example.com/TenantA") == normalizedServerForCompare("https://home.example.com/tenanta") {
		t.Fatal("normalizedServerForCompare() folded a case-sensitive path")
	}
}

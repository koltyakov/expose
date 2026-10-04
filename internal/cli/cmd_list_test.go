package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func TestListCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")
	response := `[{"id":"t_test","type":"tunnel","hostname":"app.example.com","url":"https://app.example.com","status":"connected","created_at":"2026-01-01T00:00:00Z"},{"id":"site_test","type":"site","hostname":"docs.example.com","url":"https://docs.example.com","status":"active","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z"}]`
	status := http.StatusOK
	wantRetention := "168h0m0s"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != serviceapi.Exposures || r.Header.Get("Authorization") != "Bearer owner" {
			t.Errorf("unexpected listing request: %s %s, auth %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
		if got := r.URL.Query().Get("retention"); got != wantRetention {
			t.Errorf("retention = %q, want %q", got, wantRetention)
		}
		if status == http.StatusFound {
			w.Header().Set("Location", "/redirected")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	if err := settings.Save(settings.Credentials{ServerURL: server.URL, APIKey: "owner"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := listCommand(context.Background(), nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TYPE", "STATUS", "NAME", "SEEN", "EXPIRES", "named", "online", "app.example.com", "docs.example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("table missing %q: %s", want, out.String())
		}
	}
	out.Reset()
	if err := listCommand(context.Background(), []string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var got []domain.Exposure
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || len(got) != 2 || got[1].ExpiresAt == nil {
		t.Fatalf("JSON listing: %s, error %v", out.String(), err)
	}
	for _, prefix := range [][]string{{"list"}, {"client", "list"}} {
		args := append(prefix, "--server", server.URL, "--api-key", "owner", "--json")
		if code := Run(args); code != 0 {
			t.Fatalf("%v: exit code %d", args, code)
		}
	}
	for _, retention := range []string{"24h", "0"} {
		wantRetention = "24h0m0s"
		if retention == "0" {
			wantRetention = "0s"
		}
		if err := listCommand(context.Background(), []string{"--retention", retention}, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	wantRetention = "168h0m0s"
	for _, retention := range []string{"-1h", "invalid"} {
		if err := listCommand(context.Background(), []string{"--retention", retention}, io.Discard); err == nil {
			t.Fatalf("accepted invalid retention %q", retention)
		}
	}
	response = "[]"
	for _, jsonOutput := range []bool{false, true} {
		out.Reset()
		var args []string
		want := "Your exposures\n\n  No tunnels or published sites found.\n  Start one with expose http 3000 or expose pub ./dist."
		if jsonOutput {
			args, want = []string{"--json"}, "[]"
		}
		if err := listCommand(context.Background(), args, &out); err != nil || strings.TrimSpace(out.String()) != want {
			t.Fatalf("empty output: %q, error %v", out.String(), err)
		}
	}
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusNotFound, "update the server"},
		{http.StatusUnauthorized, "expose login"},
		{http.StatusInternalServerError, "500"},
		{http.StatusFound, "302"},
	} {
		status = tc.status
		out.Reset()
		if err := listCommand(context.Background(), nil, &out); err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
			t.Fatalf("status %d: error %v, output %s", status, err, out.String())
		}
	}
	status, response = http.StatusOK, "invalid JSON"
	if err := listCommand(context.Background(), nil, io.Discard); err == nil || !strings.Contains(err.Error(), "decode exposure list") {
		t.Fatalf("malformed response: %v", err)
	}
	if err := listCommand(context.Background(), []string{"unexpected"}, io.Discard); err == nil || !strings.Contains(err.Error(), "no positional arguments") {
		t.Fatalf("unexpected argument: %v", err)
	}
	if code := runList(context.Background(), []string{"--help"}); code != 0 {
		t.Fatalf("help exit code: %d", code)
	}
}

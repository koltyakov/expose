package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/client/settings"
	"github.com/koltyakov/expose/internal/serviceapi"
)

func TestServerVersionCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("EXPOSE_DOMAIN", "")
	t.Setenv("EXPOSE_API_KEY", "")

	srv := newServerVersionTestHTTP(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != serviceapi.Version ||
			r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected version request: %s %s, auth %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"version":"v2.3.4"}`)
	})
	login := settings.Credentials{ServerURL: srv.URL, APIKey: "test-key"}
	if err := settings.Save(login); err != nil {
		t.Fatal(err)
	}
	if err := settings.SaveProfile("work", login); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "default login"},
		{name: "named login", args: []string{"--profile", "work"}},
		{name: "explicit credentials", args: []string{"--server", srv.URL, "--api-key", "test-key"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name != "default login" {
				t.Setenv("EXPOSE_DOMAIN", "https://unused.invalid")
				t.Setenv("EXPOSE_API_KEY", "unused")
			}
			var out bytes.Buffer
			if err := serverVersionCommand(t.Context(), tc.args, &out); err != nil || out.String() != "v2.3.4\n" {
				t.Fatalf("output = %q, error = %v", out.String(), err)
			}
		})
	}

	if code := Run([]string{"server", "version"}); code != 0 {
		t.Fatalf("server version exit code = %d", code)
	}
	if code := Run([]string{"server", "version", "--help"}); code != 0 {
		t.Fatalf("server version help exit code = %d", code)
	}
}

func TestServerVersionCommandErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "old server", status: http.StatusNotFound, want: "update the server"},
		{name: "unauthorized", status: http.StatusUnauthorized, want: "expose login"},
		{name: "redirect", status: http.StatusFound, want: "302"},
		{name: "invalid JSON", status: http.StatusOK, body: `{"version":`, want: "decode server version"},
		{name: "missing version", status: http.StatusOK, body: `{}`, want: "invalid version"},
		{name: "control character", status: http.StatusOK, body: `{"version":"v2.3.4\u001b"}`, want: "invalid version"},
		{name: "oversized response", status: http.StatusOK, body: strings.Repeat(" ", 4097), want: "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServerVersionTestHTTP(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != serviceapi.Version {
					t.Errorf("unexpected request to %s", r.URL.Path)
				}
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "/unexpected")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			var out bytes.Buffer
			err := serverVersionCommand(t.Context(), []string{"--server", srv.URL, "--api-key", "test-key"}, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) || out.Len() != 0 {
				t.Fatalf("output = %q, error = %v, want error containing %q", out.String(), err, tc.want)
			}
		})
	}
}

func newServerVersionTestHTTP(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	original := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	return srv
}

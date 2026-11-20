package client

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestForwardResultRequestLogToggle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		cfg   config.ClientConfig
		level slog.Level
		want  bool
	}{
		{name: "default", level: slog.LevelInfo, want: true},
		{name: "omitted", cfg: config.ClientConfig{OmitRequestLogs: true}, level: slog.LevelInfo},
		{name: "warn level", level: slog.LevelWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var logs bytes.Buffer
			c := New(tc.cfg, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: tc.level})))
			c.logForwardResult(&tunnelproto.HTTPRequest{Method: http.MethodGet, Path: "/x", Query: "token=secret"}, http.StatusOK, time.Now())
			if got := strings.Contains(logs.String(), "forwarded request"); got != tc.want {
				t.Fatalf("logged=%v, want %v: %q", got, tc.want, logs.String())
			}
			if strings.Contains(logs.String(), "secret") {
				t.Fatalf("query value leaked: %q", logs.String())
			}
		})
	}
}

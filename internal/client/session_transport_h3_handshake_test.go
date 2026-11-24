package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

// A server that accepts the QUIC connection and the control request but
// never answers must not hang the connect.
func TestH3ControlConnectBoundedBySilentServer(t *testing.T) {
	release := make(chan struct{})
	addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer shutdown()
	defer close(release)

	original := h3ControlHandshakeTimeout
	t.Cleanup(func() { h3ControlHandshakeTimeout = original })

	c := New(config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	connects := map[string]func(context.Context) error{
		"compat": func(ctx context.Context) error {
			_, err := c.connectHTTP3Transport(ctx, domain.RegisterResponse{H3URL: "https://" + addr + "/connect"})
			return err
		},
		"multistream": func(ctx context.Context) error {
			_, err := c.connectHTTP3MultiStreamTransport(ctx, domain.RegisterResponse{
				H3URL: "https://" + addr + "/connect", Capabilities: []string{tunnelCapabilityH3MultistreamV2},
			})
			return err
		},
	}
	for name, connect := range connects {
		t.Run(name+"/deadline", func(t *testing.T) {
			h3ControlHandshakeTimeout = 200 * time.Millisecond
			started := time.Now()
			err := connect(t.Context())
			if err == nil {
				t.Fatal("connect succeeded against a silent server")
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("connect took %s, past its handshake deadline", elapsed)
			}
		})
		t.Run(name+"/cancel", func(t *testing.T) {
			h3ControlHandshakeTimeout = time.Minute
			ctx, cancel := context.WithCancel(t.Context())
			time.AfterFunc(200*time.Millisecond, cancel)
			started := time.Now()
			err := connect(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("connect = %v, want context.Canceled", err)
			}
			if elapsed := time.Since(started); elapsed > 3*time.Second {
				t.Fatalf("cancelled connect took %s", elapsed)
			}
		})
	}
}

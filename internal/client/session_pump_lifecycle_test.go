package client

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/quic-go/quic-go/http3"
)

func idleWritePumpCount() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return bytes.Count(buf[:n], []byte("tunneltransport.(*WritePump).next"))
}

func TestQUICV2ConnectionsReleaseAllWritePumps(t *testing.T) {
	// Do not run in parallel: this test counts idle pumps across the process.
	addr, shutdown := startHTTP3TestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(h3SessionHeader, "lifecycle-token")
		w.WriteHeader(http.StatusOK)
		if _, err := w.(http3.HTTPStreamer).HTTPStream(); err != nil {
			t.Errorf("take over stream: %v", err)
		}
	}))
	defer shutdown()
	c := New(config.ClientConfig{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.h3TLSConfig = &tls.Config{InsecureSkipVerify: true}
	before := idleWritePumpCount()
	for i := range 3 {
		started := time.Now()
		conn, err := c.connectHTTP3MultiStreamTransport(t.Context(), domain.RegisterResponse{
			H3URL:        "https://" + addr + "/connect",
			Capabilities: []string{tunnelCapabilityH3MultistreamV2},
		})
		if err != nil {
			t.Fatalf("connection %d after %s: %T: %v", i+1, time.Since(started), err, err)
		}
		conn.writer.Close()
	}
	deadline := time.Now().Add(time.Second)
	for idleWritePumpCount() > before && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if after := idleWritePumpCount(); after > before {
		t.Fatalf("idle write pumps before=%d after=%d", before, after)
	}
}

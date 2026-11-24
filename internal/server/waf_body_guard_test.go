package server

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/waf"
)

type readTrackingBody struct {
	*strings.Reader
	read bool
}

func (b *readTrackingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.Reader.Read(p)
}

func (*readTrackingBody) Close() error { return nil }

func TestWAFSkipsBodiesForHostsNotServed(t *testing.T) {
	srv := New(config.ServerConfig{WAFBodyInspectLimit: 16 * 1024}, nil, nil, "test")
	srv.routes.setMiss("ghost.example.com")
	srv.routes.set("app.example.com", domain.TunnelRoute{Domain: domain.Domain{ID: "d1", Hostname: "app.example.com"}})

	reached := 0
	handler := waf.NewMiddleware(waf.Config{
		Enabled:           true,
		BodyInspectLimit:  16 * 1024,
		ShouldInspectBody: srv.shouldInspectWAFBody,
	}, slog.New(slog.DiscardHandler))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusNotFound)
	}))
	const attack = "q=1' OR '1'='1"
	for _, tc := range []struct {
		host        string
		wantRead    bool
		wantBlocked bool
	}{
		{"ghost.example.com", false, false}, // cached miss: answered without the body
		{"203.0.113.9", false, false},       // IP-literal Host
		{"app.example.com", true, true},     // served host
		{"new.example.com", true, true},     // not resolved yet: inspect
	} {
		body := &readTrackingBody{Reader: strings.NewReader(attack)}
		r := httptest.NewRequest(http.MethodPost, "https://"+tc.host+"/login", nil)
		r.Host = tc.host
		r.Body = body
		r.ContentLength = int64(len(attack))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		before := reached
		handler.ServeHTTP(w, r)
		if body.read != tc.wantRead {
			t.Errorf("%s: body read = %v, want %v", tc.host, body.read, tc.wantRead)
		}
		if blocked := reached == before; blocked != tc.wantBlocked {
			t.Errorf("%s: blocked = %v (status %d), want %v", tc.host, blocked, w.Code, tc.wantBlocked)
		}
	}
}

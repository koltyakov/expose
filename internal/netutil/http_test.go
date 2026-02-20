package netutil

import (
	"net/http"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"Example.COM:443":      "example.com",
		" example.com. ":       "example.com",
		"[2001:db8::1]:8443":   "2001:db8::1",
		"2001:db8::1":          "2001:db8::1",
		"localhost:10443":      "localhost",
		"sub.test.EXAMPLE.com": "sub.test.example.com",
	}

	for in, want := range tests {
		if got := NormalizeHost(in); got != want {
			t.Fatalf("NormalizeHost(%q): got %q, want %q", in, got, want)
		}
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	t.Parallel()

	h := http.Header{
		"Connection":        {"keep-alive, upgrade, X-Internal-Hop"},
		"Keep-Alive":        {"timeout=5"},
		"Proxy-Connection":  {"keep-alive"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"websocket"},
		"X-Internal-Hop":    {"drop-me"},
		"X-Keep":            {"keep-me"},
	}

	RemoveHopByHopHeaders(h)

	for _, key := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Connection",
		"Transfer-Encoding",
		"Upgrade",
		"X-Internal-Hop",
	} {
		if got := h.Get(key); got != "" {
			t.Fatalf("expected %s to be removed, got %q", key, got)
		}
	}
	if got := h.Get("X-Keep"); got != "keep-me" {
		t.Fatalf("expected X-Keep to be preserved, got %q", got)
	}
}

func TestRemoveHopByHopHeadersPreserveUpgrade(t *testing.T) {
	t.Parallel()

	h := http.Header{
		"Connection":        {"keep-alive, upgrade, X-Internal-Hop"},
		"Keep-Alive":        {"timeout=5"},
		"Proxy-Connection":  {"keep-alive"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"websocket"},
		"X-Internal-Hop":    {"drop-me"},
		"X-Keep":            {"keep-me"},
	}

	RemoveHopByHopHeadersPreserveUpgrade(h)

	for _, key := range []string{
		"Keep-Alive",
		"Proxy-Connection",
		"Transfer-Encoding",
		"X-Internal-Hop",
	} {
		if got := h.Get(key); got != "" {
			t.Fatalf("expected %s to be removed, got %q", key, got)
		}
	}
	if got := h.Get("Connection"); got != "Upgrade" {
		t.Fatalf("expected Connection to be preserved as Upgrade, got %q", got)
	}
	if got := h.Get("Upgrade"); got != "websocket" {
		t.Fatalf("expected Upgrade to be preserved, got %q", got)
	}
	if got := h.Get("X-Keep"); got != "keep-me" {
		t.Fatalf("expected X-Keep to be preserved, got %q", got)
	}
}

func TestShouldPreserveUpgradeHeaders(t *testing.T) {
	t.Parallel()

	if !ShouldPreserveUpgradeHeaders(http.Header{
		"Connection": {"keep-alive, Upgrade"},
		"Upgrade":    {"websocket"},
	}) {
		t.Fatal("expected websocket upgrade headers to be detected")
	}

	if ShouldPreserveUpgradeHeaders(http.Header{
		"Connection": {"keep-alive"},
		"Upgrade":    {"websocket"},
	}) {
		t.Fatal("expected non-upgrade Connection headers to be rejected")
	}
}

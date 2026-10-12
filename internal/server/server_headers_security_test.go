package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestForwardedClientIdentityDropsAllSpoofedSpellings(t *testing.T) {
	for _, ip := range []string{"203.0.113.7", "[2001:db8::7]:1234", ""} {
		t.Run(ip, func(t *testing.T) {
			h := http.Header{
				"X-Forwarded-For": {"127.0.0.1", "10.0.0.1"}, "x-forwarded-for": {"spoofed"},
				"X-Real-IP": {"127.0.0.1"}, "x-real-ip": {"10.0.0.1"},
				"Forwarded": {"for=127.0.0.1;proto=http;host=evil.example"}, "forwarded": {"for=10.0.0.1"},
			}
			injectForwardedFor(h, ip)
			for key := range h {
				if strings.EqualFold(key, "Forwarded") || (key != "X-Forwarded-For" && key != "X-Real-Ip") {
					t.Fatalf("spoofed header remains: %q", key)
				}
			}
			want := ip
			if strings.HasPrefix(ip, "[") {
				want = "2001:db8::7"
			}
			for _, key := range []string{"X-Forwarded-For", "X-Real-IP"} {
				if h.Get(key) != want || (want != "" && len(h.Values(key)) != 1) {
					t.Fatalf("%s=%v, want one %q", key, h.Values(key), want)
				}
			}
		})
	}
}

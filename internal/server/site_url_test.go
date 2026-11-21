package server

import (
	"net/http/httptest"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
)

func TestWithSiteURLKeepsNonDefaultPort(t *testing.T) {
	t.Parallel()
	site := domain.PublishedSite{Hostname: "docs.example.com"}
	for host, want := range map[string]string{
		"example.com":       "https://docs.example.com",
		"example.com:443":   "https://docs.example.com",
		"example.com:18443": "https://docs.example.com:18443",
	} {
		r := httptest.NewRequest("GET", "/_expose/v1/sites", nil)
		r.Host = host
		if got := withSiteURL(r, site).URL; got != want {
			t.Fatalf("Host %q: URL = %q, want %q", host, got, want)
		}
	}
}

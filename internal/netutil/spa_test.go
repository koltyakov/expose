package netutil

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowSPAFallback(t *testing.T) {
	for _, tc := range []struct {
		name, method, url, accept, dest string
		want                            bool
	}{
		{"route without headers", "GET", "/dashboard/settings", "", "", true},
		{"head route", "HEAD", "/dashboard", "", "", true},
		{"navigation", "GET", "/dashboard", "text/html,application/xhtml+xml,*/*;q=0.8", "document", true},
		{"iframe", "GET", "/dashboard", "text/html", "iframe", true},
		{"html route", "GET", "/dashboard.html", "text/html", "", true},
		{"htm route", "GET", "/dashboard.HTM", "text/html", "", true},
		{"query extension", "GET", "/dashboard?file=icon.png", "", "", true},
		{"wildcard", "GET", "/dashboard", "*/*", "", true},
		{"text wildcard", "GET", "/dashboard", "text/*", "", true},
		{"png", "GET", "/assets/hero.png", "", "", false},
		{"png navigation", "GET", "/assets/hero.png", "text/html", "document", false},
		{"uppercase extension", "GET", "/assets/hero.PNG", "", "", false},
		{"encoded extension", "GET", "/assets/hero%2epng?v=1", "", "", false},
		{"trailing slash", "GET", "/assets/hero.png/", "", "", false},
		{"javascript", "GET", "/assets/app.js", "*/*", "script", false},
		{"css", "GET", "/assets/app.css", "text/css,*/*;q=0.1", "style", false},
		{"unknown extension", "GET", "/assets/data.custom", "", "", false},
		{"extensionless image", "GET", "/image", "*/*", "image", false},
		{"extensionless script", "GET", "/script", "*/*", "script", false},
		{"extensionless fetch", "GET", "/data", "*/*", "empty", false},
		{"json", "GET", "/data", "application/json", "", false},
		{"image accept", "GET", "/image", "image/png", "", false},
		{"html refused", "GET", "/dashboard", "text/html;q=0,*/*;q=1", "", false},
		{"html decimal zero", "GET", "/dashboard", "text/html;q=0.0", "", false},
		{"invalid quality", "GET", "/dashboard", "text/html;q=bogus", "", false},
		{"out of range quality", "GET", "/dashboard", "text/html;q=2", "", false},
		{"xhtml", "GET", "/dashboard", "application/xhtml+xml", "", true},
		{"post", "POST", "/dashboard", "text/html", "document", false},
		{"options", "OPTIONS", "/dashboard", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.url, nil)
			r.Header.Set("Accept", tc.accept)
			r.Header.Set("Sec-Fetch-Dest", tc.dest)
			if got := AllowSPAFallback(r); got != tc.want {
				t.Fatalf("AllowSPAFallback = %v, want %v", got, tc.want)
			}
		})
	}
}

func BenchmarkAllowSPAFallback(b *testing.B) {
	for _, url := range []string{"/assets/hero.png", "/dashboard/settings"} {
		b.Run(url, func(b *testing.B) {
			r := httptest.NewRequest(http.MethodGet, url, nil)
			r.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			b.ReportAllocs()
			for b.Loop() {
				AllowSPAFallback(r)
			}
		})
	}
}

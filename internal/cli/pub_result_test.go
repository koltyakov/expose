package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/termui"
)

func TestPublishedSiteResult(t *testing.T) {
	expires := time.Date(2026, time.July, 7, 16, 26, 54, 0, time.UTC)
	for _, color := range []bool{false, true} {
		var out bytes.Buffer
		site := domain.PublishedSite{Hostname: "shitwind.firebp.com", ExpiresAt: &expires}
		if err := writePublishedSiteResult(&out, site, color); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, want := range []string{"Published", "shitwind", "Public URL", "https://shitwind.firebp.com", "Expires", expires.Local().Format("2 Jan 2006, 15:04:05 MST")} {
			if !strings.Contains(text, want) {
				t.Errorf("missing %q: %q", want, text)
			}
		}
		if color {
			if !strings.Contains(text, termui.Bold+termui.Green+"Published") || !strings.Contains(text, termui.Bold+termui.Cyan+"https://shitwind.firebp.com") {
				t.Errorf("missing success and URL styling: %q", text)
			}
		} else {
			want := "\n  Published shitwind\n\n  Public URL  https://shitwind.firebp.com\n  Expires     " + expires.Local().Format("2 Jan 2006, 15:04:05 MST") + "\n\n"
			if text != want {
				t.Errorf("plain output: %q, want %q", text, want)
			}
		}
	}
}

func TestPublishedSiteResultWithoutExpiry(t *testing.T) {
	var out bytes.Buffer
	if err := writePublishedSiteResult(&out, domain.PublishedSite{Hostname: "docs.example.com"}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Expires     No expiry") {
		t.Fatalf("missing no-expiry result: %q", out.String())
	}
}

func TestPublishedSiteResultSanitizesHostname(t *testing.T) {
	var out bytes.Buffer
	if err := writePublishedSiteResult(&out, domain.PublishedSite{Hostname: "docs.example.com\x1b[2J\n"}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b") || strings.Count(out.String(), "\n") != 6 {
		t.Fatalf("hostname injected terminal controls: %q", out.String())
	}
}

type pubResultFailWriter struct{ err error }

func (w pubResultFailWriter) Write([]byte) (int, error) { return 0, w.err }

func TestPublishedSiteResultWriteError(t *testing.T) {
	want := errors.New("write failed")
	if err := writePublishedSiteResult(pubResultFailWriter{want}, domain.PublishedSite{Hostname: "docs.example.com"}, false); !errors.Is(err, want) {
		t.Fatalf("write error: %v, want %v", err, want)
	}
}

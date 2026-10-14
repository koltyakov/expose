package waf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"regexp/syntax"
	"strings"
	"testing"
)

var sqlAlternativeWitnesses = []string{
	"UNION SELECT", "union/**/all/**/select", "; drop table x", "; DELETE FROM x",
	"; insert into x", "; update x", "; ALTER TABLE x", "' or 1=1", `" and 2=2`, "';--",
	"UNION/**/x", "SELECT/**/x", "OR/**/x", "AND/**/x", "WHERE/**/x", "FROM/**/x",
	"/**/union", "/**/select", "/**/or", "/**/and", "/**/where", "/**/from",
	"x'41'", "benchmark(1)", "sleep(1)", "waitfor(1)", "load_file(1)",
	"into outfile (1)", "into dumpfile (1)",
}

// hasRequiredTrigger proves that every ASCII match contains a trigger. Traces
// expand factored alternations such as d(?:rop|elete), retaining literal runs
// across concatenation. Unknown or repeatable spans break literal adjacency.
func hasRequiredTrigger(expr *syntax.Regexp, triggers []string) bool {
	traces := requiredLiteralTraces(expr)
	for _, trace := range traces {
		if !containsAnyFolded(trace, triggers) {
			return false
		}
	}
	return len(traces) > 0
}

func requiredLiteralTraces(expr *syntax.Regexp) []string {
	switch expr.Op {
	case syntax.OpLiteral:
		return []string{strings.ToLower(string(expr.Rune))}
	case syntax.OpConcat:
		traces := []string{""}
		for _, child := range expr.Sub {
			parts := requiredLiteralTraces(child)
			if len(parts) == 0 || len(traces)*len(parts) > 4096 {
				return nil
			}
			next := make([]string, 0, len(traces)*len(parts))
			for _, trace := range traces {
				for _, part := range parts {
					next = append(next, trace+part)
				}
			}
			traces = next
		}
		return traces
	case syntax.OpAlternate:
		var traces []string
		for _, child := range expr.Sub {
			parts := requiredLiteralTraces(child)
			if len(parts) == 0 || len(traces)+len(parts) > 4096 {
				return nil
			}
			traces = append(traces, parts...)
		}
		return traces
	case syntax.OpCapture:
		return requiredLiteralTraces(expr.Sub[0])
	case syntax.OpPlus, syntax.OpRepeat:
		if expr.Op == syntax.OpPlus || expr.Min > 0 {
			traces := requiredLiteralTraces(expr.Sub[0])
			for i := range traces {
				traces[i] = "\x00" + traces[i] + "\x00"
			}
			return traces
		}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}
	}
	return []string{"\x00"}
}

// Independent implementation for proving the configured conjunctive groups.
func hasTriggerGroupForTest(trace string, groups [][]string) bool {
	for _, group := range groups {
		all := len(group) > 0
		for _, trigger := range group {
			all = all && strings.Contains(trace, trigger)
		}
		if all {
			return true
		}
	}
	return false
}

func TestSQLTriggersCoverEveryAlternative(t *testing.T) {
	t.Parallel()
	rl := defaultRules()[0]
	if rl.name != "sql-injection" {
		t.Fatal("expected SQL rule first")
	}
	expr, err := syntax.Parse(rl.pattern.String(), syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRequiredTrigger(expr, rl.triggersFolded) {
		t.Fatal("cannot prove a required ASCII trigger for every SQL regex alternative")
	}
	for _, trace := range requiredLiteralTraces(expr) {
		if !hasTriggerGroupForTest(trace, rl.triggerGroups) {
			t.Fatalf("cannot prove a required SQL trigger group for trace %q", trace)
		}
	}
	for _, witness := range sqlAlternativeWitnesses {
		if !rl.pattern.MatchString(witness) || !rl.matches(newScanInput(witness)) {
			t.Errorf("SQL alternative witness not detected: %q", witness)
		}
	}
	for _, benign := range []string{benchChromeUA, "sid=abc123; theme=dark", "sort=name&order=asc", "Macintosh", "into the garden;"} {
		if containsAnyFolded(newScanInput(benign).folded, rl.triggersFolded) {
			t.Errorf("benign SQL regex work was not filtered: %q", benign)
		}
	}
	for _, benign := range []string{`:"` + strings.Repeat("a", 16*1024), `"safe"`, `"page=2"`, "'safe'"} {
		if hasTriggerGroupForTest(newScanInput(benign).folded, rl.triggerGroups) {
			t.Errorf("standalone quote forced SQL regex work: %q", benign)
		}
	}
}

func ruleDifferentialCorpus() []string {
	corpus := []string{
		"", "safe", "ſqlmap", "neſſuſ", "niKto", "ſleep(1)", "ſelect/**/x",
		benchChromeUA, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
		"sid=abc123; theme=dark; locale=en-US", "page=2&sort=name", "a+b%25xx", "%GG+safe", "\xffſqlmap",
		"<script>alert(1)</script>", "../../etc/passwd", "${jndi:ldap://x}", "$(cat /etc/passwd)",
		"SYSTEM 'file://x'", "{{config}}", "data:text/html", "onerror=alert(1)", "169.254.169.254",
	}
	for _, witness := range sqlAlternativeWitnesses {
		variants := []string{witness, strings.ToUpper(witness), strings.NewReplacer("s", "ſ", "k", "K").Replace(witness)}
		for _, variant := range variants {
			corpus = append(corpus, variant, "prefix "+variant+" suffix", url.QueryEscape(variant), url.QueryEscape(url.QueryEscape(variant)))
		}
	}
	return corpus
}

func checkRuleRegexParity(t *testing.T, rules []rule, raw string) {
	t.Helper()
	set := newValueSet(1 << 20)
	collectGenericValues(set, raw)
	// Include the empty value, which collectors intentionally omit.
	inputs := append([]scanInput{newScanInput(raw)}, set.values...)
	for _, in := range inputs {
		for i := range rules {
			rl := &rules[i]
			pattern := rl.pattern
			if rl.name == "scanner-ua" {
				pattern = legacyScannerPattern
			}
			if got, want := rl.matches(in), pattern.MatchString(in.raw); got != want {
				t.Fatalf("rule %q on %q: filtered = %v, independent regex = %v", rl.name, in.raw, got, want)
			}
		}
	}
}

func TestRuleMatchesRegexParity(t *testing.T) {
	t.Parallel()
	rules := defaultRules()
	for _, raw := range ruleDifferentialCorpus() {
		checkRuleRegexParity(t, rules, raw)
	}
}

func TestSQLShortTriggerParity(t *testing.T) {
	t.Parallel()
	// Make the regex match every nonempty input and disable the stronger group
	// condition, so matches reports exactly the trigger lookup's decision.
	probe := defaultRules()[0]
	probe.pattern = regexp.MustCompile(`(?s).+`)
	probe.triggerGroups = nil
	check := func(raw string) {
		t.Helper()
		folded := strings.ToLower(raw) // this corpus is ASCII only
		want := false
		for _, trigger := range probe.triggersFolded {
			want = want || strings.Contains(folded, trigger)
		}
		if got := probe.matches(newScanInput(raw)); got != want {
			t.Fatalf("trigger lookup on %q = %v, independent substring scan = %v", raw, got, want)
		}
	}
	check("")
	for a := range 128 {
		check(string([]byte{byte(a)}))
		for b := range 128 {
			check(string([]byte{byte(a), byte(b)}))
		}
	}
	for _, trigger := range probe.triggersFolded {
		for _, pad := range []int{0, 1, 7, 31, 48, 64, 65} {
			padding := strings.Repeat("k", pad)
			check(padding + trigger)
			check(trigger + padding)
			check(padding + strings.ToUpper(trigger) + padding)
		}
	}
}

func FuzzRuleMatchesRegexParity(f *testing.F) {
	for _, raw := range ruleDifferentialCorpus() {
		f.Add(raw)
	}
	rules := defaultRules()
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1024 {
			raw = raw[:1024]
		}
		checkRuleRegexParity(t, rules, raw)
	})
}

func TestWAFUnicodeScannerParity(t *testing.T) {
	t.Parallel()
	handler := newTestMiddleware(t)
	for _, ua := range []string{"ſqlmap", "neſſuſ", "niKto", "burpſuite", "Mozilla/5.0 (Macintosh)"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", ua)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, r)
		if got, want := rr.Code == http.StatusForbidden, legacyScannerPattern.MatchString(ua); got != want {
			t.Errorf("UA %q: blocked = %v, legacy = %v", ua, got, want)
		}
	}
}

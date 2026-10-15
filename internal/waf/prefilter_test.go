package waf

import (
	"math/rand/v2"
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

// One witness per branch of the XSS and shell-injection patterns, so both the
// trigger groups and the shell-injection matcher see every alternative.
var xssAlternativeWitnesses = []string{
	"<script>", "< SCRIPT", "javascript:", "JavaScript :x", "<img src=x onerror=1>", "<a onfoo =x",
	" onload=", `"onclick =`, "'onmouseover=", "/onerror=", "`onfocusin=",
	"document.cookie", "document . location", "DOCUMENT.write",
	"<iframe ", "<svg>", "< math>", "alert(", "confirm (", "PROMPT(", "eval(",
}

var shellAlternativeWitnesses = []string{
	"$(cat /etc/passwd)", "$( whoami)", "$(ID)",
	"`ls -la`", "` echo hi`", "`RM x`",
	"| curl x", "|bash", "|  chmod 777 x",
	"; wget x", ";python", "; NC host",
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

// TestRuleTriggerGroupsCoverEveryAlternative proves, for every rule with
// trigger groups, that each ASCII match contains all substrings of some group.
func TestRuleTriggerGroupsCoverEveryAlternative(t *testing.T) {
	t.Parallel()
	proved := 0
	for _, rl := range defaultRules() {
		if len(rl.triggerGroups) == 0 {
			continue
		}
		expr, err := syntax.Parse(rl.pattern.String(), syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		traces := requiredLiteralTraces(expr)
		if len(traces) == 0 {
			t.Fatalf("cannot enumerate the alternatives of rule %q", rl.name)
		}
		for _, trace := range traces {
			if !hasTriggerGroupForTest(trace, rl.triggerGroups) {
				t.Fatalf("rule %q: cannot prove a required trigger group for trace %q", rl.name, trace)
			}
		}
		proved++
	}
	if proved < 2 {
		t.Fatalf("proved trigger groups for %d rules, want SQL and XSS", proved)
	}
}

func ruleByName(t testing.TB, rules []rule, name string) *rule {
	t.Helper()
	for i := range rules {
		if rules[i].name == name {
			return &rules[i]
		}
	}
	t.Fatalf("rule %q not found", name)
	return nil
}

func TestXSSTriggerGroups(t *testing.T) {
	t.Parallel()
	rl := ruleByName(t, defaultRules(), "xss")
	for _, witness := range xssAlternativeWitnesses {
		if !rl.pattern.MatchString(witness) || !rl.matches(newScanInput(witness)) {
			t.Errorf("XSS alternative witness not detected: %q", witness)
		}
	}
	safariUA := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"
	for _, benign := range []string{safariUA, benchChromeUA, "sid=abc123; theme=dark"} {
		if hasTriggerGroupForTest(newScanInput(benign).folded, rl.triggerGroups) {
			t.Errorf("benign value forced XSS regex work: %q", benign)
		}
	}
}

func TestShellInjectionMatcherWitnesses(t *testing.T) {
	t.Parallel()
	rl := ruleByName(t, defaultRules(), "shell-injection")
	if rl.asciiMatcher == nil {
		t.Fatal("shell-injection has no ASCII matcher")
	}
	check := func(raw string, want bool) {
		t.Helper()
		if got := rl.pattern.MatchString(raw); got != want {
			t.Fatalf("regex on %q = %v, want %v", raw, got, want)
		}
		if got := rl.matches(newScanInput(raw)); got != want {
			t.Errorf("matches(%q) = %v, want %v", raw, got, want)
		}
	}
	for _, witness := range shellAlternativeWitnesses {
		for _, variant := range []string{witness, strings.Repeat(";", 16) + witness, witness + strings.Repeat(" x;", 16), "sid=1; " + witness} {
			check(variant, true)
		}
	}
	// Each branch's edges: whitespace is \s without vertical tab, the command
	// must end at a word boundary, pipe branches exclude substitution-only
	// commands, and backticks need a closing backtick after the command.
	for raw, want := range map[string]bool{
		";\t\n\f\r cat": true, "; \vcat": false, ";cat-x": true, ";cat_x": false, ";cat9": false, ";catx": false,
		"|sh": true, "|shx": false, "| ECHO hi": false, "; whoami": false, "|id": false,
		"$(echo": true, "$ (echo": false, "$(\vid)": false, "$(": false, "$": false,
		"`ls": false, "`ls`": true, "`ls\n\n`": true, "`lsx`": false, "``ls": false, "``ls`": true, "`ls ` `": true,
		"x`id": false, "`id` and `": true,
		benchChromeUA: false, strings.Repeat("sid=abc123; theme=dark; ", 16): false,
	} {
		check(raw, want)
	}
}

// TestShellInjectionMatcherParity compares the hand-written matcher with the
// rule's regexp on every sequence of up to three tokens drawn from the
// pattern's own syntax, then on random longer sequences.
func TestShellInjectionMatcherParity(t *testing.T) {
	t.Parallel()
	rl := ruleByName(t, defaultRules(), "shell-injection")
	tokens := []string{";", "|", "$(", "$", "(", ")", "`", " ", "\t", "\n", "\f", "\r", "\v", "-", "/", ".", "_", "a", "1", "x"}
	for _, command := range shellSubstitutionCommands {
		tokens = append(tokens, command, strings.ToUpper(command), command[:len(command)-1], command+"x")
	}
	check := func(raw string) {
		t.Helper()
		folded := newScanInput(raw).folded
		if got, want := matchShellInjection(folded), rl.pattern.MatchString(raw); got != want {
			t.Fatalf("matcher on %q = %v, regex = %v", raw, got, want)
		}
	}
	for _, a := range tokens {
		check(a)
		for _, b := range tokens {
			check(a + b)
			for _, c := range tokens {
				check(a + b + c)
			}
		}
	}
	rng := rand.New(rand.NewPCG(11, 12))
	for range 50_000 {
		var b strings.Builder
		for range 4 + rng.IntN(12) {
			b.WriteString(tokens[rng.IntN(len(tokens))])
		}
		check(b.String())
	}
}

// FuzzShellInjectionMatcherParity explores ASCII inputs for disagreements
// between the hand-written matcher and the rule's regexp. Inputs are masked
// to ASCII because only ASCII input reaches the matcher.
func FuzzShellInjectionMatcherParity(f *testing.F) {
	for _, witness := range shellAlternativeWitnesses {
		f.Add(witness)
	}
	f.Add("sid=abc123; theme=dark; ` echo")
	f.Add(benchChromeUA)
	shell := ruleByName(f, defaultRules(), "shell-injection")
	f.Fuzz(func(t *testing.T, raw string) {
		ascii := []byte(raw)
		for i := range ascii {
			ascii[i] &= 0x7f
		}
		raw = string(ascii)
		if got, want := matchShellInjection(newScanInput(raw).folded), shell.pattern.MatchString(raw); got != want {
			t.Fatalf("matcher on %q = %v, regex = %v", raw, got, want)
		}
	})
}

// TestShellAndXSSFragmentParity compares the filtered matchers with their
// plain patterns on random ASCII strings assembled from pattern fragments,
// covering both dense and sparse start bytes.
func TestShellAndXSSFragmentParity(t *testing.T) {
	t.Parallel()
	fragments := []string{
		";", "|", "$(", "$", "(", ")", "`", " ", "\t", "\n", "cat", "CAT", "ls", "sh", "bash", "id", "rm", "echo",
		"chown", "wget", "nc", "x", "_", "1", "=", "<", ">", "on", "ONload", "onclick", "on\tload", `"`, "'", "/",
		"javascript", ":", "document", ".", "cookie", "alert", "eval", "prompt", "script", "svg", "abcdefghijkl",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "sid=abc123; theme=dark",
	}
	rules := defaultRules()
	matchers := []*rule{ruleByName(t, rules, "xss"), ruleByName(t, rules, "shell-injection")}
	rng := rand.New(rand.NewPCG(7, 8))
	for i := range 200_000 {
		var b strings.Builder
		for range 1 + rng.IntN(16) {
			b.WriteString(fragments[rng.IntN(len(fragments))])
		}
		raw := b.String()
		in := newScanInput(raw)
		for _, rl := range matchers {
			if got, want := rl.matches(in), rl.pattern.MatchString(raw); got != want {
				t.Fatalf("iteration %d, rule %q on %q: filtered = %v, plain regex = %v", i, rl.name, raw, got, want)
			}
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
	witnesses := append(append(append([]string(nil), sqlAlternativeWitnesses...), xssAlternativeWitnesses...), shellAlternativeWitnesses...)
	for _, witness := range witnesses {
		variants := []string{witness, strings.ToUpper(witness), strings.NewReplacer("s", "ſ", "k", "K").Replace(witness)}
		for _, variant := range variants {
			corpus = append(corpus, variant, "prefix "+variant+" suffix", url.QueryEscape(variant), url.QueryEscape(url.QueryEscape(variant)),
				strings.Repeat(";", 16)+variant, strings.Repeat("x", 32)+"; "+variant)
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

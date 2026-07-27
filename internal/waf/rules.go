// Package waf implements a lightweight Web Application Firewall middleware
// that inspects incoming HTTP requests and blocks common attack patterns.
package waf

import (
	"regexp"
	"strings"
)

// scanInput is a string paired with its ASCII-lowercased form, so that the
// literal and prefilter checks fold each inspected value once per request
// rather than once per rule.
type scanInput struct {
	raw string
	// folded is raw with ASCII A-Z mapped to a-z. Only meaningful when
	// asciiOnly is true.
	folded string
	// asciiOnly reports whether raw consists entirely of bytes < 0x80.
	//
	// Prefilters are only sound for ASCII input. Go's (?i) uses Unicode
	// simple folding, so patterns such as (?i)system also match "ſystem"
	// (U+017F) and (?i)k also matches U+212A. An ASCII-only fold would miss
	// those and could wrongly suppress a rule. For any input containing a
	// byte >= 0x80 we skip the prefilter and run the pattern directly.
	asciiOnly bool
}

func newScanInput(raw string) scanInput {
	in := scanInput{raw: raw, asciiOnly: true}
	if raw == "" {
		in.folded = raw
		return in
	}

	needsFold := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 0x80 {
			in.asciiOnly = false
			return in
		}
		if c >= 'A' && c <= 'Z' {
			needsFold = true
		}
	}
	if !needsFold {
		in.folded = raw
		return in
	}

	buf := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	in.folded = string(buf)
	return in
}

// containsAnyFolded reports whether the folded input contains any literal.
// Literals must already be ASCII lowercase.
func containsAnyFolded(folded string, literals []string) bool {
	if folded == "" || len(literals) == 0 {
		return false
	}
	for _, lit := range literals {
		if strings.Contains(folded, lit) {
			return true
		}
	}
	return false
}

// target specifies which parts of an HTTP request a rule inspects.
type target int

const (
	targetPath    target = 1 << iota // URL path
	targetQuery                      // raw query string
	targetHeaders                    // header values (excluding Host)
	targetUA                         // User-Agent header only
	targetURI                        // full RequestURI
	targetBody                       // bounded request body preview
)

// rule is a single WAF detection pattern. A rule matches either via pattern
// or, when the detection is a plain case-insensitive substring set, via
// literals. Literal rules avoid the regexp engine entirely: a large
// case-insensitive alternation has no common prefix for the engine to anchor
// on, so it rescans from every byte offset and costs orders of magnitude more
// than a substring search.
type rule struct {
	name    string
	targets target
	pattern *regexp.Regexp
	// literals holds ASCII-lowercase substrings; when non-empty the rule
	// matches if any of them appears in the input, case-insensitively.
	literals []string
	// triggers holds ASCII-lowercase substrings that act as a prefilter for
	// pattern. Every alternative of pattern must require at least one
	// trigger, so an input containing none of them cannot match and can skip
	// the regexp engine entirely. Getting this wrong would silently disable a
	// rule, so TestRuleTriggersAreSound and FuzzRuleTriggers assert the
	// invariant "pattern matches => some trigger present" directly against
	// the compiled patterns.
	triggers []string
	// literalsFolded and triggersFolded mirror the above pre-lowercased, so
	// matching never allocates. Derived by defaultRules; never set by hand.
	literalsFolded []string
	triggersFolded []string
}

// matches reports whether the rule matches in.
func (r *rule) matches(in scanInput) bool {
	if in.raw == "" {
		return false
	}
	if len(r.literalsFolded) > 0 {
		if !in.asciiOnly {
			return containsAnyFoldSlow(in.raw, r.literals)
		}
		return containsAnyFolded(in.folded, r.literalsFolded)
	}
	if len(r.triggersFolded) > 0 && in.asciiOnly &&
		!containsAnyFolded(in.folded, r.triggersFolded) {
		return false
	}
	return r.pattern.MatchString(in.raw)
}

// containsAnyFoldSlow is the non-ASCII fallback for literal rules. It uses
// Unicode-aware case folding to match the semantics of a (?i) pattern.
func containsAnyFoldSlow(s string, literals []string) bool {
	lower := strings.ToLower(s)
	for _, lit := range literals {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}

// defaultRules returns the built-in WAF ruleset. Patterns are compiled once
// at startup; a panic here is a programming error caught immediately.
func defaultRules() []rule {
	rules := builtinRules()
	for i := range rules {
		rl := &rules[i]
		rl.literalsFolded = foldAll(rl.literals)
		rl.triggersFolded = foldAll(rl.triggers)
	}
	return rules
}

func foldAll(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.ToLower(v)
	}
	return out
}

func builtinRules() []rule {
	return []rule{
		{
			name:     "sql-injection",
			triggers: []string{"union", ";", "'", "\"", "/*", "benchmark", "sleep", "waitfor", "load_file", "into"},
			targets:  targetPath | targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`union(?:\s|/\*[^*]*\*/)+(?:all(?:\s|/\*[^*]*\*/)+)?select` +
					`|;\s*(?:drop|delete|insert|update|alter)\s` +
					`|'\s*(?:or|and)\s+['"\d].*=` +
					`|"\s*(?:or|and)\s+['"\d].*=` +
					`|'\s*;\s*--` +
					// Comment-based whitespace obfuscation: a SQL keyword
					// directly adjacent to an inline comment (UNION/**/SELECT,
					// 1/**/OR/**/1=1). Bare /*...*/ comments are too common in
					// legitimate code and CSS to match on their own.
					`|\b(?:union|select|or|and|where|from)/\*[^*]*\*/` +
					`|/\*[^*]*\*/(?:union|select|or|and|where|from)\b` +
					// MySQL hex-string literal. Bare 0x... literals are not
					// matched: they appear in benign IDs, hashes, and web3
					// addresses far more often than in injections.
					`|x'[0-9a-f]+'` +
					`|(?:benchmark|sleep|waitfor)\s*\(` +
					`|(?:load_file|into\s+outfile|into\s+dumpfile)\s*\(` +
					`)`,
			),
		},
		{
			name:     "xss",
			triggers: []string{"<", "javascript", "on", "document", "alert", "confirm", "prompt", "eval"},
			targets:  targetPath | targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`<\s*script` +
					`|javascript\s*:` +
					// Event handlers need markup or attribute-breakout context:
					// inside a tag, or a known handler name preceded by a
					// separator. A bare on\w+= matches benign params like
					// only=true or once=1.
					`|<[^>]*\bon\w+\s*=` +
					`|[\s"'/\x60]on(?:abort|animation\w*|auxclick|beforeunload|blur|canplay\w*|change|click|contextmenu|copy|cut|dblclick|drag\w*|drop|error|focus\w*|hashchange|input|invalid|key\w+|load\w*|message\w*|mouse\w+|paste|pause|play\w*|pointer\w+|popstate|reset|resize|scroll|select\w*|storage|submit|toggle|touch\w+|transition\w*|unload|wheel)\s*=` +
					`|document\s*\.\s*(?:cookie|location|write)` +
					`|<\s*(?:iframe|object|embed|form|svg|math)[\s>]` +
					`|(?:alert|confirm|prompt|eval)\s*\(` +
					`)`,
			),
		},
		{
			name:     "path-traversal",
			triggers: []string{"..", "%00"},
			targets:  targetURI,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`\.\.[\\/]` +
					`|\.\.%2[fF]` +
					`|\.\.%5[cC]` +
					`|%00` +
					`)`,
			),
		},
		{
			name:     "shell-injection",
			triggers: []string{"$(", "`", "|", ";"},
			targets:  targetQuery | targetHeaders | targetBody,
			// Substitution syntax ($(...), backticks) only counts when it
			// wraps a known command: bare $( matches jQuery snippets and bare
			// backtick pairs match Markdown code spans in ordinary content.
			pattern: regexp.MustCompile(
				"(?i)(?:" +
					`\$\(\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown|whoami|id|uname|echo|rm)\b` +
					"|`\\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown|whoami|id|uname|echo|rm)\\b[^`]*`" +
					`|\|\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown)\b` +
					`|;\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown)\b` +
					")",
			),
		},
		{
			name:     "log4shell-jndi",
			triggers: []string{"${"},
			targets:  targetPath | targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)\$\{.*?(?:jndi|java)\s*:`,
			),
		},
		{
			// Every entry is a plain literal, so this rule uses a substring
			// scan rather than a case-insensitive regexp alternation.
			name:    "scanner-ua",
			targets: targetUA,
			literals: []string{
				"sqlmap",
				"nikto",
				"nmap",
				"masscan",
				"dirbuster",
				"gobuster",
				"nuclei",
				"zgrab",
				"httpx-toolkit",
				"nessus",
				"openvas",
				"acunetix",
				"w3af",
				"arachni",
				"burpsuite",
				"havij",
				"commix",
				"wpscan",
				"whatweb",
				"joomscan",
				"ffuf",
				"feroxbuster",
				"subfinder",
				"amass",
				"fierce",
				"wfuzz",
				"jaeles",
				"xray",
			},
		},
		{
			name:     "header-injection",
			triggers: []string{"\r", "\n"},
			targets:  targetHeaders,
			pattern:  regexp.MustCompile(`[\r\n]`),
		},
		{
			name:     "sensitive-file-probe",
			triggers: []string{".", "/wp-admin", "/wp-login", "/phpmy", "/cgi-bin/", "/etc/passwd", "/etc/shadow", "/proc/self/environ", "/proc/1/environ", "/wp-content/uploads/", "/autodiscover/"},
			targets:  targetPath,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// Hidden files/directories anywhere in the path. /.well-known
					// is exempted in path matching code to allow standards like
					// ACME and security.txt.
					`(?:^|/)\.[^/]+(?:/|$)` +
					`|/wp-admin` +
					`|/wp-login` +
					`|/phpmy` +
					`|/cgi-bin/` +
					`|/etc/passwd` +
					`|/etc/shadow` +
					`|/proc/self/environ` +
					`|/proc/1/environ` +
					`|/wp-content/uploads/` +
					`|/autodiscover/` +
					`)`,
			),
		},
		{
			name:     "protocol-attack",
			triggers: []string{"<?", "<%", "data"},
			targets:  targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`<\?(?:php|=)` +
					`|<%[^>]*%>` +
					// Only script-capable data URIs. Matching every base64
					// data URI blocks benign inline images and fonts.
					`|\bdata\s*:\s*(?:text/html|image/svg|application/xhtml)` +
					`)`,
			),
		},
		{
			name:     "ssrf",
			triggers: []string{"169.254.169.254", "metadata.google.internal", "100.100.100.200", "http", "file://", "gopher://"},
			targets:  targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// AWS / cloud metadata endpoints
					`169\.254\.169\.254` +
					`|metadata\.google\.internal` +
					`|100\.100\.100\.200` + // Alibaba metadata
					// Internal network ranges in URL context
					`|(?:https?://)(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\])` +
					// file:// and gopher:// schemes
					`|\bfile://` +
					`|\bgopher://` +
					`)`,
			),
		},
		{
			name:     "xxe",
			triggers: []string{"<!doctype", "<!entity", "system"},
			targets:  targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`<!DOCTYPE[^>]*\[` +
					`|<!ENTITY` +
					`|SYSTEM\s+["']file://` +
					`|SYSTEM\s+["']https?://` +
					`)`,
			),
		},
		{
			name:     "ssti",
			triggers: []string{"{{", "<#assign", "${t(", "<%"},
			targets:  targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					// Jinja2 / Twig / Django
					`\{\{.*(?:config|self|request|lipsum|cycler|joiner|namespace)` +
					// Jinja2 class traversal
					`|\{\{.*\.__class__` +
					// Freemarker
					`|<#assign\b` +
					// Thymeleaf / Spring EL
					`|\$\{T\(` +
					// Mako
					`|<%!?\s*import\b` +
					`)`,
			),
		},
	}
}

// Package waf implements a lightweight Web Application Firewall middleware
// that inspects incoming HTTP requests and blocks common attack patterns.
package waf

import "regexp"

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

// rule is a single WAF detection pattern.
type rule struct {
	name    string
	targets target
	pattern *regexp.Regexp
}

// defaultRules returns the built-in WAF ruleset. Patterns are compiled once
// at startup; a panic here is a programming error caught immediately.
func defaultRules() []rule {
	return []rule{
		{
			name:    "sql-injection",
			targets: targetPath | targetQuery | targetHeaders | targetBody,
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
			name:    "xss",
			targets: targetPath | targetQuery | targetHeaders | targetBody,
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
			name:    "path-traversal",
			targets: targetURI,
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
			name:    "shell-injection",
			targets: targetQuery | targetHeaders | targetBody,
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
			name:    "log4shell-jndi",
			targets: targetPath | targetQuery | targetHeaders | targetBody,
			pattern: regexp.MustCompile(
				`(?i)\$\{.*?(?:jndi|java)\s*:`,
			),
		},
		{
			name:    "scanner-ua",
			targets: targetUA,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`sqlmap` +
					`|nikto` +
					`|nmap` +
					`|masscan` +
					`|dirbuster` +
					`|gobuster` +
					`|nuclei` +
					`|zgrab` +
					`|httpx-toolkit` +
					`|nessus` +
					`|openvas` +
					`|acunetix` +
					`|w3af` +
					`|arachni` +
					`|burpsuite` +
					`|havij` +
					`|commix` +
					`|wpscan` +
					`|whatweb` +
					`|joomscan` +
					`|ffuf` +
					`|feroxbuster` +
					`|subfinder` +
					`|amass` +
					`|fierce` +
					`|wfuzz` +
					`|jaeles` +
					`|xray` +
					`)`,
			),
		},
		{
			name:    "header-injection",
			targets: targetHeaders,
			pattern: regexp.MustCompile(`[\r\n]`),
		},
		{
			name:    "sensitive-file-probe",
			targets: targetPath,
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
			name:    "protocol-attack",
			targets: targetQuery | targetHeaders | targetBody,
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
			name:    "ssrf",
			targets: targetQuery | targetHeaders | targetBody,
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
			name:    "xxe",
			targets: targetQuery | targetHeaders | targetBody,
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
			name:    "ssti",
			targets: targetQuery | targetHeaders | targetBody,
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

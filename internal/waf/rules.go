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
			targets: targetPath | targetQuery | targetHeaders,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`union\s+(?:all\s+)?select` +
					`|;\s*(?:drop|delete|insert|update|alter)\s` +
					`|'\s*(?:or|and)\s+['"\d].*=` +
					`|"\s*(?:or|and)\s+['"\d].*=` +
					`|'\s*;\s*--` +
					`|/\*[^*]*\*/` +
					`|(?:0x[0-9a-f]+|x'[0-9a-f]+')` +
					`|(?:benchmark|sleep|waitfor)\s*\(` +
					`|(?:load_file|into\s+outfile|into\s+dumpfile)\s*\(` +
					`)`,
			),
		},
		{
			name:    "xss",
			targets: targetPath | targetQuery | targetHeaders,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`<\s*script` +
					`|javascript\s*:` +
					`|\bon\w+\s*=` +
					`|<\s*img[^>]+onerror` +
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
			targets: targetQuery | targetHeaders,
			pattern: regexp.MustCompile(
				"(?i)(?:" +
					`\$\(` +
					"|`[^`]+`" +
					`|\|\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown)\b` +
					`|;\s*(?:cat|ls|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown)\b` +
					")",
			),
		},
		{
			name:    "log4shell-jndi",
			targets: targetPath | targetQuery | targetHeaders,
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
			targets: targetQuery | targetHeaders,
			pattern: regexp.MustCompile(
				`(?i)(?:` +
					`<\?(?:php|=)` +
					`|<%[^>]*%>` +
					`|\bdata\s*:.*base64` +
					`)`,
			),
		},
		{
			name:    "ssrf",
			targets: targetQuery | targetHeaders,
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
			targets: targetQuery | targetHeaders,
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
			targets: targetQuery | targetHeaders,
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

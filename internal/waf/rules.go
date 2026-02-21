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
					`/\.env` +
					`|/\.git/` +
					`|/\.git$` +
					`|/wp-admin` +
					`|/wp-login` +
					`|/phpmy` +
					`|/cgi-bin/` +
					`|/\.aws/` +
					`|/\.ssh/` +
					`|/etc/passwd` +
					`|/etc/shadow` +
					`|/\.docker/` +
					`|/\.kube/` +
					`|/\.config/` +
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
	}
}

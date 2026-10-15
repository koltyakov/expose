package waf

import (
	"slices"
	"strings"
)

// Commands that make '|' or ';' a shell-injection match. Command substitution,
// $(...) or backticks, also accepts shellSubstitutionCommands. The rule's
// regexp and matchShellInjection are both built from these lists.
var (
	shellPipeCommands         = []string{"cat", "ls", "curl", "wget", "nc", "bash", "sh", "python", "perl", "ruby", "chmod", "chown"}
	shellSubstitutionCommands = append(slices.Clip(shellPipeCommands), "whoami", "id", "uname", "echo", "rm")
)

// matchShellInjection evaluates the shell-injection pattern directly on
// ASCII-lowercased input. Every cookie header contains ';', and the regexp
// engine retries the whole alternation at every offset, which made this the
// costliest check on ordinary browser requests. This is one linear scan.
//
// It must report exactly what the pattern reports for every ASCII input. The
// regexp still decides non-ASCII input and is the reference for
// TestShellInjectionMatcherParity and FuzzRuleMatchesRegexParity.
func matchShellInjection(folded string) bool {
	for i := 0; i < len(folded); i++ {
		commands := shellPipeCommands
		next := i + 1
		switch folded[i] {
		case '|', ';':
		case '`':
			commands = shellSubstitutionCommands
		case '$':
			if next >= len(folded) || folded[next] != '(' {
				continue
			}
			commands = shellSubstitutionCommands
			next++
		default:
			continue
		}
		for next < len(folded) && isRegexpSpace(folded[next]) {
			next++
		}
		end := shellCommandEnd(folded, next, commands)
		if end < 0 {
			continue
		}
		// A backtick substitution also needs its closing backtick.
		if folded[i] == '`' && strings.IndexByte(folded[end:], '`') < 0 {
			continue
		}
		return true
	}
	return false
}

// shellCommandEnd returns where the command starting at pos ends when it is
// one of commands followed by a word boundary (\b), or -1.
func shellCommandEnd(folded string, pos int, commands []string) int {
	rest := folded[pos:]
	for _, command := range commands {
		if strings.HasPrefix(rest, command) && (len(rest) == len(command) || !isRegexpWordByte(rest[len(command)])) {
			return pos + len(command)
		}
	}
	return -1
}

// isRegexpSpace reports whether c is in regexp's \s class: tab, newline, form
// feed, carriage return and space, but not vertical tab.
func isRegexpSpace(c byte) bool {
	return c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

// isRegexpWordByte reports whether c is in regexp's ASCII \w class.
func isRegexpWordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_'
}

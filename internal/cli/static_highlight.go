// Syntax highlighting for fenced code blocks in rendered markdown pages.
package cli

import (
	"html"
	"strings"
	"unicode"
	"unicode/utf8"
)

func highlightCodeBlock(lang, code string) string {
	normalized := normalizeCodeLanguage(lang)
	switch normalized {
	case "go":
		return highlightCodeLike(code, codeHighlightSpec{
			keywords:     []string{"break", "case", "chan", "const", "continue", "default", "defer", "else", "fallthrough", "for", "func", "go", "goto", "if", "import", "interface", "map", "package", "range", "return", "select", "struct", "switch", "type", "var"},
			types:        []string{"any", "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr"},
			lineComment:  "//",
			blockComment: true,
			singleQuote:  true,
			doubleQuote:  true,
			backtick:     true,
		})
	case "js", "ts":
		return highlightCodeLike(code, codeHighlightSpec{
			keywords:     []string{"async", "await", "break", "case", "catch", "class", "const", "continue", "default", "delete", "else", "export", "extends", "finally", "for", "from", "function", "if", "import", "in", "instanceof", "let", "new", "of", "return", "static", "super", "switch", "this", "throw", "try", "typeof", "var", "while", "yield"},
			types:        []string{"boolean", "number", "string", "object", "undefined", "null", "void", "unknown", "never"},
			lineComment:  "//",
			blockComment: true,
			singleQuote:  true,
			doubleQuote:  true,
			backtick:     true,
		})
	case "json":
		return highlightJSON(code)
	case "yaml":
		return highlightYAML(code)
	case "sh", "bash", "zsh", "shell":
		return highlightShell(code)
	case "html", "xml":
		return highlightMarkup(code)
	case "css":
		return highlightCSS(code)
	default:
		return html.EscapeString(code)
	}
}

func normalizeCodeLanguage(lang string) string {
	lang = strings.ToLower(strings.TrimSpace(lang))
	switch lang {
	case "golang":
		return "go"
	case "javascript":
		return "js"
	case "typescript":
		return "ts"
	case "yml":
		return "yaml"
	case "shellscript", "console":
		return "sh"
	default:
		return lang
	}
}

type codeHighlightSpec struct {
	keywords     []string
	types        []string
	lineComment  string
	blockComment bool
	singleQuote  bool
	doubleQuote  bool
	backtick     bool
}

func highlightCodeLike(code string, spec codeHighlightSpec) string {
	keywordSet := make(map[string]struct{}, len(spec.keywords))
	for _, v := range spec.keywords {
		keywordSet[v] = struct{}{}
	}
	typeSet := make(map[string]struct{}, len(spec.types))
	for _, v := range spec.types {
		typeSet[v] = struct{}{}
	}
	var out strings.Builder
	for i := 0; i < len(code); {
		if spec.lineComment != "" && strings.HasPrefix(code[i:], spec.lineComment) {
			j := i + len(spec.lineComment)
			for j < len(code) && code[j] != '\n' {
				j++
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if spec.blockComment && strings.HasPrefix(code[i:], "/*") {
			j := i + 2
			for j+1 < len(code) && code[j:j+2] != "*/" {
				j++
			}
			if j+1 < len(code) {
				j += 2
			} else {
				j = len(code)
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if (spec.singleQuote && code[i] == '\'') || (spec.doubleQuote && code[i] == '"') || (spec.backtick && code[i] == '`') {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if quote != '`' && code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && isCodeNumberPart(code[j]) {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) {
			j := i + 1
			for j < len(code) && isCodeIdentPart(code[j]) {
				j++
			}
			word := code[i:j]
			if _, ok := keywordSet[word]; ok {
				writeToken(&out, "tok-keyword", word)
			} else if _, ok := typeSet[word]; ok {
				writeToken(&out, "tok-type", word)
			} else if nextNonSpaceByte(code, j) == '(' {
				writeToken(&out, "tok-func", word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		if strings.ContainsRune("{}[]():.,;", rune(code[i])) {
			writeToken(&out, "tok-punct", code[i:i+1])
		} else {
			out.WriteString(html.EscapeString(code[i : i+1]))
		}
		i++
	}
	return out.String()
}

func highlightShell(code string) string {
	keywords := map[string]struct{}{
		"if": {}, "then": {}, "else": {}, "elif": {}, "fi": {}, "for": {}, "in": {}, "do": {}, "done": {},
		"case": {}, "esac": {}, "while": {}, "until": {}, "function": {}, "select": {}, "time": {}, "coproc": {},
	}
	builtins := map[string]struct{}{
		"cd": {}, "echo": {}, "exit": {}, "export": {}, "local": {}, "readonly": {}, "return": {}, "set": {}, "shift": {}, "source": {}, "unset": {},
	}
	var out strings.Builder
	for i := 0; i < len(code); {
		if code[i] == '#' {
			j := i + 1
			for j < len(code) && code[j] != '\n' {
				j++
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if code[i] == '\'' || code[i] == '"' {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if quote == '"' && code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if code[i] == '$' {
			j := i + 1
			if j < len(code) && code[j] == '{' {
				j++
				for j < len(code) && code[j] != '}' {
					j++
				}
				if j < len(code) {
					j++
				}
			} else {
				for j < len(code) && (isCodeIdentPart(code[j]) || code[j] == '@' || code[j] == '*' || code[j] == '#') {
					j++
				}
			}
			writeToken(&out, "tok-var", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) {
			j := i + 1
			for j < len(code) && isCodeIdentPart(code[j]) {
				j++
			}
			word := code[i:j]
			if _, ok := keywords[word]; ok {
				writeToken(&out, "tok-keyword", word)
			} else if _, ok := builtins[word]; ok {
				writeToken(&out, "tok-func", word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		out.WriteString(html.EscapeString(code[i : i+1]))
		i++
	}
	return out.String()
}

func highlightJSON(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); {
		if code[i] == '"' {
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == '"' {
					j++
					break
				}
				j++
			}
			token := code[i:j]
			className := "tok-string"
			if nextNonSpaceByte(code, j) == ':' {
				className = "tok-attr"
			}
			writeToken(&out, className, token)
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && isCodeNumberPart(code[j]) {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		for _, literal := range []string{"true", "false", "null"} {
			if strings.HasPrefix(code[i:], literal) && !isCodeIdentBoundary(code, i-1) && !isCodeIdentBoundary(code, i+len(literal)) {
				writeToken(&out, "tok-keyword", literal)
				i += len(literal)
				goto nextJSON
			}
		}
		if strings.ContainsRune("{}[]:,", rune(code[i])) {
			writeToken(&out, "tok-punct", code[i:i+1])
		} else {
			out.WriteString(html.EscapeString(code[i : i+1]))
		}
		i++
	nextJSON:
	}
	return out.String()
}

func highlightYAML(code string) string {
	lines := strings.SplitAfter(code, "\n")
	var out strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		indentLen := len(line) - len(trimmed)
		out.WriteString(html.EscapeString(line[:indentLen]))
		if strings.HasPrefix(strings.TrimSpace(trimmed), "#") {
			writeToken(&out, "tok-comment", strings.TrimRight(trimmed, "\n"))
			if strings.HasSuffix(line, "\n") {
				out.WriteString("\n")
			}
			continue
		}
		if key, rest, ok := splitStaticYAMLKeyValue(strings.TrimRight(trimmed, "\n")); ok {
			writeToken(&out, "tok-attr", key)
			writeToken(&out, "tok-punct", ":")
			if rest != "" {
				out.WriteString(" ")
				out.WriteString(highlightYAMLScalar(rest))
			}
			if strings.HasSuffix(line, "\n") {
				out.WriteString("\n")
			}
			continue
		}
		out.WriteString(highlightYAMLScalar(strings.TrimRight(trimmed, "\n")))
		if strings.HasSuffix(line, "\n") {
			out.WriteString("\n")
		}
	}
	return out.String()
}

func splitStaticYAMLKeyValue(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, "- ") {
		return "", "", false
	}
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", "", false
	}
	return line[:idx], strings.TrimSpace(line[idx+1:]), true
}

func highlightYAMLScalar(s string) string {
	switch s {
	case "true", "false", "null", "~":
		return wrapToken("tok-keyword", s)
	}
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return wrapToken("tok-string", s)
	}
	if len(s) > 0 && isCodeNumberStart(s, 0) {
		allNum := true
		for i := 1; i < len(s); i++ {
			if !isCodeNumberPart(s[i]) {
				allNum = false
				break
			}
		}
		if allNum {
			return wrapToken("tok-number", s)
		}
	}
	return html.EscapeString(s)
}

func highlightMarkup(code string) string {
	// Scan only the source, never the spans we emit. Escaping happens once,
	// after token boundaries are known, so entities and whitespace stay intact.
	var out strings.Builder
	out.Grow(len(code))
	for i := 0; i < len(code); {
		if code[i] != '<' {
			j := strings.IndexByte(code[i:], '<')
			if j < 0 {
				j = len(code) - i
			}
			writeMarkupText(&out, code[i:i+j])
			i += j
			continue
		}
		if strings.HasPrefix(code[i:], "<!--") {
			j := strings.Index(code[i+4:], "-->")
			if j < 0 {
				j = len(code)
			} else {
				j += i + 7
			}
			writeMarkupToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if strings.HasPrefix(code[i:], "<![CDATA[") {
			writeMarkupToken(&out, "tok-tag", code[i:i+9])
			i += 9
			j := strings.Index(code[i:], "]]>")
			if j < 0 {
				writeMarkupText(&out, code[i:])
				break
			}
			writeMarkupText(&out, code[i:i+j])
			i += j
			writeMarkupToken(&out, "tok-tag", code[i:i+3])
			i += 3
			continue
		}
		j := i + 1
		if j < len(code) && (code[j] == '/' || code[j] == '?' || code[j] == '!') {
			j++
		}
		end := markupNameEnd(code, j)
		if end == j {
			writeMarkupText(&out, code[i:i+1])
			i++
			continue
		}
		writeMarkupToken(&out, "tok-tag", code[i:end])
		i = highlightMarkupAttributes(&out, code, end)
	}
	return out.String()
}

func highlightMarkupAttributes(out *strings.Builder, code string, i int) int {
	value := false
	for i < len(code) {
		if code[i] == '>' || ((code[i] == '/' || code[i] == '?') && i+1 < len(code) && code[i+1] == '>') {
			j := i + 1
			if code[i] != '>' {
				j++
			}
			writeMarkupToken(out, "tok-tag", code[i:j])
			return j
		}
		if strings.ContainsRune(" \t\r\n\f", rune(code[i])) {
			j := i + 1
			for j < len(code) && strings.ContainsRune(" \t\r\n\f", rune(code[j])) {
				j++
			}
			writeMarkupText(out, code[i:j])
			i = j
			continue
		}
		if code[i] == '"' || code[i] == '\'' {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeMarkupToken(out, "tok-string", code[i:j])
			i, value = j, false
			continue
		}
		if code[i] == '=' {
			writeMarkupToken(out, "tok-punct", code[i:i+1])
			i++
			value = true
			continue
		}
		if value {
			j := i
			for j < len(code) && !strings.ContainsRune(" \t\r\n\f>", rune(code[j])) {
				if (code[j] == '/' || code[j] == '?') && j+1 < len(code) && code[j+1] == '>' {
					break
				}
				j++
			}
			writeMarkupToken(out, "tok-string", code[i:j])
			i, value = j, false
			continue
		}
		if j := markupNameEnd(code, i); j > i {
			writeMarkupToken(out, "tok-attr", code[i:j])
			i = j
			continue
		}
		writeMarkupText(out, code[i:i+1])
		i++
	}
	return i
}

func markupNameEnd(code string, i int) int {
	j := i
	for j < len(code) {
		r, size := utf8.DecodeRuneInString(code[j:])
		valid := r == '_' || r == ':' || unicode.IsLetter(r)
		if j > i {
			valid = valid || r == '-' || r == '.' || unicode.IsDigit(r) || unicode.IsMark(r)
		}
		if !valid {
			break
		}
		j += size
	}
	return j
}

func writeMarkupToken(out *strings.Builder, className, text string) {
	out.WriteString(`<span class="`)
	out.WriteString(className)
	out.WriteString(`">`)
	writeMarkupText(out, text)
	out.WriteString(`</span>`)
}

func writeMarkupText(out *strings.Builder, text string) {
	start := 0
	for i := 0; i < len(text); i++ {
		var escaped string
		switch text[i] {
		case '&':
			escaped = "&amp;"
		case '<':
			escaped = "&lt;"
		case '>':
			escaped = "&gt;"
		case '"':
			escaped = "&#34;"
		case '\'':
			escaped = "&#39;"
		case '\r':
			// Literal CR is normalized by HTML parsers, unlike a character reference.
			escaped = "&#13;"
		default:
			continue
		}
		out.WriteString(text[start:i])
		out.WriteString(escaped)
		start = i + 1
	}
	out.WriteString(text[start:])
}

func highlightCSS(code string) string {
	var out strings.Builder
	for i := 0; i < len(code); {
		if strings.HasPrefix(code[i:], "/*") {
			j := i + 2
			for j+1 < len(code) && code[j:j+2] != "*/" {
				j++
			}
			if j+1 < len(code) {
				j += 2
			} else {
				j = len(code)
			}
			writeToken(&out, "tok-comment", code[i:j])
			i = j
			continue
		}
		if code[i] == '"' || code[i] == '\'' {
			quote := code[i]
			j := i + 1
			for j < len(code) {
				if code[j] == '\\' && j+1 < len(code) {
					j += 2
					continue
				}
				if code[j] == quote {
					j++
					break
				}
				j++
			}
			writeToken(&out, "tok-string", code[i:j])
			i = j
			continue
		}
		if isCodeIdentStart(code[i]) || code[i] == '.' || code[i] == '#' {
			j := i + 1
			for j < len(code) && (isCodeIdentPart(code[j]) || strings.ContainsRune(".#-%", rune(code[j]))) {
				j++
			}
			word := code[i:j]
			next := nextNonSpaceByte(code, j)
			className := ""
			switch next {
			case ':':
				className = "tok-attr"
			case '{':
				className = "tok-tag"
			}
			if className != "" {
				writeToken(&out, className, word)
			} else {
				out.WriteString(html.EscapeString(word))
			}
			i = j
			continue
		}
		if isCodeNumberStart(code, i) {
			j := i + 1
			for j < len(code) && (isCodeNumberPart(code[j]) || unicode.IsLetter(rune(code[j])) || code[j] == '%') {
				j++
			}
			writeToken(&out, "tok-number", code[i:j])
			i = j
			continue
		}
		out.WriteString(html.EscapeString(code[i : i+1]))
		i++
	}
	return out.String()
}

func writeToken(out *strings.Builder, className, text string) {
	out.WriteString(wrapToken(className, text))
}

func wrapToken(className, text string) string {
	return `<span class="` + className + `">` + html.EscapeString(text) + `</span>`
}

func isCodeIdentStart(b byte) bool {
	return b == '_' || unicode.IsLetter(rune(b))
}

func isCodeIdentPart(b byte) bool {
	return isCodeIdentStart(b) || (b >= '0' && b <= '9')
}

func isCodeNumberStart(s string, i int) bool {
	if i < 0 || i >= len(s) || s[i] < '0' || s[i] > '9' {
		return false
	}
	return i == 0 || !isCodeIdentPart(s[i-1])
}

func isCodeNumberPart(b byte) bool {
	return (b >= '0' && b <= '9') || b == '.' || b == '_' || b == 'x' || b == 'X' || b == 'a' || b == 'b' || b == 'c' || b == 'd' || b == 'e' || b == 'E' || b == 'f' || b == 'F' || b == '+' || b == '-'
}

func nextNonSpaceByte(s string, i int) byte {
	for i < len(s) {
		if !unicode.IsSpace(rune(s[i])) {
			return s[i]
		}
		i++
	}
	return 0
}

func isCodeIdentBoundary(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return true
	}
	return !isCodeIdentPart(s[i])
}

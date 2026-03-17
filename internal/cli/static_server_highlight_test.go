package cli

import (
	"strings"
	"testing"
)

func TestNormalizeCodeLanguage(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"golang":      "go",
		"javascript":  "js",
		"typescript":  "ts",
		"yml":         "yaml",
		"shellscript": "sh",
		"console":     "sh",
		" css ":       "css",
	}
	for input, want := range tests {
		if got := normalizeCodeLanguage(input); got != want {
			t.Fatalf("normalizeCodeLanguage(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHighlightCodeBlockSupportsLanguages(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		lang     string
		code     string
		contains []string
	}{
		{name: "go", lang: "golang", code: "package main\nfunc run() {}\n", contains: []string{`tok-keyword`, `tok-func`, `tok-punct`}},
		{name: "js", lang: "javascript", code: "const run = async () => value\n", contains: []string{`tok-keyword`, `tok-punct`}},
		{name: "json", lang: "json", code: "{\"name\": 42}", contains: []string{`tok-attr`, `tok-number`, `tok-punct`}},
		{name: "yaml", lang: "yml", code: "name: 42\n", contains: []string{`tok-attr`, `tok-number`}},
		{name: "shell", lang: "shellscript", code: "echo \"$HOME\"\n", contains: []string{`tok-func`, `tok-string`}},
		{name: "markup", lang: "html", code: "<div class=\"x\">ok</div>", contains: []string{`tok-tag`, `tok-attr`, `tok-string`}},
		{name: "css", lang: "css", code: ".box { color: red; width: 10px; }\n", contains: []string{`tok-tag`, `tok-attr`, `tok-number`}},
	}

	for _, tc := range cases {
		out := highlightCodeBlock(tc.lang, tc.code)
		for _, want := range tc.contains {
			if !strings.Contains(out, want) {
				t.Fatalf("%s output missing %q: %s", tc.name, want, out)
			}
		}
	}

	plain := highlightCodeBlock("unknown", "<raw>")
	if plain != "&lt;raw&gt;" {
		t.Fatalf("highlightCodeBlock(unknown) = %q, want escaped fallback", plain)
	}
}

func TestHighlightShell(t *testing.T) {
	t.Parallel()

	out := highlightShell("if true; then echo \"$HOME\" # hi\nfi\n")
	for _, want := range []string{`tok-keyword`, `tok-func`, `tok-string`, `tok-comment`} {
		if !strings.Contains(out, want) {
			t.Fatalf("highlightShell() missing %q: %s", want, out)
		}
	}
}

func TestHighlightJSON(t *testing.T) {
	t.Parallel()

	out := highlightJSON("{\"name\": 42, \"tags\": [\"a\"]}")
	for _, want := range []string{`tok-attr`, `tok-number`, `tok-punct`, `tok-string`} {
		if !strings.Contains(out, want) {
			t.Fatalf("highlightJSON() missing %q: %s", want, out)
		}
	}
}

func TestHighlightYAMLAndHelpers(t *testing.T) {
	t.Parallel()

	out := highlightYAML("name: 42\nquoted: \"x\"\n# note\n- item\n")
	for _, want := range []string{`tok-attr`, `tok-number`, `tok-string`, `tok-comment`} {
		if !strings.Contains(out, want) {
			t.Fatalf("highlightYAML() missing %q: %s", want, out)
		}
	}

	if key, rest, ok := splitStaticYAMLKeyValue("name: value"); !ok || key != "name" || rest != "value" {
		t.Fatalf("splitStaticYAMLKeyValue() = %q, %q, %v", key, rest, ok)
	}
	if _, _, ok := splitStaticYAMLKeyValue("- item"); ok {
		t.Fatal("splitStaticYAMLKeyValue(list item) = ok, want false")
	}
	if got := highlightYAMLScalar("true"); !strings.Contains(got, `tok-keyword`) {
		t.Fatalf("highlightYAMLScalar(true) = %s", got)
	}
	if got := highlightYAMLScalar("\"x\""); !strings.Contains(got, `tok-string`) {
		t.Fatalf("highlightYAMLScalar(string) = %s", got)
	}
	if got := highlightYAMLScalar("12.5"); !strings.Contains(got, `tok-number`) {
		t.Fatalf("highlightYAMLScalar(number) = %s", got)
	}
}

func TestHighlightMarkupAndCSS(t *testing.T) {
	t.Parallel()

	markup := highlightMarkup("<!-- note --><div class=\"hero\">Hi</div>")
	for _, want := range []string{`tok-comment`, `tok-tag`, `tok-attr`, `tok-string`} {
		if !strings.Contains(markup, want) {
			t.Fatalf("highlightMarkup() missing %q: %s", want, markup)
		}
	}

	css := highlightCSS("/* note */\n.box { color: red; width: 10px; content: \"x\"; }\n")
	for _, want := range []string{`tok-comment`, `tok-tag`, `tok-attr`, `tok-number`, `tok-string`} {
		if !strings.Contains(css, want) {
			t.Fatalf("highlightCSS() missing %q: %s", want, css)
		}
	}
}

func TestCodeHelpers(t *testing.T) {
	t.Parallel()

	if got := padMarkdownTableRow([]string{"a"}, 3); len(got) != 3 || got[0] != "a" || got[1] != "" {
		t.Fatalf("padMarkdownTableRow() = %#v", got)
	}
	if !isCodeNumberPart('x') || !isCodeNumberPart('+') || isCodeNumberPart('z') {
		t.Fatal("isCodeNumberPart() returned unexpected result")
	}
	if got := nextNonSpaceByte("  x", 0); got != 'x' {
		t.Fatalf("nextNonSpaceByte() = %q, want %q", got, 'x')
	}
	if !isCodeIdentBoundary("x+y", 1) {
		t.Fatal("isCodeIdentBoundary(+) = false, want true")
	}
	if isCodeIdentBoundary("word", 1) {
		t.Fatal("isCodeIdentBoundary(in-word) = true, want false")
	}
}

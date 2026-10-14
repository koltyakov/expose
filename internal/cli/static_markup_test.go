package cli

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
	xatom "golang.org/x/net/html/atom"
)

func TestHighlightMarkupTokensAndRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		code string
		want map[string][]string
	}{
		{
			name: "HTML comments and attributes",
			code: "<!-- <script>bad()</script> --><div\tclass = \"hero\"\r\n disabled data-id='a&b' n=42>Hi &lt;x&gt;</div>",
			want: map[string][]string{
				"tok-comment": {"<!-- <script>bad()</script> -->"},
				"tok-tag":     {"<div", ">", "</div", ">"},
				"tok-attr":    {"class", "disabled", "data-id", "n"},
				"tok-punct":   {"=", "=", "="},
				"tok-string":  {`"hero"`, "'a&b'", "42"},
			},
		},
		{
			name: "XML unicode names and processing instruction",
			code: `<?xml version="1.0"?><ns:élément 名="雪" café́='é' />`,
			want: map[string][]string{
				"tok-tag":    {"<?xml", "?>", "<ns:élément", "/>"},
				"tok-attr":   {"version", "名", "café́"},
				"tok-punct":  {"=", "=", "="},
				"tok-string": {`"1.0"`, `"雪"`, "'é'"},
			},
		},
		{
			name: "escaped quotes and raw angles",
			code: `<a title="say \"<hello>\" &quot;" value='it\'s >'>x</a>`,
			want: map[string][]string{
				"tok-tag":    {"<a", ">", "</a", ">"},
				"tok-attr":   {"title", "value"},
				"tok-punct":  {"=", "="},
				"tok-string": {`"say \"<hello>\" &quot;"`, `'it\'s >'`},
			},
		},
		{
			name: "CDATA does not tokenize embedded markup",
			code: `<![CDATA[<script x="y">&amp;</script>]]>`,
			want: map[string][]string{"tok-tag": {"<![CDATA[", "]]>"}},
		},
		{
			name: "unterminated comment",
			code: "\t<!-- x <b>\n&",
			want: map[string][]string{"tok-comment": {"<!-- x <b>\n&"}},
		},
		{
			name: "unterminated quoted value",
			code: "<a x=\"\r\n<script>&",
			want: map[string][]string{
				"tok-tag": {"<a"}, "tok-attr": {"x"}, "tok-punct": {"="},
				"tok-string": {"\"\r\n<script>&"},
			},
		},
		{
			name: "plain angles entities and whitespace",
			code: "\r\n 1 < 2 > 0 &amp; &#34; &lt; \t\n",
			want: map[string][]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := checkMarkupHTML(t, tc.code)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("tokens = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestHighlightMarkupNeverEmitsSourceElements(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		`<script>alert(1)</script><img src=x onerror="alert(1)">`,
		`</span></code><iframe src="javascript:alert(1)">`,
		`<!-- --><svg onload='alert(1)'><style>*{display:none}</style>`,
		`<a x="</span><script>bad()</script>">&lt;script&gt;</a>`,
		"<!DOCTYPE html [<!ENTITY x 'file:///etc/passwd'>]><x>&x;</x>",
		"<![CDATA[<b>unfinished &",
		"<> <<<< / > & \" ' 🚀 <é data-x=☃>",
	} {
		checkMarkupHTML(t, code)
	}
}

func FuzzHighlightMarkup(f *testing.F) {
	for _, code := range []string{
		"<!-- note --><div class=\"hero\" id=\"main\"><a href=\"/x\">Hi</a></div>",
		"\r\n<名 属性='雪 &lt;'><![CDATA[<&>]]></名>\t",
		`<script x="\"</span>">alert(1)</script>`,
		"<!-- incomplete <a", "<a x=unquoted/>", "&lt;&amp;&#0;<>\r\n",
		"\x00\xff<img onerror=alert(1)>",
	} {
		f.Add(code)
	}
	f.Fuzz(func(t *testing.T, code string) {
		if len(code) > 16*1024 {
			t.Skip()
		}
		checkMarkupHTML(t, code)
	})
}

// HTML cannot represent NUL or invalid UTF-8 verbatim in DOM text. For those
// fuzz inputs, still check the output structure, but only require exact text
// round trips for source text representable by HTML.
func checkMarkupHTML(t *testing.T, code string) map[string][]string {
	t.Helper()
	out := highlightMarkup(code)
	context := &xhtml.Node{Type: xhtml.ElementNode, Data: "div", DataAtom: xatom.Div}
	nodes, err := xhtml.ParseFragment(strings.NewReader(out), context)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	tokens := make(map[string][]string)
	for _, node := range nodes {
		if node.Type == xhtml.TextNode {
			text.WriteString(node.Data)
			continue
		}
		if node.Type != xhtml.ElementNode || node.DataAtom != xatom.Span || node.Namespace != "" || len(node.Attr) != 1 || node.Attr[0].Key != "class" || node.Attr[0].Namespace != "" {
			t.Fatalf("unexpected generated node %#v in %q", node, out)
		}
		class := node.Attr[0].Val
		switch class {
		case "tok-comment", "tok-tag", "tok-attr", "tok-punct", "tok-string":
		default:
			t.Fatalf("unexpected span class %q", class)
		}
		var token strings.Builder
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if child.Type != xhtml.TextNode {
				t.Fatalf("nested/non-text node in token: %#v", child)
			}
			token.WriteString(child.Data)
		}
		text.WriteString(token.String())
		tokens[class] = append(tokens[class], token.String())
	}
	if utf8.ValidString(code) && !strings.ContainsRune(code, 0) && text.String() != code {
		t.Fatalf("text round trip = %q, want %q; HTML = %q", text.String(), code, out)
	}
	return tokens
}

package termui

import "testing"

func TestStylerStyle(t *testing.T) {
	t.Parallel()

	if got := (Styler{}).Style(Bold, "plain"); got != "plain" {
		t.Fatalf("Style() without color = %q, want %q", got, "plain")
	}

	want := Bold + "styled" + Reset
	if got := (Styler{Color: true}).Style(Bold, "styled"); got != want {
		t.Fatalf("Style() with color = %q, want %q", got, want)
	}
}

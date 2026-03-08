package termui

// ANSI escape codes for terminal styling.
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Cyan      = "\033[36m"
	ClearDown = "\033[J"
	Home      = "\033[H"
	HideCur   = "\033[?25l"
	ShowCur   = "\033[?25h"
)

type Styler struct {
	Color bool
}

func (s Styler) Style(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + Reset
}

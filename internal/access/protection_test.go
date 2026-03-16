package access

import "testing"

func TestNormalizeMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "empty disables protection", input: "", want: ""},
		{name: "off disables protection", input: " off ", want: ""},
		{name: "false disables protection", input: "FALSE", want: ""},
		{name: "none disables protection", input: "none", want: ""},
		{name: "true maps to form", input: "true", want: ModeForm},
		{name: "form passes through", input: "form", want: ModeForm},
		{name: "basic is normalized", input: " BASIC ", want: ModeBasic},
		{name: "invalid mode errors", input: "digest", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeMode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeMode(%q) error = nil, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeMode(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeMode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

package cli

import (
	"testing"
)

func TestIsAutoUpdateEnabled(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"1", true},
		{"yes", true},
		{"YES", true},
		{"Yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"maybe", false},
		{"  true  ", true},
		{"  ", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv("EXPOSE_AUTOUPDATE", tt.value)
			got := isAutoUpdateEnabled()
			if got != tt.want {
				t.Errorf("isAutoUpdateEnabled() with EXPOSE_AUTOUPDATE=%q = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsAutoUpdateEnabled_Unset(t *testing.T) {
	t.Setenv("EXPOSE_AUTOUPDATE", "")
	if isAutoUpdateEnabled() {
		t.Error("isAutoUpdateEnabled() should be false when EXPOSE_AUTOUPDATE is empty")
	}
}

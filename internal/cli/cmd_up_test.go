package cli

import "testing"

func TestResolveUpAccessPasswordUsesEnvWhenUppercaseNameExists(t *testing.T) {
	t.Setenv("UP_SHARED_PASSWORD", "from-env")

	got, err := resolveUpAccess(upAccessConfig{
		Protect:  true,
		User:     "admin",
		Password: "UP_SHARED_PASSWORD",
	})
	if err != nil {
		t.Fatalf("resolveUpAccess error: %v", err)
	}
	if got.Password != "from-env" {
		t.Fatalf("expected env value, got %q", got.Password)
	}
}

func TestResolveUpAccessPasswordFallsBackToLiteralWhenEnvMissing(t *testing.T) {
	got, err := resolveUpAccess(upAccessConfig{
		Protect:  true,
		User:     "admin",
		Password: "UP_SHARED_PASSWORD_MISSING",
	})
	if err != nil {
		t.Fatalf("resolveUpAccess error: %v", err)
	}
	if got.Password != "UP_SHARED_PASSWORD_MISSING" {
		t.Fatalf("expected literal password fallback, got %q", got.Password)
	}
}

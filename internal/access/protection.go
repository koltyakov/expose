package access

import (
	"fmt"
	"strings"
)

const (
	CookieName        = "__Host-expose_access"
	FormActionField   = "__expose_access_action"
	FormUserField     = "__expose_access_user"
	FormPasswordField = "__expose_access_password"
	FormNextField     = "__expose_access_next"

	ModeForm          = "form"
	ModeBasic         = "basic"
	ModeUpstreamBasic = "upstream-basic"
)

func NormalizeMode(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "", "off", "false", "none":
		return "", nil
	case "true":
		return ModeForm, nil
	case ModeForm, ModeBasic, ModeUpstreamBasic:
		return raw, nil
	default:
		return "", fmt.Errorf("invalid protect mode %q (expected form, basic or upstream-basic)", raw)
	}
}

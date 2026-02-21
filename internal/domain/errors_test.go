package domain

import (
	"errors"
	"testing"
)

func TestTunnelErrorMessage(t *testing.T) {
	t.Parallel()

	err := &TunnelError{TunnelID: "t-1", Op: "connect", Err: ErrTunnelOffline}
	want := "tunnel t-1: connect: tunnel offline"
	if got := err.Error(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTunnelErrorUnwrap(t *testing.T) {
	t.Parallel()

	err := &TunnelError{TunnelID: "t-2", Op: "register", Err: ErrHostnameInUse}
	if !errors.Is(err, ErrHostnameInUse) {
		t.Fatal("expected errors.Is to match ErrHostnameInUse")
	}
}

func TestTunnelErrorWithoutID(t *testing.T) {
	t.Parallel()

	err := &TunnelError{Op: "resolve", Err: ErrTunnelNotFound}
	want := "resolve: tunnel not found"
	if got := err.Error(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want string
	}{
		{"hostname_in_use", ErrHostnameInUse, "hostname already in use"},
		{"tunnel_not_found", ErrTunnelNotFound, "tunnel not found"},
		{"unauthorized", ErrUnauthorized, "unauthorized"},
		{"rate_limit", ErrRateLimitExceeded, "rate limit exceeded"},
		{"tunnel_limit", ErrTunnelLimitReached, "active tunnel limit reached"},
		{"tunnel_offline", ErrTunnelOffline, "tunnel offline"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

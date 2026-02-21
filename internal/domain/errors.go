package domain

import (
	"errors"
	"fmt"
)

// Sentinel errors for well-known failure conditions that cross package
// boundaries.  Callers should use [errors.Is] to match these.
var (
	// ErrHostnameInUse indicates the requested subdomain is already taken.
	ErrHostnameInUse = errors.New("hostname already in use")

	// ErrTunnelNotFound means the requested tunnel ID does not exist.
	ErrTunnelNotFound = errors.New("tunnel not found")

	// ErrUnauthorized indicates missing or invalid credentials.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrRateLimitExceeded is returned when a client exceeds the allowed
	// request rate.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrTunnelLimitReached is returned when an API key has exhausted its
	// maximum number of concurrent tunnels.
	ErrTunnelLimitReached = errors.New("active tunnel limit reached")

	// ErrTunnelOffline means the tunnel exists but no client is connected.
	ErrTunnelOffline = errors.New("tunnel offline")
)

// TunnelError wraps an underlying error with tunnel context.
type TunnelError struct {
	TunnelID string
	Op       string
	Err      error
}

func (e *TunnelError) Error() string {
	if e.TunnelID != "" {
		return fmt.Sprintf("tunnel %s: %s: %v", e.TunnelID, e.Op, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *TunnelError) Unwrap() error {
	return e.Err
}

// Package domain defines the core data types shared across the expose
// server, store, and tunnel protocol layers.
package domain

import "time"

// Domain type constants distinguish temporary from permanent subdomains.
const (
	DomainTypeTemporarySubdomain = "temporary_subdomain"
	DomainTypePermanentSubdomain = "permanent_subdomain"
)

// Domain status constants track whether a domain is currently routable.
const (
	DomainStatusActive   = "active"
	DomainStatusReserved = "reserved"
	DomainStatusInactive = "inactive"
)

// Tunnel state constants describe the lifecycle of a tunnel session.
const (
	TunnelStateConnected    = "connected"
	TunnelStateDisconnected = "disconnected"
	TunnelStateClosed       = "closed"
)

// APIKey represents a server-managed authentication key.
type APIKey struct {
	ID          string
	Name        string
	KeyHash     string
	CreatedAt   time.Time
	RevokedAt   *time.Time
	TunnelLimit int // max active tunnels; -1 = unlimited
}

// Domain represents a registered subdomain record (temporary or permanent).
type Domain struct {
	ID         string
	APIKeyID   string
	Type       string
	Hostname   string
	Status     string
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

// Tunnel represents an active or historic tunnel session.
type Tunnel struct {
	ID                 string
	APIKeyID           string
	DomainID           string
	State              string
	IsTemporary        bool
	ClientMeta         string
	AccessUser         string
	AccessPasswordHash string
	ConnectedAt        *time.Time
	DisconnectedAt     *time.Time
}

// TunnelRoute pairs a [Domain] with its most recent [Tunnel] for routing.
type TunnelRoute struct {
	Domain Domain
	Tunnel Tunnel
}

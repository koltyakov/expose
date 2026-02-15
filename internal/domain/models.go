package domain

import "time"

const (
	DomainTypeTemporarySubdomain = "temporary_subdomain"
	DomainTypePermanentSubdomain = "permanent_subdomain"
	DomainTypeCustom             = "custom_domain"
)

const (
	DomainStatusActive   = "active"
	DomainStatusReserved = "reserved"
	DomainStatusInactive = "inactive"
)

const (
	TunnelStateConnected    = "connected"
	TunnelStateDisconnected = "disconnected"
	TunnelStateClosed       = "closed"
)

type APIKey struct {
	ID        string
	Name      string
	KeyHash   string
	CreatedAt time.Time
	RevokedAt *time.Time
}

type Domain struct {
	ID         string
	APIKeyID   string
	Type       string
	Hostname   string
	Status     string
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

type Tunnel struct {
	ID             string
	APIKeyID       string
	DomainID       string
	State          string
	IsTemporary    bool
	ClientMeta     string
	ConnectedAt    *time.Time
	DisconnectedAt *time.Time
}

type TunnelRoute struct {
	Domain Domain
	Tunnel Tunnel
}

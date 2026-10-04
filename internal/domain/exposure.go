package domain

import "time"

const (
	ExposureTypeTunnel = "tunnel"
	ExposureTypeSite   = "site"
)

// Exposure is the client-safe summary of a tunnel hostname or published site.
type Exposure struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Hostname  string     `json:"hostname"`
	URL       string     `json:"url"`
	Status    string     `json:"status"`
	Temporary bool       `json:"temporary,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

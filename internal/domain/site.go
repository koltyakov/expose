package domain

import "time"

// PublishedSite is a durable server-hosted static site owned by an API key.
type PublishedSite struct {
	ID        string     `json:"id"`
	APIKeyID  string     `json:"-"`
	SourceID  string     `json:"source_id,omitempty"`
	ContentID string     `json:"-"`
	Hostname  string     `json:"hostname"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// StorageID identifies an immutable upload directory. Older publications used ID.
func (s PublishedSite) StorageID() string {
	if s.ContentID != "" {
		return s.ContentID
	}
	return s.ID
}

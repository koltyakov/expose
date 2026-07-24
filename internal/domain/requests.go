// Package domain defines the core data types shared across the expose
// server, store, and tunnel protocol layers.
package domain

// RegisterResumeTunnelHeader allows a reconnecting client to ask the server to
// resume a previously issued tunnel ID instead of allocating a replacement.
const RegisterResumeTunnelHeader = "X-Expose-Resume-Tunnel"

const CapabilityWAFIgnorePaths = "waf_ignore_paths_v1"

// RegisterRequest is the JSON body sent by the client to create a new tunnel.
type RegisterRequest struct {
	Mode            string   `json:"mode"`
	Subdomain       string   `json:"subdomain,omitempty"`
	User            string   `json:"user,omitempty"`
	AccessMode      string   `json:"access_mode,omitempty"`
	Password        string   `json:"password,omitempty"`
	ClientHostname  string   `json:"client_hostname,omitempty"`
	ClientMachineID string   `json:"client_machine_id,omitempty"`
	LocalPort       string   `json:"local_port,omitempty"`
	ClientVersion   string   `json:"client_version,omitempty"`
	WAFIgnorePaths  []string `json:"waf_ignore_paths,omitempty"`
}

// RegisterResponse is the JSON body returned by the server on successful
// tunnel registration.
type RegisterResponse struct {
	TunnelID      string   `json:"tunnel_id"`
	PublicURL     string   `json:"public_url"`
	WSURL         string   `json:"ws_url"`
	H3URL         string   `json:"h3_url,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	ServerTLSMode string   `json:"server_tls_mode"`
	ServerVersion string   `json:"server_version,omitempty"`
	WAFEnabled    bool     `json:"waf_enabled,omitempty"`
}

// ErrorResponse is the JSON body returned by the server for structured errors.
type ErrorResponse struct {
	Error     string `json:"error"`
	ErrorCode string `json:"error_code,omitempty"`
}

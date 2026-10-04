// Package serviceapi defines expose's reserved HTTP service namespace.
package serviceapi

import "strings"

const (
	Prefix          = "/_expose"
	V1              = Prefix + "/v1"
	Health          = Prefix + "/healthz"
	Sites           = V1 + "/sites"
	Register        = V1 + "/tunnels/register"
	Connect         = V1 + "/tunnels/connect"
	ConnectH3       = V1 + "/tunnels/connect-h3"
	ConnectH3Stream = ConnectH3 + "/stream"
)

// IsServicePath excludes browser presence endpoints, which belong to each site.
func IsServicePath(path string) bool {
	return path == Health || path == V1 || strings.HasPrefix(path, V1+"/")
}

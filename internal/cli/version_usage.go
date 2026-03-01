package cli

import (
	"fmt"
	"os/exec"
	"strings"
)

func printUsage() {
	fmt.Println(`expose - Bring Your Own Infrastructure (BYOI) HTTP tunnel

Expose local HTTP ports to the internet through your own server.

Usage:
  expose http <port>                    Expose local port (temporary subdomain)
  expose http --domain=myapp <port>     Expose with a named subdomain
                                        --protect enables form protection, --protect=basic opts into Basic Auth
  expose static [dir]                   Expose a static directory (stable default subdomain)
                                        --folders enables listings, --spa enables root index fallback
  expose auth curl --url URL            Login to a protected route and print curl-ready auth output
  expose login                          Save server URL and API key
  expose up                             Start routes from ./expose.yml
  expose up -f expose.yml               Start routes from YAML config
  expose up init                        Create expose.yml via wizard
  expose server                         Start tunnel server
  expose server init                    Guided server setup + .env write
  expose apikey create --name NAME      Create a new API key
  expose apikey list                    List all API keys
  expose apikey revoke --id=ID          Revoke an API key
  expose update                         Update to the latest release
  expose version                        Print version
  expose help                           Show this help

Quick Start:
  1. expose server                                 # start server
  2. expose apikey create --name default            # create API key
  3. expose login --server example.com --api-key KEY  # save credentials
  4. expose http 3000                               # expose local port
     or: expose static ./public                     # expose a static site
     or: expose up init && expose up                # multi-route project config

Environment Variables:
  EXPOSE_DOMAIN           Server base domain (e.g. example.com)
  EXPOSE_API_KEY          API key for client authentication
  EXPOSE_USER             Protected-route username (default: admin)
  EXPOSE_PASSWORD         Optional public access password for this tunnel session
  EXPOSE_PORT             Local port to expose
  EXPOSE_SUBDOMAIN        Requested subdomain name
  EXPOSE_TLS_MODE         TLS mode: auto|dynamic|wildcard (default: auto)
  EXPOSE_DB_PATH          SQLite database path (default: ./expose.db)
  EXPOSE_LOG_LEVEL        Log level: debug|info|warn|error (default: info)
  EXPOSE_AUTOUPDATE       Enable automatic self-update (true|1|yes)

For detailed documentation, see: https://github.com/koltyakov/expose`)
}

// Version is set at build time via -ldflags.
var Version = "dev"

func init() {
	if Version == "dev" {
		if desc, err := exec.Command("git", "describe", "--tags", "--always").Output(); err == nil {
			if v := strings.TrimSpace(string(desc)); v != "" {
				Version = v + "-dev"
			}
		}
	}
	// Normalize: ensure non-dev versions start with "v" (GoReleaser
	// template {{.Version}} strips the prefix while git-describe keeps it).
	if Version != "dev" && !strings.HasPrefix(Version, "v") {
		Version = "v" + Version
	}
}

func printVersion() {
	fmt.Println("expose", Version)
}

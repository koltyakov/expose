package server

import (
	"net/http"
	"path"
	"strings"

	"github.com/koltyakov/expose/internal/domain"
)

const sensitiveFileProbeRule = "sensitive-file-probe"

func (s *Server) shouldIgnoreWAFPathRule(r *http.Request, rule string) bool {
	if s == nil || r == nil || rule != sensitiveFileProbeRule {
		return false
	}
	host := normalizeHost(r.Host)
	if snap, ok := s.liveRoutes.lookupHost(host); ok {
		return tunnelWAFPathIgnored(snap.route.Tunnel, r.URL.Path)
	}
	if route, found, cached := s.routes.lookup(host); cached && found {
		return tunnelWAFPathIgnored(route.Tunnel, r.URL.Path)
	}
	return false
}

func tunnelWAFPathIgnored(tunnel domain.Tunnel, requestPath string) bool {
	if tunnel.WAFPathRules == nil {
		return false
	}
	return wafPathIgnored(tunnel.WAFPathRules.IgnorePaths, requestPath)
}

func wafPathIgnored(prefixes []string, requestPath string) bool {
	requestPath = path.Clean("/" + strings.TrimPrefix(requestPath, "/"))
	for _, prefix := range prefixes {
		if prefix == "/" || requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}
	return false
}

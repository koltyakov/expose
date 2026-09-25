package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/koltyakov/expose/internal/store/sqlite"
)

// Only describe exposures owned by the authenticated key.
func (s *Server) hostnameConflict(ctx context.Context, keyID, host string) error {
	if st, ok := s.store.(siteStore); ok {
		// Include expired publications whose reservations await cleanup.
		if sites, err := st.ListPublishedSites(ctx, keyID); err == nil {
			for _, site := range sites {
				if site.Hostname == host && site.APIKeyID == keyID {
					label := strings.TrimSuffix(host, "."+normalizeHost(s.cfg.BaseDomain))
					return fmt.Errorf("%w: %s is a published site (expose pub) owned by your API key; delete it with `expose pub delete --domain=%s` on this server to release the hostname", sqlite.ErrHostnameInUse, host, label)
				}
			}
		}
	}
	if route, err := s.store.FindRouteByHost(ctx, host); err == nil && route.Domain.APIKeyID == keyID {
		return fmt.Errorf("%w: %s is an HTTP tunnel (expose http or expose static) owned by your API key; stop the tunnel with Ctrl+C before reusing the hostname", sqlite.ErrHostnameInUse, host)
	}
	return sqlite.ErrHostnameInUse
}

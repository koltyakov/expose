package cli

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
)

func prepareUpLocalRoute(ctx context.Context, configDir string, tunnel upTunnelConfig, unprotected bool, log *slog.Logger) (upLocalRoute, *staticFileServer, error) {
	route := upLocalRoute{
		Name:        tunnel.Name,
		Subdomain:   tunnel.Subdomain,
		PathPrefix:  tunnel.PathPrefix,
		StripPrefix: tunnel.StripPrefix,
	}
	if !tunnel.IsStatic() {
		route.LocalPort = tunnel.Port
		return route, nil, nil
	}

	root, err := resolveUpStaticRoot(configDir, tunnel.Dir)
	if err != nil {
		return upLocalRoute{}, nil, fmt.Errorf("%s: resolve static dir: %w", tunnel.Name, err)
	}
	staticSrv, port, err := startStaticFileServer(ctx, root, staticServerOptions{
		AllowFolders: tunnel.Folders,
		SPA:          tunnel.SPA,
		Unprotected:  unprotected,
	}, log)
	if err != nil {
		return upLocalRoute{}, nil, fmt.Errorf("%s: start static server: %w", tunnel.Name, err)
	}
	route.LocalPort = port
	route.StaticDir = root
	return route, staticSrv, nil
}

func resolveUpStaticRoot(configDir, root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("dir is required")
	}
	if !filepath.IsAbs(root) {
		root = filepath.Join(strings.TrimSpace(configDir), root)
	}
	return resolveStaticRoot(root)
}

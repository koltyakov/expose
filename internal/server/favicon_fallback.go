package server

import (
	"net/http"
	"strings"

	embedassets "github.com/koltyakov/expose/internal/assets"
)

var fallbackFaviconICO = append([]byte(nil), embedassets.FaviconICO...)

func shouldServeFallbackFavicon(r *http.Request, status int) bool {
	if r == nil || status != http.StatusNotFound {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(r.URL.Path), "/favicon.ico")
}

func writeFallbackFavicon(w http.ResponseWriter, r *http.Request) {
	if w == nil || r == nil {
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(fallbackFaviconICO)
}

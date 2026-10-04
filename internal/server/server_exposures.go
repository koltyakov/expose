package server

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

type exposureStore interface {
	ListExposures(context.Context, string) ([]domain.Exposure, error)
}

func (s *Server) handleExposures(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowPreAuthRequest(w, r) {
		return
	}
	keyID, ok := s.authenticate(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	retention := domain.DefaultExposureRetention
	if r.URL.Query().Has("retention") {
		var err error
		retention, err = time.ParseDuration(r.URL.Query().Get("retention"))
		if err != nil || retention < 0 {
			http.Error(w, "retention must be a non-negative duration, e.g. 168h; 0 includes all entries", http.StatusBadRequest)
			return
		}
	}
	st, ok := s.store.(exposureStore)
	if !ok {
		http.Error(w, "exposure listing unavailable", http.StatusServiceUnavailable)
		return
	}
	exposures, err := st.ListExposures(r.Context(), keyID)
	if err != nil {
		s.log.Error("failed to list exposures", "err", err)
		http.Error(w, "failed to list exposures", http.StatusInternalServerError)
		return
	}
	port := authorityPort(r.Host)
	cutoff := time.Now().UTC().Add(-retention)
	visible := make([]domain.Exposure, 0, len(exposures))
	for _, exposure := range exposures {
		if retention > 0 && exposure.Status != domain.TunnelStateConnected && exposure.LastActiveAt.Before(cutoff) {
			continue
		}
		host := exposure.Hostname
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		exposure.URL = "https://" + host
		visible = append(visible, exposure)
	}
	writeJSON(w, http.StatusOK, visible)
}

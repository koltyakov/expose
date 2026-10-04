package server

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

const sitePresenceInterval = 20 * time.Second
const sitePresenceTimeout = 55 * time.Second
const sitePresenceLimit = 1024
const sitePresenceVisitorLimit = 8

type sitePresence struct {
	fingerprint [32]byte
	seen        time.Time
}

// The caller holds sitesMu through registration, so deletion or disabling WS
// cannot miss a connection being upgraded. The socket loop owns it afterwards.
func (s *Server) prepareSitePresence(w http.ResponseWriter, r *http.Request, site domain.PublishedSite) func() {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && (r.URL.Path != publish.PresenceScriptPath || r.Method != http.MethodHead) {
		w.Header().Set("Allow", "GET")
		if r.URL.Path == publish.PresenceScriptPath {
			w.Header().Set("Allow", "GET, HEAD")
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return nil
	}
	if r.URL.Path == publish.PresenceScriptPath {
		s.queueDomainTouch(site.ID)
		publish.ServePresenceScript(w, r)
		return nil
	}
	stats := s.statsForSite(site.ID)
	fingerprint := sha256.Sum256([]byte(s.clientIP(r) + "\x00" + r.UserAgent()))
	stats.mu.Lock()
	defer stats.mu.Unlock()
	count := 0
	for _, visitor := range stats.presence {
		if visitor.fingerprint == fingerprint {
			count++
		}
	}
	if len(stats.presence) >= sitePresenceLimit || count >= sitePresenceVisitorLimit {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "presence connection limit reached", http.StatusTooManyRequests)
		return nil
	}
	upgrader := websocket.Upgrader{
		HandshakeTimeout: 5 * time.Second,
		ReadBufferSize:   256, WriteBufferSize: 256,
		CheckOrigin: func(r *http.Request) bool {
			origins := r.Header.Values("Origin")
			if len(origins) != 1 {
				return false
			}
			origin, err := url.Parse(origins[0])
			return err == nil && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" &&
				(origin.Scheme == "https" || origin.Scheme == "http") && strings.EqualFold(origin.Host, r.Host)
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil
	}
	if stats.presence == nil {
		stats.presence = make(map[*websocket.Conn]sitePresence)
	}
	stats.presence[conn] = sitePresence{fingerprint: fingerprint}
	return func() { s.runSitePresence(conn, site, stats, fingerprint, sitePresenceInterval, sitePresenceTimeout) }
}

func (s *Server) runSitePresence(conn *websocket.Conn, site domain.PublishedSite, stats *siteStats, fingerprint [32]byte, interval, timeout time.Duration) {
	done := make(chan struct{})
	defer func() {
		_ = conn.Close()
		<-done
	}()
	conn.SetReadLimit(32)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	conn.SetPongHandler(func(data string) error {
		if data != "expose" {
			return nil
		}
		now := time.Now().UTC()
		stats.mu.Lock()
		if presence, ok := stats.presence[conn]; ok {
			presence.seen = now
			stats.presence[conn] = presence
			stats.touchVisitorLocked(fingerprint, now)
		}
		stats.mu.Unlock()
		s.queueDomainTouch(site.ID)
		return conn.SetReadDeadline(now.Add(timeout))
	})
	go func() {
		defer func() {
			stats.mu.Lock()
			delete(stats.presence, conn)
			stats.mu.Unlock()
			close(done)
		}()
		// Presence accepts control frames only, never application data.
		_, _, _ = conn.ReadMessage()
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := conn.WriteControl(websocket.PingMessage, []byte("expose"), time.Now().Add(5*time.Second)); err != nil {
			return
		}
		select {
		case <-done:
			return
		case <-s.serverContext().Done():
			return
		case <-ticker.C:
			// Recheck ownership, expiry and opt-in after each interval, including
			// revoked API keys and publications replaced while this tab was open.
			ctx, cancel := context.WithTimeout(s.serverContext(), 5*time.Second)
			current, err := s.store.(siteStore).FindPublishedSite(ctx, site.Hostname)
			cancel()
			if err != nil || current.ID != site.ID || !current.WS {
				return
			}
		}
	}
}

func (s *Server) closeSitePresence(id string) {
	if value, ok := s.siteStats.Load(id); ok {
		stats := value.(*siteStats)
		stats.mu.Lock()
		defer stats.mu.Unlock()
		for conn := range stats.presence {
			_ = conn.Close()
		}
		clear(stats.presence)
	}
}

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/domain"
)

const (
	delegatedAccessTTL         = 15 * time.Minute
	delegatedAccessMaxSessions = 4096
)

// Sessions belong to one live tunnel connection, not merely a reusable hostname.
// The cookie is opaque; recoverable Basic credentials never leave server memory
// except in the Authorization header sent through that tunnel.
type delegatedAccessScope struct {
	host, tunnelID, keyID string
	connection            *session
}

type delegatedAccessSession struct {
	scope      delegatedAccessScope
	user, auth string
	expiresAt  time.Time
}

type delegatedAccessSessions struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]delegatedAccessSession
}

func (c *delegatedAccessSessions) create(entry delegatedAccessSession, now time.Time) (string, bool) {
	var random [32]byte
	_, _ = rand.Read(random[:])
	token := base64.RawURLEncoding.EncodeToString(random[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	if len(c.entries) >= delegatedAccessMaxSessions {
		return "", false
	}
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]delegatedAccessSession)
	}
	entry.expiresAt = now.Add(delegatedAccessTTL)
	c.entries[sha256.Sum256([]byte(token))] = entry
	return token, true
}

func (c *delegatedAccessSessions) lookup(token string, scope delegatedAccessScope, now time.Time) (delegatedAccessSession, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	entry, ok := c.entries[key]
	if !ok {
		return delegatedAccessSession{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return delegatedAccessSession{}, false
	}
	if entry.scope != scope {
		return delegatedAccessSession{}, false
	}
	return entry, true
}

func (c *delegatedAccessSessions) remove(token string) {
	c.mu.Lock()
	delete(c.entries, sha256.Sum256([]byte(token)))
	c.mu.Unlock()
}

func (c *delegatedAccessSessions) removeConnection(connection *session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.scope.connection == connection {
			delete(c.entries, key)
		}
	}
}

func (c *delegatedAccessSessions) removeTunnel(tunnelID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.scope.tunnelID == tunnelID {
			delete(c.entries, key)
		}
	}
}

func (c *delegatedAccessSessions) cleanup(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
}

func (c *delegatedAccessSessions) cleanupLocked(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

type delegatedConnectionKey struct{}
type delegatedRequestKey struct{}

type delegatedAccessRequest struct {
	entry    delegatedAccessSession
	token    string
	login    bool
	next     string
	limitKey string
}

func delegatedScope(r *http.Request, route domain.TunnelRoute) delegatedAccessScope {
	connection, _ := r.Context().Value(delegatedConnectionKey{}).(*session)
	return delegatedAccessScope{
		host: route.Domain.Hostname, tunnelID: route.Tunnel.ID,
		keyID: route.Domain.APIKeyID, connection: connection,
	}
}

func delegatedRequest(r *http.Request) *delegatedAccessRequest {
	state, _ := r.Context().Value(delegatedRequestKey{}).(*delegatedAccessRequest)
	return state
}

func publicAccessProtected(route domain.TunnelRoute) bool {
	return route.Tunnel.AccessPasswordHash != "" || publicAccessMode(route) == access.ModeUpstreamBasic
}

func delegatedOriginAllowed(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.User == nil && u.Scheme == "https" &&
		strings.EqualFold(u.Host, r.Host) && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func (s *Server) authorizeDelegatedAccess(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute) bool {
	// Reject browser cross-origin logins and unsafe cookie-authenticated requests.
	// Requests without browser origin metadata remain usable by CLI clients.
	if websocket.IsWebSocketUpgrade(r) || (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions) {
		if !delegatedOriginAllowed(r) {
			http.Error(w, "access form origin not allowed", http.StatusForbidden)
			return false
		}
	}
	scope := delegatedScope(r, route)
	if cookie, err := r.Cookie(publicAccessCookieName); err == nil {
		if entry, ok := s.delegatedAccess.lookup(cookie.Value, scope, time.Now()); ok {
			state := &delegatedAccessRequest{entry: entry, token: cookie.Value}
			*r = *r.WithContext(context.WithValue(r.Context(), delegatedRequestKey{}, state))
			return true
		}
		clearPublicAccessCookie(w)
	}
	if isPublicAccessFormSubmission(r) {
		return s.prepareDelegatedLogin(w, r, route, scope)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		writePublicAccessForm(w, r, route, publicAccessFormState{Next: publicAccessCurrentTarget(r)}, http.StatusUnauthorized)
	} else {
		writePublicAccessDenied(w)
	}
	return false
}

func (s *Server) prepareDelegatedLogin(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, scope delegatedAccessScope) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicAccessFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid access form submission", http.StatusBadRequest)
		return false
	}
	// Only the POST body supplies credentials. Do not accept query-string secrets.
	user := r.PostForm.Get(publicAccessFormUserField)
	password := r.PostForm.Get(publicAccessFormPasswordField)
	next := publicAccessRedirectTarget(r.PostForm.Get(publicAccessFormNextField), publicAccessCurrentTarget(r))
	state := publicAccessFormState{User: user, Next: next}
	if r.PostForm.Get(publicAccessFormActionField) != "login" {
		writePublicAccessForm(w, r, route, state, http.StatusUnauthorized)
		return false
	}
	if len(user) > 256 || len(password) > 256 || strings.ContainsAny(user, ":\r\n") {
		state.ErrorText = "Enter a valid application username and password."
		writePublicAccessForm(w, r, route, state, http.StatusUnauthorized)
		return false
	}
	limitKey := s.accessAuthLimitKey(route, r)
	if !s.accessLimiter.allow(limitKey) {
		w.Header().Set("Retry-After", "5")
		state.ErrorText = "Too many failed attempts. Try again in a moment."
		writePublicAccessForm(w, r, route, state, http.StatusTooManyRequests)
		return false
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	attempt := &delegatedAccessRequest{
		entry: delegatedAccessSession{scope: scope, user: user, auth: auth},
		login: true, next: next, limitKey: limitKey,
	}
	// Probe the submitted path with a safe GET through the normal tunnel.
	// Never forward the login form body or replay the visitor's original POST.
	probe := r.Clone(context.WithValue(r.Context(), delegatedRequestKey{}, attempt))
	probe.Method = http.MethodGet
	probe.Body, probe.GetBody = nil, nil
	probe.ContentLength, probe.TransferEncoding = 0, nil
	probe.Form, probe.PostForm, probe.MultipartForm = nil, nil, nil
	for _, name := range []string{"Content-Type", "Content-Length", "Transfer-Encoding", "Expect", "Range", "If-None-Match", "If-Modified-Since"} {
		probe.Header.Del(name)
	}
	*r = *probe
	return true
}

func preparePublicAccessHeaders(headers http.Header, r *http.Request, route domain.TunnelRoute) {
	stripPublicAccessCookie(headers)
	stripPublicAccessCredentials(headers, route)
	if publicAccessMode(route) == access.ModeUpstreamBasic {
		// Browser-supplied Authorization can never override delegated credentials.
		headers.Del("Authorization")
		if state := delegatedRequest(r); state != nil {
			headers.Set("Authorization", state.entry.auth)
		}
	}
}

// Returns true when the response was replaced by a form or login redirect.
// Call before copying any upstream headers or streaming body bytes.
func (s *Server) handleDelegatedAccessResponse(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, status int, headers http.Header) bool {
	if publicAccessMode(route) != access.ModeUpstreamBasic {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if headers != nil {
		headers.Set("Cache-Control", "no-store")
		// An application cannot replace expose's opaque session cookie.
		cookies := headers.Values("Set-Cookie")
		headers.Del("Set-Cookie")
		for _, raw := range cookies {
			cookie, err := http.ParseSetCookie(raw)
			if err == nil && cookie.Name != publicAccessCookieName {
				headers.Add("Set-Cookie", raw)
			}
		}
	}
	state := delegatedRequest(r)
	if status == http.StatusUnauthorized {
		form := publicAccessFormState{Next: publicAccessCurrentTarget(r), ErrorText: "Incorrect username or password."}
		if state != nil {
			form.User = state.entry.user
			if state.login {
				form.Next = state.next
			}
			s.delegatedAccess.remove(state.token)
		}
		clearPublicAccessCookie(w)
		writePublicAccessForm(w, r, route, form, http.StatusUnauthorized)
		return true
	}
	if state == nil || !state.login {
		return false
	}
	if status < http.StatusOK || status >= http.StatusBadRequest {
		writePublicAccessForm(w, r, route, publicAccessFormState{
			User: state.entry.user, Next: state.next,
			ErrorText: "The application could not confirm access. Try again.",
		}, normalizeUpstreamStatus(status))
		return true
	}
	s.accessLimiter.refund(state.limitKey)
	token, ok := s.delegatedAccess.create(state.entry, time.Now())
	if !ok {
		http.Error(w, "access sessions full; try again later", http.StatusServiceUnavailable)
		return true
	}
	http.SetCookie(w, &http.Cookie{
		Name: publicAccessCookieName, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(delegatedAccessTTL / time.Second), Expires: time.Now().Add(delegatedAccessTTL),
	})
	http.Redirect(w, r, state.next, http.StatusSeeOther)
	return true
}

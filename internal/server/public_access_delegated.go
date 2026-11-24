package server

import (
	"container/list"
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
	delegatedAccessTTL = 15 * time.Minute
	// delegatedAccessMaxSessions bounds all sessions in memory and
	// delegatedAccessMaxPerScope bounds one tunnel connection's share. A full
	// table evicts the oldest session (the scope's own first) instead of
	// refusing logins, so one busy tunnel cannot lock out the others.
	delegatedAccessMaxSessions = 4096
	delegatedAccessMaxPerScope = 512
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

// delegatedAccessSessions keeps sessions in creation order, globally and per
// scope. Every session has the same TTL, so creation order is also expiry
// order: cleanup pops expired sessions from the front, and eviction removes
// the oldest. Lookups do not extend a session: its cookie has a fixed
// lifetime set at login, so a server-side extension could not be used.
type delegatedAccessSessions struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]*delegatedAccessEntry
	order   list.List // *delegatedAccessEntry, oldest first
	scopes  map[delegatedAccessScope]*list.List
}

type delegatedAccessEntry struct {
	key            [sha256.Size]byte
	session        delegatedAccessSession
	inOrder, scope *list.Element
}

func (c *delegatedAccessSessions) create(entry delegatedAccessSession, now time.Time) string {
	var random [32]byte
	_, _ = rand.Read(random[:])
	token := base64.RawURLEncoding.EncodeToString(random[:])
	key := sha256.Sum256([]byte(token))
	entry.expiresAt = now.Add(delegatedAccessTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]*delegatedAccessEntry)
		c.scopes = make(map[delegatedAccessScope]*list.List)
	}
	scoped := c.scopes[entry.scope]
	if scoped == nil {
		scoped = list.New()
		c.scopes[entry.scope] = scoped
	}
	if scoped.Len() >= delegatedAccessMaxPerScope {
		c.deleteLocked(scoped.Front().Value.(*delegatedAccessEntry))
	}
	if len(c.entries) >= delegatedAccessMaxSessions {
		c.deleteLocked(c.order.Front().Value.(*delegatedAccessEntry))
	}
	e := &delegatedAccessEntry{key: key, session: entry}
	e.inOrder = c.order.PushBack(e)
	e.scope = scoped.PushBack(e)
	c.entries[key] = e
	return token
}

func (c *delegatedAccessSessions) lookup(token string, scope delegatedAccessScope, now time.Time) (delegatedAccessSession, bool) {
	key := sha256.Sum256([]byte(token))
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return delegatedAccessSession{}, false
	}
	if !now.Before(e.session.expiresAt) {
		c.deleteLocked(e)
		return delegatedAccessSession{}, false
	}
	if e.session.scope != scope {
		return delegatedAccessSession{}, false
	}
	return e.session, true
}

func (c *delegatedAccessSessions) remove(token string) {
	key := sha256.Sum256([]byte(token))
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		c.deleteLocked(e)
	}
	c.mu.Unlock()
}

func (c *delegatedAccessSessions) removeConnection(connection *session) {
	c.removeScopes(func(scope delegatedAccessScope) bool { return scope.connection == connection })
}

func (c *delegatedAccessSessions) removeTunnel(tunnelID string) {
	c.removeScopes(func(scope delegatedAccessScope) bool { return scope.tunnelID == tunnelID })
}

func (c *delegatedAccessSessions) removeScopes(match func(delegatedAccessScope) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for scope, scoped := range c.scopes {
		if !match(scope) {
			continue
		}
		for scoped.Len() > 0 {
			c.deleteLocked(scoped.Front().Value.(*delegatedAccessEntry))
		}
	}
}

func (c *delegatedAccessSessions) cleanup(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
}

func (c *delegatedAccessSessions) cleanupLocked(now time.Time) {
	for front := c.order.Front(); front != nil; front = c.order.Front() {
		e := front.Value.(*delegatedAccessEntry)
		if now.Before(e.session.expiresAt) {
			return
		}
		c.deleteLocked(e)
	}
}

func (c *delegatedAccessSessions) deleteLocked(e *delegatedAccessEntry) {
	delete(c.entries, e.key)
	c.order.Remove(e.inOrder)
	if scoped := c.scopes[e.session.scope]; scoped != nil {
		scoped.Remove(e.scope)
		if scoped.Len() == 0 {
			delete(c.scopes, e.session.scope)
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
	token := s.delegatedAccess.create(state.entry, time.Now())
	http.SetCookie(w, &http.Cookie{
		Name: publicAccessCookieName, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(delegatedAccessTTL / time.Second), Expires: time.Now().Add(delegatedAccessTTL),
	})
	http.Redirect(w, r, state.next, http.StatusSeeOther)
	return true
}

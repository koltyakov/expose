package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/domain"
)

const (
	publicAccessCookieName        = access.CookieName
	publicAccessCookieVersion     = "v2"
	publicAccessCookieTTL         = 24 * time.Hour
	publicAccessFormActionField   = access.FormActionField
	publicAccessFormUserField     = access.FormUserField
	publicAccessFormPasswordField = access.FormPasswordField
	publicAccessFormNextField     = access.FormNextField
	maxPublicAccessFormBytes      = 8 * 1024
)

func (s *Server) authorizePublicRequest(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute) bool {
	if route.Tunnel.AccessPasswordHash == "" {
		return true
	}
	if publicAccessMode(route) == access.ModeBasic {
		expectedUser := publicAccessExpectedUser(route)
		user, password, hasCreds := r.BasicAuth()
		if hasCreds {
			limitKey := s.accessAuthLimitKey(route, r)
			if s.accessLimiter.exhausted(limitKey) {
				writeAccessAuthThrottled(w)
				return false
			}
			if isAuthorizedBasicUser(user, expectedUser) && auth.VerifyPasswordHash(route.Tunnel.AccessPasswordHash, password) {
				return true
			}
			s.accessLimiter.allow(limitKey)
		}
		writeBasicAuthChallenge(w)
		return false
	}

	expectedUser := publicAccessExpectedUser(route)
	if valid, present := s.hasValidPublicAccessCookie(r, route, expectedUser, time.Now()); valid {
		return true
	} else if present {
		clearPublicAccessCookie(w)
	}

	if isPublicAccessFormSubmission(r) {
		s.handlePublicAccessLogin(w, r, route, expectedUser)
		return false
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		writePublicAccessForm(w, r, route, publicAccessFormState{
			User: expectedUser,
			Next: publicAccessCurrentTarget(r),
		}, http.StatusUnauthorized)
		return false
	}

	writePublicAccessDenied(w)
	return false
}

func publicAccessMode(route domain.TunnelRoute) string {
	mode := strings.TrimSpace(route.Tunnel.AccessMode)
	if mode == "" {
		return access.ModeBasic
	}
	return mode
}

type publicAccessFormState struct {
	User      string
	Next      string
	ErrorText string
}

func publicAccessExpectedUser(route domain.TunnelRoute) string {
	expectedUser := strings.TrimSpace(route.Tunnel.AccessUser)
	if expectedUser == "" {
		return "admin"
	}
	return expectedUser
}

func (s *Server) hasValidPublicAccessCookie(r *http.Request, route domain.TunnelRoute, expectedUser string, now time.Time) (valid bool, present bool) {
	if r == nil {
		return false, false
	}
	cookie, err := r.Cookie(publicAccessCookieName)
	if err != nil {
		return false, false
	}
	return s.publicAccessCookieMatches(route, expectedUser, cookie.Value, now), true
}

func (s *Server) publicAccessCookieMatches(route domain.TunnelRoute, expectedUser, raw string, now time.Time) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != publicAccessCookieVersion {
		return false
	}

	expiryUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	if now.Unix() > expiryUnix {
		return false
	}

	expectedSig := s.publicAccessCookieSignature(route, expectedUser, expiryUnix)
	if expectedSig == "" {
		return false
	}
	return hmac.Equal([]byte(parts[2]), []byte(expectedSig))
}

func (s *Server) publicAccessCookieValue(route domain.TunnelRoute, expectedUser string, now time.Time) string {
	expiryUnix := now.Add(publicAccessCookieTTL).Unix()
	sig := s.publicAccessCookieSignature(route, expectedUser, expiryUnix)
	if sig == "" {
		return ""
	}
	return publicAccessCookieVersion + "." + strconv.FormatInt(expiryUnix, 10) + "." + sig
}

func (s *Server) publicAccessCookieSignature(route domain.TunnelRoute, expectedUser string, expiryUnix int64) string {
	secret := strings.TrimSpace(s.cfg.AccessCookieSecret)
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(publicAccessCookieVersion))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(route.Domain.Hostname))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(expectedUser))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strconv.FormatInt(expiryUnix, 10)))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(route.Tunnel.AccessPasswordHash))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) handlePublicAccessLogin(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, expectedUser string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPublicAccessFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid access form submission", http.StatusBadRequest)
		return
	}

	next := publicAccessRedirectTarget(r.Form.Get(publicAccessFormNextField), publicAccessCurrentTarget(r))
	state := publicAccessFormState{
		User: strings.TrimSpace(r.Form.Get(publicAccessFormUserField)),
		Next: next,
	}

	if strings.TrimSpace(r.Form.Get(publicAccessFormActionField)) != "login" {
		if state.User == "" {
			state.User = expectedUser
		}
		writePublicAccessForm(w, r, route, state, http.StatusUnauthorized)
		return
	}

	limitKey := s.accessAuthLimitKey(route, r)
	if s.accessLimiter.exhausted(limitKey) {
		clearPublicAccessCookie(w)
		state.ErrorText = "Too many failed attempts. Try again in a moment."
		if state.User == "" {
			state.User = expectedUser
		}
		w.Header().Set("Retry-After", "5")
		writePublicAccessForm(w, r, route, state, http.StatusTooManyRequests)
		return
	}

	password := r.Form.Get(publicAccessFormPasswordField)
	if !isAuthorizedBasicUser(state.User, expectedUser) || !auth.VerifyPasswordHash(route.Tunnel.AccessPasswordHash, password) {
		s.accessLimiter.allow(limitKey)
		clearPublicAccessCookie(w)
		state.ErrorText = "Incorrect username or password."
		if state.User == "" {
			state.User = expectedUser
		}
		writePublicAccessForm(w, r, route, state, http.StatusUnauthorized)
		return
	}

	cookieValue := s.publicAccessCookieValue(route, expectedUser, time.Now())
	if cookieValue == "" {
		http.Error(w, "protected route misconfigured: access cookie secret missing", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     publicAccessCookieName,
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(publicAccessCookieTTL / time.Second),
		Expires:  time.Now().Add(publicAccessCookieTTL),
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func clearPublicAccessCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     publicAccessCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func writePublicAccessDenied(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "protected route: sign in through the access form first", http.StatusUnauthorized)
}

//go:embed templates/public_access_form.html
var publicAccessFormHTML string

var publicAccessFormTemplate = template.Must(template.New("public_access_form").Parse(publicAccessFormHTML))

type publicAccessFormData struct {
	Host          string
	ErrorText     string
	Action        string
	ActionField   string
	NextField     string
	Next          string
	UserField     string
	User          string
	PasswordField string
}

func writePublicAccessForm(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, state publicAccessFormState, status int) {
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	_ = publicAccessFormTemplate.Execute(w, publicAccessFormData{
		Host:          route.Domain.Hostname,
		ErrorText:     state.ErrorText,
		Action:        publicAccessFormAction(r),
		ActionField:   publicAccessFormActionField,
		NextField:     publicAccessFormNextField,
		Next:          state.Next,
		UserField:     publicAccessFormUserField,
		User:          state.User,
		PasswordField: publicAccessFormPasswordField,
	})
}

func publicAccessCurrentTarget(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	return publicAccessRedirectTarget(r.URL.RequestURI(), "/")
}

func publicAccessFormAction(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "/"
	}
	path := strings.TrimSpace(r.URL.Path)
	if path == "" {
		return "/"
	}
	return publicAccessRedirectTarget(path, "/")
}

func publicAccessRedirectTarget(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u == nil || u.Scheme != "" || u.Host != "" {
		return fallback
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.RequestURI()
}

func publicWebSocketOriginAllowed(r *http.Request) bool {
	if r == nil {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
	case "http", "https":
	default:
		return false
	}
	if strings.TrimSpace(u.Host) == "" {
		return false
	}
	return normalizeHost(u.Host) == normalizeHost(r.Host)
}

func isPublicAccessFormSubmission(r *http.Request) bool {
	if r == nil || r.Method != http.MethodPost {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return mediaType == "application/x-www-form-urlencoded"
}

func stripPublicAccessCookie(h http.Header) {
	if len(h) == 0 {
		return
	}
	values := h.Values("Cookie")
	if len(values) == 0 {
		return
	}

	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := stripCookieValue(value, publicAccessCookieName); trimmed != "" {
			filtered = append(filtered, trimmed)
		}
	}

	h.Del("Cookie")
	for _, value := range filtered {
		h.Add("Cookie", value)
	}
}

func stripPublicAccessCredentials(h http.Header, route domain.TunnelRoute) {
	if route.Tunnel.AccessPasswordHash != "" && publicAccessMode(route) == access.ModeBasic {
		h.Del("Authorization")
	}
}

func stripCookieValue(headerValue, cookieName string) string {
	parts := strings.Split(headerValue, ";")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(name) == cookieName {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "; ")
}

func isAuthorizedBasicUser(user, expectedUser string) bool {
	return subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser)) == 1
}

func writeBasicAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="expose", charset="UTF-8"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// accessAuthLimitKey scopes failed-auth throttling per protected hostname and
// client IP so one visitor cannot lock others out.
func (s *Server) accessAuthLimitKey(route domain.TunnelRoute, r *http.Request) string {
	return "access|" + publicRateLimitKey(route.Domain.Hostname, clientIPFromRemoteAddr(r.RemoteAddr))
}

func writeAccessAuthThrottled(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "too many failed sign-in attempts; try again shortly", http.StatusTooManyRequests)
}

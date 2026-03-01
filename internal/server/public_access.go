package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
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
	publicAccessCookieVersion     = "v1"
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

	expectedUser := publicAccessExpectedUser(route)
	if valid, present := hasValidPublicAccessCookie(r, route, expectedUser, time.Now()); valid {
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

func hasValidPublicAccessCookie(r *http.Request, route domain.TunnelRoute, expectedUser string, now time.Time) (valid bool, present bool) {
	if r == nil {
		return false, false
	}
	cookie, err := r.Cookie(publicAccessCookieName)
	if err != nil {
		return false, false
	}
	return publicAccessCookieMatches(route, expectedUser, cookie.Value, now), true
}

func publicAccessCookieMatches(route domain.TunnelRoute, expectedUser, raw string, now time.Time) bool {
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

	expectedSig := publicAccessCookieSignature(route, expectedUser, expiryUnix)
	return hmac.Equal([]byte(parts[2]), []byte(expectedSig))
}

func publicAccessCookieValue(route domain.TunnelRoute, expectedUser string, now time.Time) string {
	expiryUnix := now.Add(publicAccessCookieTTL).Unix()
	return publicAccessCookieVersion + "." + strconv.FormatInt(expiryUnix, 10) + "." + publicAccessCookieSignature(route, expectedUser, expiryUnix)
}

func publicAccessCookieSignature(route domain.TunnelRoute, expectedUser string, expiryUnix int64) string {
	mac := hmac.New(sha256.New, []byte(route.Tunnel.AccessPasswordHash))
	_, _ = mac.Write([]byte(publicAccessCookieVersion))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(route.Domain.Hostname))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(expectedUser))
	_, _ = mac.Write([]byte("|"))
	_, _ = mac.Write([]byte(strconv.FormatInt(expiryUnix, 10)))
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

	password := r.Form.Get(publicAccessFormPasswordField)
	if state.User != expectedUser || !auth.VerifyPasswordHash(route.Tunnel.AccessPasswordHash, password) {
		clearPublicAccessCookie(w)
		state.ErrorText = "Incorrect username or password."
		if state.User == "" {
			state.User = expectedUser
		}
		writePublicAccessForm(w, r, route, state, http.StatusUnauthorized)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     publicAccessCookieName,
		Value:    publicAccessCookieValue(route, expectedUser, time.Now()),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
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
		SameSite: http.SameSiteNoneMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func writePublicAccessDenied(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "protected route: sign in through the access form first", http.StatusUnauthorized)
}

func writePublicAccessForm(w http.ResponseWriter, r *http.Request, route domain.TunnelRoute, state publicAccessFormState, status int) {
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	host := html.EscapeString(route.Domain.Hostname)
	action := html.EscapeString(publicAccessFormAction(r))
	next := html.EscapeString(state.Next)
	user := html.EscapeString(state.User)
	errorBanner := ""
	if state.ErrorText != "" {
		errorBanner = `<p class="error" role="alert">` + html.EscapeString(state.ErrorText) + `</p>`
	}

	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protected route</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3efe7;
      --bg-accent: #d6e6dc;
      --panel: rgba(255,255,255,0.92);
      --panel-border: rgba(24, 41, 33, 0.12);
      --text: #17231c;
      --muted: #5e6f64;
      --accent: #1f7a5a;
      --accent-dark: #14523d;
      --danger: #9c2f2f;
      --shadow: 0 24px 60px rgba(23, 35, 28, 0.16);
      --radius: 24px;
      --radius-sm: 16px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(214, 230, 220, 0.9), transparent 38%%),
        radial-gradient(circle at bottom right, rgba(248, 209, 172, 0.48), transparent 34%%),
        linear-gradient(145deg, var(--bg), #fbf8f3 55%%, #e7efe7);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .shell {
      width: min(100%%, 920px);
      display: grid;
      gap: 18px;
      grid-template-columns: minmax(0, 1.15fr) minmax(280px, 0.85fr);
      align-items: stretch;
    }
    .hero, .panel {
      border-radius: var(--radius);
      border: 1px solid var(--panel-border);
      box-shadow: var(--shadow);
      overflow: hidden;
      backdrop-filter: blur(12px);
    }
    .hero {
      background:
        linear-gradient(170deg, rgba(31, 122, 90, 0.94), rgba(20, 82, 61, 0.92)),
        linear-gradient(125deg, rgba(255,255,255,0.12), transparent 42%%);
      color: #f6fbf7;
      padding: 32px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 24px;
    }
    .eyebrow {
      margin: 0;
      font-size: 12px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      opacity: 0.76;
    }
    h1 {
      margin: 10px 0 14px;
      font-size: clamp(2rem, 4vw, 3.2rem);
      line-height: 0.95;
      max-width: 10ch;
    }
    .hero p {
      margin: 0;
      max-width: 28rem;
      font-size: 1rem;
      line-height: 1.6;
      color: rgba(246, 251, 247, 0.84);
    }
    .host {
      display: inline-flex;
      max-width: 100%%;
      padding: 10px 14px;
      border-radius: 999px;
      background: rgba(255,255,255,0.12);
      border: 1px solid rgba(255,255,255,0.16);
      font-family: "SFMono-Regular", "Consolas", monospace;
      font-size: 0.92rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .panel {
      background: var(--panel);
      padding: 28px;
      display: flex;
      flex-direction: column;
      justify-content: center;
    }
    .panel h2 {
      margin: 0 0 8px;
      font-size: 1.45rem;
    }
    .panel-copy {
      margin: 0 0 18px;
      color: var(--muted);
      line-height: 1.5;
    }
    form {
      display: grid;
      gap: 14px;
    }
    label {
      display: grid;
      gap: 8px;
      font-size: 0.92rem;
      font-weight: 600;
    }
    input {
      width: 100%%;
      border: 1px solid rgba(23, 35, 28, 0.12);
      border-radius: var(--radius-sm);
      background: rgba(255,255,255,0.92);
      color: var(--text);
      font: inherit;
      padding: 14px 16px;
      transition: border-color 120ms ease, box-shadow 120ms ease, transform 120ms ease;
    }
    input:focus {
      outline: none;
      border-color: rgba(31, 122, 90, 0.56);
      box-shadow: 0 0 0 4px rgba(31, 122, 90, 0.12);
      transform: translateY(-1px);
    }
    button {
      appearance: none;
      border: 0;
      border-radius: 999px;
      background: linear-gradient(135deg, var(--accent), var(--accent-dark));
      color: #f7fcf9;
      font: inherit;
      font-weight: 700;
      padding: 14px 18px;
      cursor: pointer;
    }
    .error {
      margin: 0 0 2px;
      padding: 12px 14px;
      border-radius: var(--radius-sm);
      background: rgba(156, 47, 47, 0.08);
      color: var(--danger);
      font-weight: 600;
    }
    .hint {
      margin: 12px 0 0;
      color: var(--muted);
      font-size: 0.92rem;
      line-height: 1.5;
    }
    @media (max-width: 860px) {
      .shell {
        grid-template-columns: 1fr;
      }
      .hero, .panel {
        padding: 24px;
      }
      h1 {
        max-width: none;
      }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div>
        <p class="eyebrow">Expose protection</p>
        <h1>Protected route</h1>
        <p>This tunnel is gated before traffic reaches the upstream app. Sign in once to continue without using HTTP auth headers.</p>
      </div>
      <div class="host">%s</div>
    </section>
    <section class="panel">
      <h2>Sign in to continue</h2>
      <p class="panel-copy">The access session is stored in a dedicated host-scoped cookie and stays out of the upstream app's auth flow.</p>
      %s
      <form method="post" action="%s" novalidate>
        <input type="hidden" name="%s" value="login">
        <input type="hidden" name="%s" value="%s">
        <label>
          Username
          <input type="text" name="%s" value="%s" autocomplete="username" autocapitalize="none" spellcheck="false" required>
        </label>
        <label>
          Password
          <input type="password" name="%s" value="" autocomplete="current-password" required autofocus>
        </label>
        <button type="submit">Continue</button>
      </form>
      <p class="hint">After access is granted, your app's own cookies, sessions, or OAuth flows continue independently.</p>
    </section>
  </main>
</body>
</html>`,
		host,
		errorBanner,
		action,
		publicAccessFormActionField,
		publicAccessFormNextField,
		next,
		publicAccessFormUserField,
		user,
		publicAccessFormPasswordField,
	)
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
	return path
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

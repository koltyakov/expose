package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/access"
	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func delegatedTestRoute() domain.TunnelRoute {
	return domain.TunnelRoute{
		Domain: domain.Domain{Hostname: "app.example.com", APIKeyID: "key-1"},
		Tunnel: domain.Tunnel{ID: "tunnel-1", AccessMode: access.ModeUpstreamBasic},
	}
}

func delegatedTestLogin(password string) *http.Request {
	form := url.Values{
		publicAccessFormActionField: {"login"}, publicAccessFormUserField: {"alice"},
		publicAccessFormPasswordField: {password}, publicAccessFormNextField: {"/private?tab=1"},
	}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/private", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://app.example.com")
	return r
}

func TestDelegatedAccessLoginAndSession(t *testing.T) {
	t.Parallel()
	s := &Server{}
	route := delegatedTestRoute()
	r := delegatedTestLogin(" spaces:are preserved ")
	rr := httptest.NewRecorder()
	r.Header.Set("Authorization", "Bearer must-not-win")
	r.AddCookie(&http.Cookie{Name: "app", Value: "kept"})
	if !s.authorizePublicRequest(rr, r, route) {
		t.Fatalf("login not sent upstream: %d %s", rr.Code, rr.Body)
	}
	if r.Method != http.MethodGet || r.Body != nil || r.ContentLength != 0 {
		t.Fatal("login must become a bodyless GET, not forward the credentials form")
	}
	headers := r.Header.Clone()
	preparePublicAccessHeaders(headers, r, route)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice: spaces:are preserved "))
	if headers.Get("Authorization") != want || headers.Get("Cookie") != "app=kept" {
		t.Fatalf("unexpected upstream headers: %v", headers)
	}
	if len(s.delegatedAccess.entries) != 0 {
		t.Fatal("credentials stored before upstream accepted them")
	}
	upstream := http.Header{"Location": {"https://untrusted.example/redirect"}}
	if !s.handleDelegatedAccessResponse(rr, r, route, http.StatusFound, upstream) {
		t.Fatal("login response not intercepted")
	}
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != "/private?tab=1" {
		t.Fatalf("login redirect: %d %v", rr.Code, rr.Header())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != publicAccessCookieName || !cookie.Secure || !cookie.HttpOnly ||
		cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode ||
		cookie.MaxAge != int(delegatedAccessTTL/time.Second) {
		t.Fatalf("insecure session cookie: %+v", cookie)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 || strings.Contains(cookie.Value, "alice") {
		t.Fatal("expected a random 256-bit opaque token")
	}
	next := httptest.NewRequest(http.MethodPost, "https://app.example.com/private", strings.NewReader("actual app body"))
	next.AddCookie(cookie)
	next.AddCookie(&http.Cookie{Name: "app", Value: "kept"})
	next.Header.Set("Authorization", "Bearer still-must-not-win")
	if !s.authorizePublicRequest(httptest.NewRecorder(), next, route) {
		t.Fatal("session not recognized")
	}
	headers = next.Header.Clone()
	preparePublicAccessHeaders(headers, next, route)
	if headers.Get("Authorization") != want || headers.Get("Cookie") != "app=kept" || next.Method != http.MethodPost {
		t.Fatal("session did not preserve app requests and inject Basic credentials")
	}
	rejected := httptest.NewRecorder()
	if !s.handleDelegatedAccessResponse(rejected, next, route, http.StatusUnauthorized,
		http.Header{"Www-Authenticate": {`Basic realm="app"`}}) {
		t.Fatal("upstream challenge not intercepted")
	}
	if rejected.Header().Get("WWW-Authenticate") != "" || rejected.Code != http.StatusUnauthorized ||
		!strings.Contains(rejected.Body.String(), "Incorrect username or password.") {
		t.Fatalf("challenge escaped the form: %d %v %s", rejected.Code, rejected.Header(), rejected.Body)
	}
	if len(s.delegatedAccess.entries) != 0 || rejected.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatal("rejected session not revoked")
	}
	replay := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	replay.AddCookie(cookie)
	if s.authorizePublicRequest(httptest.NewRecorder(), replay, route) {
		t.Fatal("revoked token still authorized")
	}
}

func TestDelegatedAccessSessionsAreBoundedScopedAndExpire(t *testing.T) {
	t.Parallel()
	var c delegatedAccessSessions
	now := time.Now()
	scope := delegatedAccessScope{host: "app.example.com", tunnelID: "t1", keyID: "k1", connection: &session{}}
	entry := delegatedAccessSession{scope: scope, user: "alice", auth: "Basic secret"}
	token, ok := c.create(entry, now)
	if !ok {
		t.Fatal("create failed")
	}
	for _, changed := range []delegatedAccessScope{
		{host: "other.example.com", tunnelID: "t1", keyID: "k1", connection: scope.connection},
		{host: scope.host, tunnelID: "t2", keyID: "k1", connection: scope.connection},
		{host: scope.host, tunnelID: "t1", keyID: "k2", connection: scope.connection},
		{host: scope.host, tunnelID: "t1", keyID: "k1", connection: &session{}},
	} {
		if _, ok := c.lookup(token, changed, now); ok {
			t.Fatal("token accepted outside its live tunnel scope")
		}
	}
	if _, ok := c.lookup(token, scope, now.Add(delegatedAccessTTL-time.Second)); !ok {
		t.Fatal("live session rejected")
	}
	if _, ok := c.lookup(token+"tampered", scope, now); ok {
		t.Fatal("tampered token accepted")
	}
	if _, ok := c.lookup(token, scope, now.Add(delegatedAccessTTL)); ok || len(c.entries) != 0 {
		t.Fatal("session survived expiry")
	}
	entry.expiresAt = now.Add(delegatedAccessTTL)
	for i := range delegatedAccessMaxSessions {
		c.entries[sha256.Sum256(fmt.Appendf(nil, "token-%d", i))] = entry
	}
	if _, ok := c.create(entry, now); ok || len(c.entries) != delegatedAccessMaxSessions {
		t.Fatal("session capacity not enforced")
	}
	if _, ok := c.create(entry, now.Add(delegatedAccessTTL)); !ok || len(c.entries) != 1 {
		t.Fatal("expired entries did not release capacity")
	}
	c.removeConnection(scope.connection)
	if len(c.entries) != 0 {
		t.Fatal("credentials survived tunnel disconnect")
	}
}

func TestDelegatedAccessFormFailures(t *testing.T) {
	t.Parallel()
	route := delegatedTestRoute()
	for _, tc := range []struct {
		name   string
		method string
		origin string
		status int
	}{
		{"initial form", http.MethodGet, "", http.StatusUnauthorized},
		{"head", http.MethodHead, "", http.StatusUnauthorized},
		{"unsafe unauthenticated", http.MethodPut, "", http.StatusUnauthorized},
		{"cross-site login", http.MethodPost, "https://evil.example", http.StatusForbidden},
		{"sibling login", http.MethodPost, "https://sibling.example.com", http.StatusForbidden},
		{"downgraded origin", http.MethodPost, "http://app.example.com", http.StatusForbidden},
		{"other port", http.MethodPost, "https://app.example.com:444", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{}
			r := httptest.NewRequest(tc.method, "https://app.example.com/private", nil)
			r.Header.Set("Origin", tc.origin)
			r.SetBasicAuth("alice", "bypass")
			rr := httptest.NewRecorder()
			if s.authorizePublicRequest(rr, r, route) || rr.Code != tc.status {
				t.Fatalf("unexpected authorization: %d", rr.Code)
			}
			if rr.Header().Get("WWW-Authenticate") != "" || (tc.method == http.MethodHead && rr.Body.Len() != 0) {
				t.Fatal("browser challenge or HEAD response body")
			}
		})
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		s := &Server{}
		r := delegatedTestLogin("bad-pass")
		rr := httptest.NewRecorder()
		if !s.authorizePublicRequest(rr, r, route) {
			t.Fatal("could not prepare login")
		}
		s.handleDelegatedAccessResponse(rr, r, route, status, http.Header{"Www-Authenticate": {`Basic realm="app"`}})
		if len(s.delegatedAccess.entries) != 0 || strings.Contains(rr.Body.String(), "bad-pass") {
			t.Fatal("failed upstream login retained or reflected credentials")
		}
	}
	s := &Server{accessLimiter: newConfiguredRateLimiter(0, 1, time.Minute)}
	r := delegatedTestLogin("bad-pass")
	s.authorizePublicRequest(httptest.NewRecorder(), r, route)
	s.handleDelegatedAccessResponse(httptest.NewRecorder(), r, route, http.StatusUnauthorized, nil)
	rr := httptest.NewRecorder()
	if s.authorizePublicRequest(rr, delegatedTestLogin("valid-pass"), route) || rr.Code != http.StatusTooManyRequests {
		t.Fatal("failed delegated attempts not throttled")
	}
}

func TestDelegatedAccessProxyResponses(t *testing.T) {
	for _, transport := range []string{"ws", "h3-multistream", "h3-multistream-v2"} {
		for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
			t.Run(fmt.Sprintf("%s/%d", transport, status), func(t *testing.T) {
				sess, read, write := newStreamingLimitTestPeer(t, transport)
				s := &Server{}
				s.cfg.RequestTimeout = time.Second
				route := delegatedTestRoute()
				r := delegatedTestLogin("app-pass")
				r = r.WithContext(context.WithValue(r.Context(), delegatedConnectionKey{}, sess))
				rr := httptest.NewRecorder()
				if !s.authorizePublicRequest(rr, r, route) {
					t.Fatal("login rejected")
				}
				peerDone := make(chan error, 1)
				go func() {
					msg, err := read()
					if err != nil {
						peerDone <- err
						return
					}
					if msg.Request == nil || msg.Request.Method != http.MethodGet ||
						http.Header(msg.Request.Headers).Get("Authorization") != "Basic YWxpY2U6YXBwLXBhc3M=" {
						peerDone <- fmt.Errorf("credentials not forwarded as Basic on safe probe")
						return
					}
					peerDone <- write(tunnelproto.Message{Kind: tunnelproto.KindResponse,
						Response: &tunnelproto.HTTPResponse{
							ID: msg.Request.ID, Status: status, Streamed: true,
							Headers: http.Header{"Www-Authenticate": {`Basic realm="app"`}, "Content-Type": {"application/octet-stream"}},
						}})
				}()
				if transport == "ws" {
					s.proxyPublicHTTP(rr, r, route, sess)
				} else {
					s.proxyPublicHTTPH3MultiStream(rr, r, route, sess)
					if sess.h3StreamPool.idle() != 0 {
						t.Fatal("stream with unread upstream body was reused")
					}
				}
				if err := <-peerDone; err != nil {
					t.Fatal(err)
				}
				want := http.StatusSeeOther
				if status == http.StatusUnauthorized {
					want = http.StatusUnauthorized
				}
				if rr.Code != want || rr.Header().Get("WWW-Authenticate") != "" ||
					rr.Header().Get("Content-Type") == "application/octet-stream" || sess.pendingCount.Load() != 0 {
					t.Fatalf("upstream response not replaced safely: %d %v", rr.Code, rr.Header())
				}
			})
		}
	}
}

func TestDelegatedAccessDoesNotReplaceOtherAuthModes(t *testing.T) {
	t.Parallel()
	r := delegatedTestLogin("secret")
	s := &Server{}
	for _, mode := range []string{access.ModeForm, access.ModeBasic, ""} {
		route := domain.TunnelRoute{Tunnel: domain.Tunnel{AccessMode: mode}}
		rr := httptest.NewRecorder()
		headers := http.Header{"Www-Authenticate": {`Basic realm="app"`}}
		if s.handleDelegatedAccessResponse(rr, r, route, http.StatusUnauthorized, headers) ||
			headers.Get("WWW-Authenticate") == "" || len(rr.Header()) != 0 {
			t.Fatal("delegation altered an existing auth mode")
		}
	}
}

func TestDelegatedAccessProtectsItsCookie(t *testing.T) {
	t.Parallel()
	s := &Server{}
	r := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	headers := http.Header{"Set-Cookie": {publicAccessCookieName + "=spoofed; Path=/; Secure", "app=allowed; Path=/"}}
	if s.handleDelegatedAccessResponse(httptest.NewRecorder(), r, delegatedTestRoute(), http.StatusOK, headers) {
		t.Fatal("ordinary response unexpectedly replaced")
	}
	if strings.Join(headers.Values("Set-Cookie"), "") != "app=allowed; Path=/" || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("upstream could replace the delegated cookie or cache protected content")
	}
}

func TestDelegatedAccessRegistrationNeedsNoEdgePassword(t *testing.T) {
	t.Parallel()
	for _, extra := range []string{"", `,"user":"operator","password":"ignored"`} {
		s := &Server{}
		req := httptest.NewRequest(http.MethodPost, "/register",
			strings.NewReader(`{"access_mode":"upstream-basic"`+extra+`}`))
		rr := httptest.NewRecorder()
		prepared, ok := s.parseAndValidateRegisterRequest(rr, req)
		if !ok {
			t.Fatalf("delegated registration rejected: %d %s", rr.Code, rr.Body)
		}
		if err := s.prepareRegisterPasswordHash(t.Context(), "key", "", &prepared); err != nil {
			t.Fatal(err)
		}
		if prepared.accessMode != access.ModeUpstreamBasic || prepared.accessUser != "" ||
			prepared.passwordHash != "" || prepared.request.Password != "" {
			t.Fatal("delegated registration retained or required edge credentials")
		}
	}
}

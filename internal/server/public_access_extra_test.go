package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/auth"
	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

func testProtectedRoute(t *testing.T) domain.TunnelRoute {
	t.Helper()

	hash, err := auth.HashPassword("session-pass")
	if err != nil {
		t.Fatal(err)
	}
	return domain.TunnelRoute{
		Domain: domain.Domain{Hostname: "demo.example.com"},
		Tunnel: domain.Tunnel{
			ID:                 "tun_public",
			AccessUser:         "admin",
			AccessMode:         "form",
			AccessPasswordHash: hash,
		},
	}
}

func TestHandlePublicAccessLoginInvalidActionShowsForm(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: config.ServerConfig{AccessCookieSecret: testAccessCookieSecret}}
	route := testProtectedRoute(t)
	form := url.Values{
		publicAccessFormActionField: {"preview"},
		publicAccessFormNextField:   {"/private"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://demo.example.com/private", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handlePublicAccessLogin(rr, req, route, publicAccessExpectedUser(route))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("handlePublicAccessLogin() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rr.Body.String(), `value="admin"`) {
		t.Fatalf("expected default user in form, got %q", rr.Body.String())
	}
}

func TestHandlePublicAccessLoginWrongPasswordClearsCookie(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: config.ServerConfig{AccessCookieSecret: testAccessCookieSecret}}
	route := testProtectedRoute(t)
	form := url.Values{
		publicAccessFormActionField:   {"login"},
		publicAccessFormUserField:     {"admin"},
		publicAccessFormPasswordField: {"wrong"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://demo.example.com/private", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handlePublicAccessLogin(rr, req, route, publicAccessExpectedUser(route))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("handlePublicAccessLogin() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rr.Body.String(), "Incorrect username or password.") {
		t.Fatalf("expected invalid-password message, got %q", rr.Body.String())
	}

	found := false
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name != publicAccessCookieName {
			continue
		}
		found = true
		if cookie.Value != "" || cookie.MaxAge >= 0 {
			t.Fatalf("expected cleared cookie, got %+v", cookie)
		}
	}
	if !found {
		t.Fatal("expected access cookie clear header")
	}
}

func TestHandlePublicAccessLoginRejectsMissingSecret(t *testing.T) {
	t.Parallel()

	srv := &Server{}
	route := testProtectedRoute(t)
	form := url.Values{
		publicAccessFormActionField:   {"login"},
		publicAccessFormUserField:     {"admin"},
		publicAccessFormPasswordField: {"session-pass"},
	}
	req := httptest.NewRequest(http.MethodPost, "https://demo.example.com/private", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handlePublicAccessLogin(rr, req, route, publicAccessExpectedUser(route))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("handlePublicAccessLogin() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestAuthorizePublicRequestDeniesNonGETWithoutForm(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: config.ServerConfig{AccessCookieSecret: testAccessCookieSecret}}
	route := testProtectedRoute(t)
	req := httptest.NewRequest(http.MethodPut, "https://demo.example.com/private", nil)
	rr := httptest.NewRecorder()

	if srv.authorizePublicRequest(rr, req, route) {
		t.Fatal("expected request to be denied")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("authorizePublicRequest() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func TestPublicAccessHelpers(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodHead, "https://demo.example.com/private/docs?tab=1", nil)

	if got := publicAccessCurrentTarget(req); got != "/private/docs?tab=1" {
		t.Fatalf("publicAccessCurrentTarget() = %q", got)
	}
	if got := publicAccessCurrentTarget(nil); got != "/" {
		t.Fatalf("publicAccessCurrentTarget(nil) = %q", got)
	}
	if got := publicAccessFormAction(req); got != "/private/docs" {
		t.Fatalf("publicAccessFormAction() = %q", got)
	}
	if got := publicAccessRedirectTarget("//evil.example.com", "/safe"); got != "/safe" {
		t.Fatalf("publicAccessRedirectTarget(cross-origin) = %q", got)
	}
	if got := publicAccessRedirectTarget("/ok?x=1", "/safe"); got != "/ok?x=1" {
		t.Fatalf("publicAccessRedirectTarget() = %q", got)
	}

	rr := httptest.NewRecorder()
	writePublicAccessForm(rr, req, domain.TunnelRoute{Domain: domain.Domain{Hostname: "demo.example.com"}}, publicAccessFormState{}, http.StatusUnauthorized)
	if rr.Code != http.StatusUnauthorized || rr.Body.Len() != 0 {
		t.Fatalf("HEAD access form = (%d, %q), want empty 401 body", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	clearPublicAccessCookie(rr)
	if len(rr.Result().Cookies()) != 1 || rr.Result().Cookies()[0].Name != publicAccessCookieName {
		t.Fatalf("expected clearPublicAccessCookie() to emit access cookie, got %+v", rr.Result().Cookies())
	}

	rr = httptest.NewRecorder()
	writePublicAccessDenied(rr)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("writePublicAccessDenied() status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
}

package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/access"
)

func TestNormalizeProtectedURL(t *testing.T) {
	got, err := normalizeProtectedURL("demo.example.com/private")
	if err != nil {
		t.Fatalf("normalizeProtectedURL error: %v", err)
	}
	if got != "https://demo.example.com/private" {
		t.Fatalf("unexpected normalized url: %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("Cookie: a='b'")
	want := `'Cookie: a='"'"'b'"'"''`
	if got != want {
		t.Fatalf("shellQuote: got %q, want %q", got, want)
	}
}

func TestFetchProtectedRouteAuthHeaderForm(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "sign in", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST after probe, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get(access.FormActionField); got != "login" {
			t.Fatalf("unexpected action: %q", got)
		}
		if got := r.Form.Get(access.FormUserField); got != "admin" {
			t.Fatalf("unexpected user: %q", got)
		}
		if got := r.Form.Get(access.FormPasswordField); got != "secret" {
			http.Error(w, "wrong password", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     access.CookieName,
			Value:    "cookie-token",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
		})
		w.Header().Set("Location", "/private")
		w.WriteHeader(http.StatusSeeOther)
	}))
	defer srv.Close()

	got, err := fetchProtectedRouteAuthHeader(context.Background(), srv.URL+"/private", "admin", "secret", true)
	if err != nil {
		t.Fatalf("fetchProtectedRouteAuthHeader error: %v", err)
	}
	if got != "Cookie: "+access.CookieName+"=cookie-token" {
		t.Fatalf("unexpected cookie header: %q", got)
	}
}

func TestFetchProtectedRouteAuthHeaderBasic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="expose"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
	}))
	defer srv.Close()

	got, err := fetchProtectedRouteAuthHeader(context.Background(), srv.URL+"/private", "admin", "secret", true)
	if err != nil {
		t.Fatalf("fetchProtectedRouteAuthHeader error: %v", err)
	}
	if !strings.HasPrefix(got, "Authorization: Basic ") {
		t.Fatalf("unexpected basic header: %q", got)
	}
}

func TestFetchProtectedRouteAuthHeaderRejectsBadLogin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "sign in", http.StatusUnauthorized)
			return
		}
		http.Error(w, "wrong password", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := fetchProtectedRouteAuthHeader(context.Background(), srv.URL+"/private", "admin", "wrong", true)
	if err == nil {
		t.Fatal("expected login failure")
	}
	if !strings.Contains(err.Error(), "wrong password") {
		t.Fatalf("expected password failure in error, got %v", err)
	}
}

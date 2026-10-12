package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/domain"
)

func newThrottleTestServer(t *testing.T) (*Server, domain.TunnelRoute) {
	t.Helper()
	// MinCost keeps the many deliberate bcrypt failures fast, and a
	// zero-refill limiter makes exhaustion deterministic: the production
	// refill rate would top the bucket back up while slow builds (-race)
	// grind through the failed attempts.
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(config.ServerConfig{AccessCookieSecret: "throttle-test-secret"}, nil, nil, "test")
	srv.accessLimiter = newConfiguredRateLimiter(0, accessAuthFailBurst, time.Minute)
	route := domain.TunnelRoute{
		Domain: domain.Domain{Hostname: "demo.example.com"},
		Tunnel: domain.Tunnel{
			AccessUser:         "admin",
			AccessMode:         "basic",
			AccessPasswordHash: string(hash),
		},
	}
	return srv, route
}

func TestConcurrentPasswordAttemptsRespectBudget(t *testing.T) {
	for _, mode := range []string{"basic", "form"} {
		t.Run(mode, func(t *testing.T) {
			srv, route := newThrottleTestServer(t)
			route.Tunnel.AccessMode = mode
			// Use a budget below the global cap so this checks atomic
			// per-client admission independently of the server-wide limit.
			const budget = 1
			srv.accessLimiter = newConfiguredRateLimiter(0, budget, time.Minute)
			hash, err := bcrypt.GenerateFromPassword([]byte("correct-pass"), bcrypt.DefaultCost)
			if err != nil {
				t.Fatal(err)
			}
			route.Tunnel.AccessPasswordHash = string(hash)
			start := make(chan struct{})
			var wg sync.WaitGroup
			var checked, throttled atomic.Int64
			for range 32 {
				wg.Go(func() {
					req := passwordAttemptRequest(mode, "wrong-pass")
					w := httptest.NewRecorder()
					<-start
					srv.authorizePublicRequest(w, req, route)
					switch w.Code {
					case http.StatusUnauthorized:
						checked.Add(1)
					case http.StatusTooManyRequests:
						throttled.Add(1)
					default:
						t.Errorf("unexpected status: %d", w.Code)
					}
				})
			}
			close(start)
			wg.Wait()
			if checked.Load() != budget || throttled.Load() != 32-budget {
				t.Fatalf("checks=%d throttled=%d budget=%d", checked.Load(), throttled.Load(), budget)
			}
			if srv.accessChecks.Load() != 0 {
				t.Fatal("password verification slot leaked")
			}
		})
	}
}

func passwordAttemptRequest(mode, password string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	if mode == "form" {
		form := url.Values{publicAccessFormActionField: {"login"}, publicAccessFormUserField: {"admin"}, publicAccessFormPasswordField: {password}}
		req = httptest.NewRequest(http.MethodPost, "https://demo.example.com/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req.SetBasicAuth("admin", password)
	}
	req.RemoteAddr = "203.0.113.7:1234"
	return req
}

func TestPasswordSuccessRefundsOnlyItsOwnAttempt(t *testing.T) {
	for _, mode := range []string{"basic", "form"} {
		t.Run(mode, func(t *testing.T) {
			srv, route := newThrottleTestServer(t)
			route.Tunnel.AccessMode = mode
			attempt := func(password string) int {
				w := httptest.NewRecorder()
				srv.authorizePublicRequest(w, passwordAttemptRequest(mode, password), route)
				return w.Code
			}
			for range int(accessAuthFailBurst) - 1 {
				if got := attempt("wrong-pass"); got != http.StatusUnauthorized {
					t.Fatalf("wrong password status=%d", got)
				}
			}
			for range 15 {
				got := attempt("correct-pass")
				if got != http.StatusOK && got != http.StatusSeeOther {
					t.Fatalf("success consumed failure budget: status=%d", got)
				}
			}
			if got := attempt("wrong-pass"); got != http.StatusUnauthorized {
				t.Fatalf("last failure budget unavailable: status=%d", got)
			}
			if got := attempt("wrong-pass"); got != http.StatusTooManyRequests {
				t.Fatalf("success erased previous failures: status=%d", got)
			}
		})
	}
}

func TestPasswordChecksHaveServerWideLimit(t *testing.T) {
	for _, mode := range []string{"basic", "form"} {
		t.Run(mode, func(t *testing.T) {
			srv, route := newThrottleTestServer(t)
			route.Tunnel.AccessMode = mode
			srv.accessChecks.Store(maxAccessChecks)
			w := httptest.NewRecorder()
			req := passwordAttemptRequest(mode, "wrong-pass")
			srv.authorizePublicRequest(w, req, route)
			if w.Code != http.StatusTooManyRequests || srv.accessChecks.Load() != maxAccessChecks {
				t.Fatalf("global limit: status=%d active=%d", w.Code, srv.accessChecks.Load())
			}
			srv.accessChecks.Store(0)
			// Rejecting overload must not burn an attempt that was never checked.
			for range int(accessAuthFailBurst) {
				w = httptest.NewRecorder()
				srv.authorizePublicRequest(w, passwordAttemptRequest(mode, "wrong-pass"), route)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("overload consumed attempt: status=%d", w.Code)
				}
			}
		})
	}
}

func TestBasicAuthFailedAttemptsThrottled(t *testing.T) {
	srv, route := newThrottleTestServer(t)

	// Exhaust the failure budget with wrong passwords.
	for i := range int(accessAuthFailBurst) {
		req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
		req.RemoteAddr = "203.0.113.7:1234"
		req.SetBasicAuth("admin", "wrong-pass")
		rr := httptest.NewRecorder()
		if srv.authorizePublicRequest(rr, req, route) {
			t.Fatalf("attempt %d: wrong password authorized", i)
		}
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rr.Code)
		}
	}

	// The next attempt is throttled before bcrypt — even the right password.
	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "203.0.113.7:1234"
	req.SetBasicAuth("admin", "correct-pass")
	rr := httptest.NewRecorder()
	if srv.authorizePublicRequest(rr, req, route) {
		t.Fatal("throttled attempt authorized")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled status = %d, want 429", rr.Code)
	}

	// A different client IP is unaffected.
	req = httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "198.51.100.9:4321"
	req.SetBasicAuth("admin", "correct-pass")
	rr = httptest.NewRecorder()
	if !srv.authorizePublicRequest(rr, req, route) {
		t.Fatal("other client should not be throttled")
	}

	// Requests without credentials never consume the budget (no lockout by
	// merely loading the challenge).
	for range 30 {
		req = httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
		req.RemoteAddr = "192.0.2.5:1111"
		rr = httptest.NewRecorder()
		srv.authorizePublicRequest(rr, req, route)
	}
	req = httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "192.0.2.5:1111"
	req.SetBasicAuth("admin", "correct-pass")
	rr = httptest.NewRecorder()
	if !srv.authorizePublicRequest(rr, req, route) {
		t.Fatal("credential-less requests must not drain the failure budget")
	}
}

func TestBasicAuthSuccessCacheIsBoundToPasswordHash(t *testing.T) {
	srv, route := newThrottleTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "https://demo.example.com/", nil)
	req.RemoteAddr = "198.51.100.10:4321"
	req.SetBasicAuth("admin", "correct-pass")

	if !srv.authorizePublicRequest(httptest.NewRecorder(), req, route) {
		t.Fatal("valid credentials were not authorized")
	}
	key := srv.basicAuthSuccessKey(route, "admin", "correct-pass")
	if !srv.basicAuthCache.valid(key, time.Now()) {
		t.Fatal("successful credentials were not cached")
	}

	changedHash, err := bcrypt.GenerateFromPassword([]byte("new-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	route.Tunnel.AccessPasswordHash = string(changedHash)
	if srv.authorizePublicRequest(httptest.NewRecorder(), req, route) {
		t.Fatal("cached credentials remained valid after the password hash changed")
	}
}

func TestFormLoginFailedAttemptsThrottled(t *testing.T) {
	srv, route := newThrottleTestServer(t)
	route.Tunnel.AccessMode = "form"

	postLogin := func(password string) *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set(publicAccessFormActionField, "login")
		form.Set(publicAccessFormUserField, "admin")
		form.Set(publicAccessFormPasswordField, password)
		req := httptest.NewRequest(http.MethodPost, "https://demo.example.com/login", strings.NewReader(form.Encode()))
		req.RemoteAddr = "203.0.113.7:1234"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.authorizePublicRequest(rr, req, route)
		return rr
	}

	for i := range int(accessAuthFailBurst) {
		if rr := postLogin("wrong-pass"); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i, rr.Code)
		}
	}
	if rr := postLogin("correct-pass"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled login status = %d, want 429", rr.Code)
	}
}

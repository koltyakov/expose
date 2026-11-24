package server

import (
	"context"
	"fmt"
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
			for i := range 32 {
				wg.Go(func() {
					// Distinct guesses: identical Basic credentials share one
					// verification (see TestBasicAuthColdCacheSharesVerification).
					req := passwordAttemptRequest(mode, fmt.Sprintf("wrong-pass-%d", i))
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

func TestBasicAuthColdCacheSharesVerification(t *testing.T) {
	srv, route := newThrottleTestServer(t)
	srv.accessLimiter = newConfiguredRateLimiter(accessAuthFailRate, accessAuthFailBurst, time.Minute)
	// DefaultCost keeps bcrypt slow enough that the requests overlap.
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	route.Tunnel.AccessPasswordHash = string(hash)
	// Leave a single server-wide check slot: separate verifications would
	// throttle all but one request.
	srv.accessChecks.Store(maxAccessChecks - 1)

	const parallel = 32 // more than the per-client failure burst too
	start := make(chan struct{})
	var wg sync.WaitGroup
	var ok, other atomic.Int64
	for range parallel {
		wg.Go(func() {
			req := passwordAttemptRequest("basic", "correct-pass")
			w := httptest.NewRecorder()
			<-start
			if srv.authorizePublicRequest(w, req, route) {
				ok.Add(1)
			} else {
				other.Add(1)
				t.Errorf("valid credentials rejected: status=%d", w.Code)
			}
		})
	}
	close(start)
	wg.Wait()
	if ok.Load() != parallel {
		t.Fatalf("authorized %d of %d", ok.Load(), parallel)
	}
	if srv.accessChecks.Load() != maxAccessChecks-1 {
		t.Fatalf("check slots leaked: %d", srv.accessChecks.Load())
	}

	// Wrong credentials are still throttled once the budget is spent.
	srv.accessChecks.Store(0)
	srv.accessLimiter = newConfiguredRateLimiter(0, 2, time.Minute)
	for i, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		w := httptest.NewRecorder()
		srv.authorizePublicRequest(w, passwordAttemptRequest("basic", fmt.Sprintf("guess-%d", i)), route)
		if w.Code != want {
			t.Fatalf("guess %d: status=%d want %d", i, w.Code, want)
		}
	}
}

func TestBasicAuthWaiterRetriesWhenLeaderThrottled(t *testing.T) {
	srv, route := newThrottleTestServer(t)
	key := srv.basicAuthSuccessKey(route, "admin", "correct-pass")
	flight, leader := srv.basicAuthFlights.join(key)
	if !leader {
		t.Fatal("expected to lead the first flight")
	}
	done := make(chan bool, 1)
	go func() {
		done <- srv.authorizePublicRequest(httptest.NewRecorder(), passwordAttemptRequest("basic", "correct-pass"), route)
	}()
	time.Sleep(20 * time.Millisecond)
	// A leader throttled under another client's budget must not fail waiters.
	srv.basicAuthFlights.finish(key, flight, false, false)
	select {
	case got := <-done:
		if !got {
			t.Fatal("waiter rejected after the leader was throttled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not retry")
	}
}

func TestBasicAuthWaiterStopsOnCancel(t *testing.T) {
	srv, route := newThrottleTestServer(t)
	key := srv.basicAuthSuccessKey(route, "admin", "correct-pass")
	flight, _ := srv.basicAuthFlights.join(key)
	defer srv.basicAuthFlights.finish(key, flight, false, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := passwordAttemptRequest("basic", "correct-pass").WithContext(ctx)
	if srv.authorizePublicRequest(httptest.NewRecorder(), req, route) {
		t.Fatal("cancelled waiter authorized")
	}
}

func TestBasicAuthCacheHitSlidesExpiry(t *testing.T) {
	var c basicAuthSuccessCache
	key := [32]byte{1}
	now := time.Now()
	c.remember(key, now)
	later := now.Add(basicAuthSuccessTTL - time.Second)
	if !c.valid(key, later) {
		t.Fatal("entry expired early")
	}
	if !c.valid(key, later.Add(basicAuthSuccessTTL-time.Second)) {
		t.Fatal("hit did not slide the expiry")
	}
	if c.valid(key, later.Add(3*basicAuthSuccessTTL)) {
		t.Fatal("idle entry did not expire")
	}
}

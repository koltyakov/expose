package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestForwardersReturnRedirectWithoutFetchingPrivateService(t *testing.T) {
	var privateRequests atomic.Int64
	private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateRequests.Add(1)
		_, _ = io.WriteString(w, "private service secret")
	}))
	defer private.Close()
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			exposed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, private.URL, status)
			}))
			defer exposed.Close()
			target, _ := url.Parse(exposed.URL)
			c := New(config.ClientConfig{}, nil)
			defer c.fwdClient.CloseIdleConnections()
			req := &tunnelproto.HTTPRequest{ID: "redirect", Method: http.MethodGet, Path: "/redirect"}
			check := func(response *tunnelproto.HTTPResponse) {
				t.Helper()
				if response == nil || response.Status != status || http.Header(response.Headers).Get("Location") != private.URL {
					t.Fatalf("redirect not preserved: %+v", response)
				}
				if privateRequests.Load() != 0 {
					t.Fatal("forwarder fetched the private redirect destination")
				}
			}
			check(c.forwardLocal(t.Context(), target, req))
			var response *tunnelproto.HTTPResponse
			c.forwardAndSend(context.Background(), target, req, nil, func(msg tunnelproto.Message) error {
				if msg.Response != nil {
					response = msg.Response
				}
				return nil
			}, func(string, []byte) error { return nil })
			check(response)
		})
	}
}

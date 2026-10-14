package cli

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestUpRouterCompressionNegotiationTransport(t *testing.T) {
	t.Parallel()
	for _, count := range []int{1, 5} {
		tr := newUpRouterTransport(count)
		defer tr.CloseIdleConnections()
		if !tr.DisableCompression || tr == http.DefaultTransport {
			t.Fatal("router must clone the transport and disable automatic compression")
		}
		if tr.Proxy == nil || tr.DialContext == nil || tr.TLSHandshakeTimeout <= 0 {
			t.Fatal("cloned proxy, dial and TLS defaults changed")
		}
		maxPerHost := max(16, count*8)
		if tr.MaxIdleConns != maxPerHost || tr.MaxIdleConnsPerHost != maxPerHost || tr.MaxConnsPerHost != maxPerHost ||
			tr.IdleConnTimeout != upRouterProxyIdleConnTimeout || tr.ResponseHeaderTimeout != upRouterProxyResponseHeaderTTL {
			t.Fatal("router connection reuse, concurrency or timeout settings changed")
		}
	}
}

func TestUpRouterCompressionNegotiationRepresentations(t *testing.T) {
	t.Parallel()
	plain := []byte("hello synthetic upstream representation\n")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	representations := map[string][]byte{
		"": plain, "gzip": buf.Bytes(),
		// Brotli uncompressed block for "hello", forwarded without decoding.
		"br": {0x0b, 0x02, 0x80, 'h', 'e', 'l', 'l', 'o', 0x03},
	}
	for _, tc := range []struct {
		name, encoding, coding, method, byteRange string
		present                                   bool
		status                                    int
	}{
		{name: "absent"},
		{name: "empty", present: true},
		{name: "gzip", encoding: "gzip", coding: "gzip", present: true},
		{name: "br", encoding: "br", coding: "br", present: true},
		{name: "gzip-br", encoding: "gzip, br", coding: "br", present: true},
		{name: "gzip-refused", encoding: "gzip;q=0", present: true},
		{name: "identity", encoding: "identity", present: true},
		{name: "head-absent", method: http.MethodHead},
		{name: "head-gzip", method: http.MethodHead, encoding: "gzip", coding: "gzip", present: true},
		{name: "range-absent", byteRange: "bytes=0-7", status: http.StatusPartialContent},
		{name: "range-gzip", byteRange: "bytes=0-7", status: http.StatusPartialContent, encoding: "gzip", coding: "gzip", present: true},
		{name: "origin-gzip-without-negotiation", coding: "gzip"},
		{name: "origin-gzip-empty-negotiation", coding: "gzip", present: true},
		{name: "not-modified-gzip", encoding: "gzip", coding: "gzip", present: true, status: http.StatusNotModified},
		{name: "redirect", status: http.StatusFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method, status := tc.method, tc.status
			if method == "" {
				method = http.MethodGet
			}
			if status == 0 {
				status = http.StatusOK
			}
			body := representations[tc.coding]
			wantHeaders := make(http.Header)
			if tc.coding != "" {
				wantHeaders.Set("Content-Encoding", tc.coding)
			}
			wantHeaders.Set("ETag", `"fixture-`+tc.coding+`"`)
			wantHeaders.Add("Vary", "Accept-Encoding")
			wantHeaders.Add("Vary", "X-Fixture")
			wantHeaders.Set("Cache-Control", "no-transform")
			if tc.byteRange != "" {
				wantHeaders.Set("Content-Range", "bytes 0-7/"+strconv.Itoa(len(body)))
				body = body[:8]
			}
			if status != http.StatusNotModified {
				wantHeaders.Set("Content-Length", strconv.Itoa(len(body)))
			}
			if status == http.StatusFound {
				wantHeaders.Set("Location", "/followed")
			}
			seen := make(chan *http.Request, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/followed" {
					http.Error(w, "redirect must not be followed", http.StatusInternalServerError)
					return
				}
				seen <- r.Clone(r.Context())
				for name, values := range wantHeaders {
					w.Header()[name] = append([]string(nil), values...)
				}
				w.WriteHeader(status)
				if method != http.MethodHead && status != http.StatusNotModified {
					_, _ = w.Write(body)
				}
			}))
			defer upstream.Close()
			_, portText, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatal(err)
			}
			router, publicPort, err := startUpLocalRouter(t.Context(), []upLocalRoute{{Name: "fixture", PathPrefix: "/", LocalPort: port}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = router.server.Close() }()
			tr := &http.Transport{DisableCompression: true}
			defer tr.CloseIdleConnections()
			caller := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, err := http.NewRequestWithContext(t.Context(), method, fmt.Sprintf("http://127.0.0.1:%d/fixture", publicPort), nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.present {
				req.Header.Set("Accept-Encoding", tc.encoding)
			}
			if tc.byteRange != "" {
				req.Header.Set("Range", tc.byteRange)
			}
			resp, err := caller.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			gotBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			var observed *http.Request
			select {
			case observed = <-seen:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream request missing")
			}
			if !reflect.DeepEqual(observed.Header.Values("Accept-Encoding"), req.Header.Values("Accept-Encoding")) || observed.Header.Get("Range") != tc.byteRange || observed.Method != method {
				t.Errorf("upstream negotiation/method changed: %s %v", observed.Method, observed.Header)
			}
			wantBody := body
			if method == http.MethodHead || status == http.StatusNotModified {
				wantBody = nil
			}
			if resp.StatusCode != status || !bytes.Equal(gotBody, wantBody) || resp.Uncompressed {
				t.Errorf("representation changed: status=%d/%d body bytes=%d/%d uncompressed=%v", resp.StatusCode, status, len(gotBody), len(wantBody), resp.Uncompressed)
			}
			for _, name := range []string{"Content-Encoding", "Content-Length", "ETag", "Vary", "Cache-Control", "Content-Range", "Location"} {
				if !reflect.DeepEqual(resp.Header.Values(name), wantHeaders.Values(name)) {
					t.Errorf("%s = %q, want %q", name, resp.Header.Values(name), wantHeaders.Values(name))
				}
			}
		})
	}
}

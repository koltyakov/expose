package client

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/tunnelproto"
)

func TestForwardCompressionNegotiationTransport(t *testing.T) {
	t.Parallel()
	c := New(config.ClientConfig{Timeout: 3 * time.Second, MaxConcurrentForwards: 7}, nil)
	tr := c.fwdClient.Transport.(*http.Transport)
	defer tr.CloseIdleConnections()
	if !tr.DisableCompression || tr == http.DefaultTransport {
		t.Fatal("forwarding must use a dedicated transport with automatic compression disabled")
	}
	if tr.Proxy == nil || tr.DialContext == nil || tr.TLSHandshakeTimeout <= 0 {
		t.Fatal("cloned proxy, dial and TLS defaults must remain configured")
	}
	if tr.MaxIdleConns != 100 || tr.MaxIdleConnsPerHost != 100 || tr.MaxConnsPerHost != 7 ||
		tr.IdleConnTimeout != 90*time.Second || tr.ResponseHeaderTimeout != 2*time.Minute {
		t.Fatal("connection reuse, concurrency or timeout settings changed")
	}
	if c.apiClient.Timeout != 3*time.Second || c.fwdClient.Timeout != 0 {
		t.Fatal("API and streaming-forward timeouts changed")
	}
	if err := c.fwdClient.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v, want ErrUseLastResponse", err)
	}
}

func TestForwardCompressionNegotiationRepresentations(t *testing.T) {
	t.Parallel()
	plain := []byte("hello synthetic upstream representation\n")
	large := make([]byte, streamingThreshold+4096)
	// Incompressible deterministic data exercises the streamed-response path.
	x := uint32(1)
	for i := range large {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		large[i] = byte(x)
	}
	gzipBytes := func(data []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	representations := map[string][]byte{
		"": plain, "gzip": gzipBytes(plain),
		// A Brotli uncompressed block containing "hello". The proxy never decodes it.
		"br": {0x0b, 0x02, 0x80, 'h', 'e', 'l', 'l', 'o', 0x03},
	}
	largeGzip := gzipBytes(large)
	if len(largeGzip) <= streamingThreshold {
		t.Fatal("large fixture must exceed the streaming threshold")
	}
	for _, mode := range []string{"buffered", "stream-capable"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name, encoding, coding, method, path, byteRange string
				present                                         bool
				status                                          int
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
				{name: "origin-gzip-without-negotiation", path: "/force-gzip", coding: "gzip"},
				{name: "origin-gzip-empty-negotiation", path: "/force-gzip", coding: "gzip", present: true},
				{name: "large-gzip", path: "/large", encoding: "gzip", coding: "gzip", present: true},
				{name: "large-origin-gzip-without-negotiation", path: "/large-force-gzip", coding: "gzip"},
				{name: "not-modified-gzip", encoding: "gzip", coding: "gzip", present: true, status: http.StatusNotModified},
				{name: "redirect", path: "/redirect", status: http.StatusFound},
			} {
				t.Run(tc.name, func(t *testing.T) {
					method, path, status := tc.method, tc.path, tc.status
					if method == "" {
						method = http.MethodGet
					}
					if path == "" {
						path = "/"
					}
					if status == 0 {
						status = http.StatusOK
					}
					seen := make(chan http.Header, 1)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path == "/followed" {
							http.Error(w, "redirect must not be followed", http.StatusInternalServerError)
							return
						}
						seen <- r.Header.Clone()
						coding := ""
						if strings.Contains(r.Header.Get("Accept-Encoding"), "br") {
							coding = "br"
						} else if r.Header.Get("Accept-Encoding") == "gzip" || strings.Contains(r.URL.Path, "force-gzip") {
							coding = "gzip"
						}
						body := representations[coding]
						if strings.Contains(r.URL.Path, "large") && coding == "gzip" {
							body = largeGzip
						}
						w.Header().Set("ETag", `"fixture-`+coding+`"`)
						w.Header().Add("Vary", "Accept-Encoding")
						w.Header().Add("Vary", "X-Fixture")
						w.Header().Set("Cache-Control", "no-transform")
						if coding != "" {
							w.Header().Set("Content-Encoding", coding)
						}
						if r.Header.Get("Range") != "" {
							w.Header().Set("Content-Range", "bytes 0-7/"+strconv.Itoa(len(body)))
							body = body[:8]
						}
						if status != http.StatusNotModified {
							w.Header().Set("Content-Length", strconv.Itoa(len(body)))
						}
						if status == http.StatusFound {
							w.Header().Set("Location", "/followed")
						}
						w.WriteHeader(status)
						if r.Method != http.MethodHead && status != http.StatusNotModified {
							_, _ = w.Write(body)
						}
					}))
					defer upstream.Close()
					c := New(config.ClientConfig{}, nil)
					defer c.fwdClient.CloseIdleConnections()
					base, err := url.Parse(upstream.URL)
					if err != nil {
						t.Fatal(err)
					}
					headers := make(http.Header)
					if tc.present {
						headers.Set("Accept-Encoding", tc.encoding)
					}
					if tc.byteRange != "" {
						headers.Set("Range", tc.byteRange)
					}
					req := &tunnelproto.HTTPRequest{ID: "coding-fixture", Method: method, Path: path, Headers: headers}
					var got *tunnelproto.HTTPResponse
					var body []byte
					if mode == "buffered" {
						got = c.forwardLocal(t.Context(), base, req)
						body, err = got.Payload()
					} else {
						c.forwardAndSend(t.Context(), base, req, nil, func(msg tunnelproto.Message) error {
							if msg.Response != nil {
								copy := *msg.Response
								got = &copy
								data, payloadErr := msg.Response.Payload()
								body = append(body, data...)
								return payloadErr
							}
							if msg.BodyChunk != nil && msg.BodyChunk.Error != "" {
								t.Errorf("stream failed: %s", msg.BodyChunk.Error)
							}
							return nil
						}, func(_ string, data []byte) error {
							body = append(body, data...)
							return nil
						})
					}
					if err != nil || got == nil {
						t.Fatalf("missing/invalid response: %v", err)
					}
					var observed http.Header
					select {
					case observed = <-seen:
					case <-time.After(5 * time.Second):
						t.Fatal("upstream request missing")
					}
					if !reflect.DeepEqual(observed.Values("Accept-Encoding"), headers.Values("Accept-Encoding")) || observed.Get("Range") != tc.byteRange {
						t.Errorf("negotiation changed: got %v, want %v", observed, headers)
					}
					wantBody := representations[tc.coding]
					if strings.Contains(path, "large") {
						wantBody = largeGzip
					}
					wantHeaders := http.Header{"Etag": {`"fixture-` + tc.coding + `"`}, "Vary": {"Accept-Encoding", "X-Fixture"}, "Cache-Control": {"no-transform"}}
					if tc.coding != "" {
						wantHeaders.Set("Content-Encoding", tc.coding)
					}
					if tc.byteRange != "" {
						wantHeaders.Set("Content-Range", "bytes 0-7/"+strconv.Itoa(len(wantBody)))
						wantBody = wantBody[:8]
					}
					if status != http.StatusNotModified {
						wantHeaders.Set("Content-Length", strconv.Itoa(len(wantBody)))
					}
					if status == http.StatusFound {
						wantHeaders.Set("Location", "/followed")
					}
					if method == http.MethodHead || status == http.StatusNotModified {
						wantBody = nil
					}
					if got.Status != status || !bytes.Equal(body, wantBody) {
						t.Errorf("representation changed: status=%d/%d body bytes=%d/%d", got.Status, status, len(body), len(wantBody))
					}
					for _, name := range []string{"Content-Encoding", "Content-Length", "ETag", "Vary", "Cache-Control", "Content-Range", "Location"} {
						if !reflect.DeepEqual(http.Header(got.Headers).Values(name), wantHeaders.Values(name)) {
							t.Errorf("%s = %q, want %q", name, http.Header(got.Headers).Values(name), wantHeaders.Values(name))
						}
					}
					if mode == "stream-capable" && strings.Contains(path, "large") && !got.Streamed {
						t.Fatal("large gzip fixture must exercise streamed response forwarding")
					}
				})
			}
		})
	}
}

package publish

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestServeContentCachePolicy(t *testing.T) {
	dir := t.TempDir()
	const body = "0123456789"
	writeFile(t, dir, "index.html", body)
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(dir, "index.html"), stamp, stamp); err != nil {
		t.Fatal(err)
	}
	for _, ws := range []bool{false, true} {
		opts := ServeOptions{WS: ws}
		warm := httptest.NewRecorder()
		ServeWithOptions(warm, httptest.NewRequest("GET", "/index.html", nil), dir, opts)
		etag := warm.Header().Get("ETag")
		content := body
		if ws {
			content += presenceHTMLScript
		}
		cases := []struct {
			name    string
			headers http.Header
			status  int
		}{
			{name: "complete", status: 200},
			{name: "etag match", headers: http.Header{"If-None-Match": {etag}}, status: 304},
			{name: "date match", headers: http.Header{"If-Modified-Since": {stamp.Format(http.TimeFormat)}}, status: 304},
			{name: "range", headers: http.Header{"Range": {"bytes=2-5"}}, status: 206},
			{name: "matching If-Range", headers: http.Header{"Range": {"bytes=2-5"}, "If-Range": {etag}}, status: 206},
			{name: "stale If-Range", headers: http.Header{"Range": {"bytes=2-5"}, "If-Range": {`"other"`}}, status: 200},
			{name: "If-Match failure", headers: http.Header{"If-Match": {`"other"`}}, status: 412},
			{name: "unmodified failure", headers: http.Header{"If-Unmodified-Since": {stamp.Add(-time.Hour).Format(http.TimeFormat)}}, status: 412},
			{name: "malformed range", headers: http.Header{"Range": {"bytes=oops"}}, status: 416},
			{name: "reversed range", headers: http.Header{"Range": {"bytes=5-2"}}, status: 416},
			{name: "unsatisfiable range", headers: http.Header{"Range": {fmt.Sprintf("bytes=%d-", len(content)+1)}}, status: 416},
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, tc := range cases {
				t.Run(fmt.Sprintf("ws=%t/%s/%s", ws, method, tc.name), func(t *testing.T) {
					r := httptest.NewRequest(method, "/index.html", nil)
					if tc.headers != nil {
						r.Header = tc.headers.Clone()
					}
					got := httptest.NewRecorder()
					ServeWithOptions(got, r, dir, opts)

					// Compare with ServeContent itself. The wrapper must change
					// only the error cache policy, not bodies or other metadata.
					want := httptest.NewRecorder()
					want.Header().Set("ETag", etag)
					want.Header().Set("Cache-Control", "no-cache")
					want.Header().Set("X-Content-Type-Options", "nosniff")
					if ws {
						want.Header().Set("Content-Type", "text/html; charset=utf-8")
					}
					http.ServeContent(want, r, "index.html", stamp, strings.NewReader(content))
					if tc.status >= 400 {
						want.Header().Set("Cache-Control", "no-store")
					}
					if got.Code != tc.status || got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Result().Header, want.Header()) {
						t.Fatalf("got %d %q %v, want %d %q %v", got.Code, got.Body.String(), got.Result().Header, want.Code, want.Body.String(), want.Header())
					}
				})
			}
		}
	}
}

func TestServeMultipartRangesCachePolicy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "0123456789")
	for _, ws := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/index.html", nil)
		r.Header.Set("Range", "bytes=0-1,8-9")
		w := httptest.NewRecorder()
		ServeWithOptions(w, r, dir, ServeOptions{WS: ws})
		if w.Code != 206 || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("ETag") == "" {
			t.Fatalf("unexpected multipart response: %d %v", w.Code, w.Header())
		}
		typ, params, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
		if err != nil || typ != "multipart/byteranges" {
			t.Fatalf("unexpected multipart content type %q: %v", typ, err)
		}
		reader := multipart.NewReader(w.Body, params["boundary"])
		for _, want := range []string{"01", "89"} {
			part, err := reader.NextPart()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(part)
			if err != nil || string(got) != want {
				t.Fatalf("range = %q, want %q: %v", got, want, err)
			}
		}
		if _, err := reader.NextPart(); err != io.EOF {
			t.Fatalf("unexpected extra part: %v", err)
		}
	}
}

func TestServeEarlyErrorsCachePolicy(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		w := httptest.NewRecorder()
		Serve(w, httptest.NewRequest(method, "/missing", nil), t.TempDir())
		want := http.StatusNotFound
		if method == http.MethodPost {
			want = http.StatusMethodNotAllowed
		}
		if w.Code != want || w.Result().Header.Get("Cache-Control") != "no-store" || w.Header().Get("ETag") != "" {
			t.Fatalf("%s: unexpected error response %d %v", method, w.Code, w.Result().Header)
		}
	}
}

func TestPublicationContentWriterSemantics(t *testing.T) {
	t.Run("informational and duplicate statuses", func(t *testing.T) {
		underlying := &publicationWriterProbe{header: make(http.Header)}
		w := &publicationContentWriter{ResponseWriter: underlying}
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(103)
		w.WriteHeader(416)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("error"))
		if !reflect.DeepEqual(underlying.statuses, []int{103, 416}) || w.Header().Get("Cache-Control") != "no-store" || underlying.body.String() != "error" {
			t.Fatalf("unexpected status/body/cache: %#v", underlying)
		}
	})
	t.Run("implicit success does not become error", func(t *testing.T) {
		underlying := httptest.NewRecorder()
		w := &publicationContentWriter{ResponseWriter: underlying}
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write([]byte("ok"))
		w.WriteHeader(416)
		if underlying.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
			t.Fatal("duplicate status changed committed success")
		}
	})
	t.Run("ReaderFrom and controller delegation", func(t *testing.T) {
		underlying := &publicationWriterProbe{header: make(http.Header)}
		w := &publicationContentWriter{ResponseWriter: underlying}
		n, err := w.ReadFrom(strings.NewReader("body"))
		if err != nil || n != 4 || !underlying.readFrom || underlying.body.String() != "body" || !reflect.DeepEqual(underlying.statuses, []int{200}) {
			t.Fatalf("ReadFrom failed: %d %v %#v", n, err, underlying)
		}
		deadline := time.Now().Add(time.Minute)
		controller := http.NewResponseController(w)
		if w.Unwrap() != underlying || controller.SetReadDeadline(deadline) != nil || !underlying.deadline.Equal(deadline) || controller.Flush() != nil || !underlying.flushed {
			t.Fatal("controller delegation failed")
		}
	})
	t.Run("ReaderFrom fallback", func(t *testing.T) {
		underlying := httptest.NewRecorder()
		w := &publicationContentWriter{ResponseWriter: underlying}
		n, err := w.ReadFrom(strings.NewReader("body"))
		if err != nil || n != 4 || underlying.Code != 200 || underlying.Body.String() != "body" {
			t.Fatalf("fallback failed: %d %v", n, err)
		}
	})
}

type publicationWriterProbe struct {
	header   http.Header
	statuses []int
	body     bytes.Buffer
	readFrom bool
	flushed  bool
	deadline time.Time
}

func (w *publicationWriterProbe) Header() http.Header         { return w.header }
func (w *publicationWriterProbe) WriteHeader(status int)      { w.statuses = append(w.statuses, status) }
func (w *publicationWriterProbe) Write(p []byte) (int, error) { return w.body.Write(p) }
func (w *publicationWriterProbe) Flush()                      { w.flushed = true }
func (w *publicationWriterProbe) SetReadDeadline(t time.Time) error {
	w.deadline = t
	return nil
}
func (w *publicationWriterProbe) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return w.body.ReadFrom(r)
}

package selfupdate

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIsNewerExported(t *testing.T) {
	if !IsNewer("1.2.2", "1.2.3") {
		t.Fatal("IsNewer() = false, want true")
	}
	if IsNewer("1.2.3", "1.2.3") {
		t.Fatal("IsNewer() = true for identical versions, want false")
	}
}

func TestExtractBinary(t *testing.T) {
	tarData := makeTarGzArchive(t, "bin/expose", []byte("tar-binary"))
	got, err := extractBinary("expose_Linux_x86_64.tar.gz", tarData)
	if err != nil {
		t.Fatalf("extractBinary(tar) error = %v", err)
	}
	if string(got) != "tar-binary" {
		t.Fatalf("extractBinary(tar) = %q, want %q", string(got), "tar-binary")
	}

	zipData := makeZipArchive(t, "release/expose.exe", []byte("zip-binary"))
	got, err = extractBinary("expose_Windows_x86_64.zip", zipData)
	if err != nil {
		t.Fatalf("extractBinary(zip) error = %v", err)
	}
	if string(got) != "zip-binary" {
		t.Fatalf("extractBinary(zip) = %q, want %q", string(got), "zip-binary")
	}
}

func TestFetchLatestRelease(t *testing.T) {
	var responseStatus = http.StatusOK
	var responseBody = `{"tag_name":"v1.2.3","assets":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+GitHubRepo+"/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(responseStatus)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()
	useReleaseServer(t, server)

	rel, err := fetchLatestRelease(context.Background())
	if err != nil {
		t.Fatalf("fetchLatestRelease() error = %v", err)
	}
	if rel.TagName != "v1.2.3" {
		t.Fatalf("TagName = %q, want %q", rel.TagName, "v1.2.3")
	}

	responseBody = `{"assets":[]}`
	if _, err := fetchLatestRelease(context.Background()); err == nil || !strings.Contains(err.Error(), "missing tag_name") {
		t.Fatalf("fetchLatestRelease() error = %v, want missing tag_name error", err)
	}

	responseStatus = http.StatusBadGateway
	responseBody = `bad gateway`
	if _, err := fetchLatestRelease(context.Background()); err == nil || !strings.Contains(err.Error(), "GitHub API returned 502 Bad Gateway") {
		t.Fatalf("fetchLatestRelease() error = %v, want status error", err)
	}
}

func TestDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Length", "6")
			_, _ = w.Write([]byte("binary"))
		case "/large":
			w.Header().Set("Content-Length", "104857601")
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "nope", http.StatusBadGateway)
		}
	}))
	defer server.Close()
	useDownloadServer(t, server)

	data, err := download(context.Background(), server.URL+"/ok")
	if err != nil {
		t.Fatalf("download(ok) error = %v", err)
	}
	if string(data) != "binary" {
		t.Fatalf("download(ok) = %q, want %q", string(data), "binary")
	}

	if _, err := download(context.Background(), server.URL+"/status"); err == nil || !strings.Contains(err.Error(), "download returned 502 Bad Gateway") {
		t.Fatalf("download(status) error = %v, want status error", err)
	}
	if _, err := download(context.Background(), server.URL+"/large"); err == nil || !strings.Contains(err.Error(), "download too large") {
		t.Fatalf("download(large) error = %v, want size error", err)
	}
}

func TestCheck(t *testing.T) {
	var tagName = "v1.2.3"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"` + tagName + `","assets":[]}`))
	}))
	defer server.Close()
	useReleaseServer(t, server)

	rel, err := Check(context.Background(), "v1.2.2")
	if err != nil {
		t.Fatalf("Check(newer) error = %v", err)
	}
	if rel == nil || rel.TagName != tagName {
		t.Fatalf("Check(newer) = %#v, want release %q", rel, tagName)
	}

	rel, err = Check(context.Background(), "v1.2.3")
	if err != nil {
		t.Fatalf("Check(same) error = %v", err)
	}
	if rel != nil {
		t.Fatalf("Check(same) = %#v, want nil", rel)
	}

	rel, err = Check(context.Background(), "dev")
	if err != nil {
		t.Fatalf("Check(dev) error = %v", err)
	}
	if rel != nil {
		t.Fatalf("Check(dev) = %#v, want nil", rel)
	}
}

func TestApplyAndCheckAndApplyErrorPaths(t *testing.T) {
	assetName, err := assetNameForPlatform()
	if err != nil {
		t.Fatalf("assetNameForPlatform() error = %v", err)
	}

	downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not an archive"))
	}))
	defer downloadServer.Close()
	useDownloadServer(t, downloadServer)

	rel := &Release{
		TagName: "v9.9.9",
		Assets: []Asset{
			{Name: assetName, BrowserDownloadURL: downloadServer.URL + "/asset"},
		},
	}
	if _, err := Apply(context.Background(), rel); err == nil || !strings.Contains(err.Error(), "extract binary") {
		t.Fatalf("Apply() error = %v, want extract error", err)
	}

	if _, err := Apply(context.Background(), &Release{TagName: "v9.9.9"}); err == nil || !strings.Contains(err.Error(), "no release asset") {
		t.Fatalf("Apply(missing asset) error = %v, want missing asset error", err)
	}

	releaseTag := "v1.2.3"
	releaseServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"` + releaseTag + `","assets":[]}`))
	}))
	defer releaseServer.Close()
	useReleaseServer(t, releaseServer)

	result, err := CheckAndApply(context.Background(), "1.2.3")
	if err != nil {
		t.Fatalf("CheckAndApply(no update) error = %v", err)
	}
	if result.Updated {
		t.Fatalf("CheckAndApply(no update) Updated = true, want false")
	}
	if result.CurrentVersion != "1.2.3" {
		t.Fatalf("CheckAndApply(no update) CurrentVersion = %q, want %q", result.CurrentVersion, "1.2.3")
	}

	releaseTag = "v9.9.9"
	releaseServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","assets":[{"name":"` + assetName + `","browser_download_url":"` + downloadServer.URL + `/asset"}]}`))
	})
	result, err = CheckAndApply(context.Background(), "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "extract binary") {
		t.Fatalf("CheckAndApply(update error) error = %v, want extract error", err)
	}
	if result != nil {
		t.Fatalf("CheckAndApply(update error) result = %#v, want nil", result)
	}
}

func useReleaseServer(t *testing.T, server *httptest.Server) {
	t.Helper()

	previous := releaseHTTPClient
	t.Cleanup(func() { releaseHTTPClient = previous })

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("Parse(server.URL) error = %v", err)
	}
	base := server.Client().Transport
	if base == nil {
		base = http.DefaultTransport
	}
	releaseHTTPClient = &http.Client{
		Timeout:   time.Second,
		Transport: rewriteTransport{target: target, base: base},
	}
}

func useDownloadServer(t *testing.T, server *httptest.Server) {
	t.Helper()

	previous := downloadHTTPClient
	t.Cleanup(func() { downloadHTTPClient = previous })

	client := server.Client()
	client.Timeout = time.Second
	downloadHTTPClient = client
}

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	clone.Host = t.target.Host
	return t.base.RoundTrip(clone)
}

func makeTarGzArchive(t *testing.T, name string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(content)),
	}); err != nil {
		t.Fatalf("WriteHeader() error = %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close(tar) error = %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("Close(gzip) error = %v", err)
	}
	return buf.Bytes()
}

func makeZipArchive(t *testing.T, name string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close(zip) error = %v", err)
	}
	return buf.Bytes()
}

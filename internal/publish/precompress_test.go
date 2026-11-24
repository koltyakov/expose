package publish

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
)

func writeSiteFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func variantExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, filepath.FromSlash(precompressedName(name))))
	return err == nil
}

func TestPrecompressWritesVariantsOutsideManifest(t *testing.T) {
	dir := t.TempDir()
	text := []byte(strings.Repeat("function hello() { return 'world'; }\n", 200))
	random := make([]byte, 4096)
	_, _ = rand.Read(random)
	writeSiteFile(t, dir, "index.html", []byte("<html>"+strings.Repeat("<p>hello</p>", 200)+"</html>"))
	writeSiteFile(t, dir, "assets/app.js", text)
	writeSiteFile(t, dir, "assets/small.css", []byte("body{}"))
	writeSiteFile(t, dir, "assets/logo.png", text)     // not a compressible type
	writeSiteFile(t, dir, "assets/noise.json", random) // does not shrink
	before, err := Manifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	count, size, _ := FileTotals(dir)

	if err := Precompress(dir, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"index.html": true, "assets/app.js": true,
		"assets/small.css": false, "assets/logo.png": false, "assets/noise.json": false,
	} {
		if got := variantExists(dir, name); got != want {
			t.Errorf("%s: variant exists = %v, want %v", name, got, want)
		}
	}
	gz, err := os.Open(filepath.Join(dir, filepath.FromSlash(precompressedName("assets/app.js"))))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gz.Close() }()
	zr, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); !bytes.Equal(got, text) {
		t.Fatal("variant does not decompress to the file")
	}

	// Variants never appear in manifests or totals, so incremental diffs and
	// stats are unchanged.
	after, err := Manifest(dir)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("manifest changed: %v", err)
	}
	if c, s, _ := FileTotals(dir); c != count || s != size {
		t.Fatalf("totals changed: %d/%d -> %d/%d", count, size, c, s)
	}
}

func TestPrecompressBudgetAndBaseReuse(t *testing.T) {
	text := []byte(strings.Repeat("const value = 42;\n", 500))
	base := t.TempDir()
	writeSiteFile(t, base, "index.html", text)
	writeSiteFile(t, base, "app.js", text)
	if err := Precompress(base, "", 1<<20); err != nil {
		t.Fatal(err)
	}

	// A tiny budget stops after the first variant that exceeds it.
	limited := t.TempDir()
	writeSiteFile(t, limited, "index.html", text)
	writeSiteFile(t, limited, "app.js", text)
	if err := Precompress(limited, "", 10); err != nil {
		t.Fatal(err)
	}
	if variantExists(limited, "index.html") || variantExists(limited, "app.js") {
		t.Fatal("variants exceeded the byte budget")
	}

	// An unchanged file hard-linked from the base reuses its variant.
	next := t.TempDir()
	if err := os.Link(filepath.Join(base, "app.js"), filepath.Join(next, "app.js")); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	writeSiteFile(t, next, "index.html", []byte(strings.Repeat("<p>changed</p>", 200)))
	if err := Precompress(next, base, 1<<20); err != nil {
		t.Fatal(err)
	}
	reused, err := os.Stat(filepath.Join(next, filepath.FromSlash(precompressedName("app.js"))))
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.Stat(filepath.Join(base, filepath.FromSlash(precompressedName("app.js"))))
	if !os.SameFile(reused, original) {
		t.Fatal("unchanged file was compressed again instead of reusing the base variant")
	}
	fresh, _ := os.Stat(filepath.Join(next, filepath.FromSlash(precompressedName("index.html"))))
	previous, _ := os.Stat(filepath.Join(base, filepath.FromSlash(precompressedName("index.html"))))
	if fresh == nil || os.SameFile(fresh, previous) {
		t.Fatal("changed file reused a stale variant")
	}
}

func TestServePrecompressedVariant(t *testing.T) {
	dir := t.TempDir()
	text := []byte(strings.Repeat("body { color: red; }\n", 200))
	writeSiteFile(t, dir, "index.html", []byte(strings.Repeat("<p>hello</p>", 200)))
	writeSiteFile(t, dir, "style.css", text)
	if err := Precompress(dir, "", 1<<20); err != nil {
		t.Fatal(err)
	}
	get := func(path string, header http.Header, opts ServeOptions) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range header {
			r.Header[k] = v
		}
		w := httptest.NewRecorder()
		ServeWithOptions(w, r, dir, opts)
		return w
	}

	identity := get("/style.css", nil, ServeOptions{})
	if identity.Code != 200 || identity.Header().Get("Content-Encoding") != "" || !bytes.Equal(identity.Body.Bytes(), text) {
		t.Fatalf("identity response: %d %q", identity.Code, identity.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(strings.Join(identity.Header().Values("Vary"), ","), "Accept-Encoding") {
		t.Fatal("identity response lacks Vary: Accept-Encoding")
	}

	gz := get("/style.css", http.Header{"Accept-Encoding": {"br, gzip;q=0.8"}}, ServeOptions{})
	if gz.Code != 200 || gz.Header().Get("Content-Encoding") != "gzip" || !strings.HasPrefix(gz.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("gzip response: %d %v", gz.Code, gz.Header())
	}
	if gz.Header().Get("ETag") == identity.Header().Get("ETag") {
		t.Fatal("gzip and identity responses share an ETag")
	}
	if gz.Body.Len() >= len(text) {
		t.Fatal("gzip body is not smaller")
	}
	zr, err := gzip.NewReader(gz.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(zr); !bytes.Equal(got, text) {
		t.Fatal("gzip body does not decode to the file")
	}

	for name, header := range map[string]http.Header{
		"refused": {"Accept-Encoding": {"gzip;q=0"}},
		"range":   {"Accept-Encoding": {"gzip"}, "Range": {"bytes=0-9"}},
	} {
		w := get("/style.css", header, ServeOptions{})
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s: served gzip", name)
		}
	}
	// HTML with an injected presence script is never served from a variant.
	if w := get("/", http.Header{"Accept-Encoding": {"gzip"}}, ServeOptions{WS: true}); w.Header().Get("Content-Encoding") != "" {
		t.Fatal("WS-injected HTML served from a precompressed variant")
	}
	// Variants are not reachable as paths.
	if w := get("/"+PrecompressedDir+"/style.css.gz", nil, ServeOptions{}); w.Code != http.StatusNotFound {
		t.Fatalf("variant directory reachable: %d", w.Code)
	}
}

func TestExtractWithManifestMatchesManifest(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"index.html", "a/b.txt", "a-c.txt", "a/z/d.txt", "b.txt"} {
		writeSiteFile(t, src, name, []byte("content of "+name))
	}
	var archive bytes.Buffer
	if err := Archive(src, &archive); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "site")
	if err := os.Mkdir(dst, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := ExtractWithManifest(&archive, dst, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Manifest(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("extract manifest differs from Manifest:\n got %v\nwant %v", got, want)
	}
}

func TestCompleteDeltaTrustsVerifiedBaseManifest(t *testing.T) {
	base := t.TempDir()
	writeSiteFile(t, base, "index.html", []byte("index"))
	writeSiteFile(t, base, "lib.js", []byte("library"))
	baseManifest, err := Manifest(base)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the base copy behind the manifest's back. Only a re-read can
	// notice, so success below proves the trusted entry skipped hashing.
	if err := os.WriteFile(filepath.Join(base, "lib.js"), []byte("LIBRARY"), 0600); err != nil {
		t.Fatal(err)
	}
	target := []domain.PublishedFile{baseManifest[0], baseManifest[1]}
	dir := t.TempDir()
	if err := CompleteDelta(base, dir, target, 1<<20); err == nil {
		t.Fatal("untrusted reuse did not verify the base file")
	}
	dir = t.TempDir()
	if err := CompleteDeltaWithBase(base, dir, target, 1<<20, baseManifest); err != nil {
		t.Fatalf("trusted reuse failed: %v", err)
	}
	// A manifest entry that does not match the target is not trusted.
	stale := []domain.PublishedFile{baseManifest[0], {Path: "lib.js", Checksum: strings.Repeat("0", 64), Size: 7}}
	if err := CompleteDeltaWithBase(base, t.TempDir(), target, 1<<20, stale); err == nil {
		t.Fatal("mismatched base entry was trusted")
	}
}

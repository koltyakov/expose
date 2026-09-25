package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, root, name, body string) {
	t.Helper()
	file := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestArchiveRoundTripAndSPARouting(t *testing.T) {
	source, dest := t.TempDir(), t.TempDir()
	for name, body := range map[string]string{"index.html": "root", "about.html": "html", "about/index.html": "folder", "docs/index.html": "docs", "app.js": "javascript"} {
		writeFile(t, source, name, body)
	}
	var archive bytes.Buffer
	if err := Archive(source, &archive); err != nil {
		t.Fatal(err)
	}
	if err := Extract(&archive, dest); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/": "root", "/about": "html", "/about/": "html", "/docs": "docs", "/docs/": "docs", "/deep/client/route?x=1": "root", "/app.js": "javascript"} {
		rr := httptest.NewRecorder()
		Serve(rr, httptest.NewRequest(http.MethodGet, path, nil), dest)
		if rr.Code != 200 || rr.Body.String() != want {
			t.Errorf("%s: %d %q, want %q", path, rr.Code, rr.Body.String(), want)
		}
	}
	for _, path := range []string{"/.env", "/../outside", "/nested/node_modules/package.json", "/secret.key"} {
		rr := httptest.NewRecorder()
		Serve(rr, httptest.NewRequest(http.MethodGet, path, nil), dest)
		if rr.Code != 404 {
			t.Errorf("%s returned %d", path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	Serve(rr, httptest.NewRequest(http.MethodHead, "/client/route", nil), dest)
	if rr.Code != 200 || rr.Body.Len() != 0 {
		t.Fatalf("HEAD: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	r.Header.Set("Range", "bytes=0-3")
	Serve(rr, r, dest)
	if rr.Code != 206 || rr.Body.String() != "java" {
		t.Fatalf("range: %d %s", rr.Code, rr.Body.String())
	}
}

func TestArchiveGuardsBeforeWriting(t *testing.T) {
	for _, name := range []string{"node_modules/pkg/index.js", ".env.production", "nested/.git/config", "tls.key", "nested/secrets.json"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, "index.html", "root")
			writeFile(t, root, name, "secret")
			var buf bytes.Buffer
			if err := Archive(root, &buf); err == nil {
				t.Fatal("expected rejection")
			}
			if buf.Len() != 0 {
				t.Fatal("wrote archive before validation finished")
			}
		})
	}
	root := t.TempDir()
	writeFile(t, root, "index.html", "root")
	if err := os.Symlink("index.html", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := Archive(root, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestExtractRejectsHostileArchives(t *testing.T) {
	for _, header := range []tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg},
		{Name: "/absolute", Typeflag: tar.TypeReg},
		{Name: "a\\..\\escape", Typeflag: tar.TypeReg},
		{Name: "node_modules/pkg.js", Typeflag: tar.TypeReg},
		{Name: ".env", Typeflag: tar.TypeReg},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "link", Typeflag: tar.TypeLink, Linkname: "index.html"},
		{Name: "pipe", Typeflag: tar.TypeFifo},
		{Name: "huge", Typeflag: tar.TypeReg, Size: MaxExpandedBytes + 1},
	} {
		t.Run(header.Name, func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&header); err != nil {
				t.Fatal(err)
			}
			_ = tw.Close()
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			if err := Extract(&buf, t.TempDir()); err == nil {
				t.Fatal("accepted hostile archive")
			}
		})
	}
}

func TestExtractRejectsCorruptionAndMissingIndex(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "index.html", "root")
	var buf bytes.Buffer
	if err := Archive(root, &buf); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	data[len(data)-8] ^= 0xff
	if err := Extract(bytes.NewReader(data), t.TempDir()); err == nil {
		t.Fatal("accepted corrupt gzip checksum")
	}
	var empty bytes.Buffer
	gz := gzip.NewWriter(&empty)
	tw := tar.NewWriter(gz)
	_ = tw.Close()
	_ = gz.Close()
	if err := Extract(&empty, t.TempDir()); err == nil {
		t.Fatal("accepted archive without index")
	}
}

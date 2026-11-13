package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/koltyakov/expose/internal/domain"
	"github.com/koltyakov/expose/internal/publish"
)

func TestPublishedSiteArchiveResourceLimits(t *testing.T) {
	srv, st := newIncrementalTestServer(t)
	root := t.TempDir()
	writeIncrementalTestFile(t, root, "index.html", "old")
	var initial bytes.Buffer
	if err := publish.Archive(root, &initial); err != nil {
		t.Fatal(err)
	}
	const uploadPath = "/_expose/v1/sites?domain=bounded"
	w := incrementalSiteRequest(srv, http.MethodPost, uploadPath, "owner", "", initial.Bytes())
	if w.Code != http.StatusCreated {
		t.Fatalf("initial upload: %d %s", w.Code, w.Body.String())
	}
	before, err := st.FindPublishedSite(context.Background(), "bounded.example.com")
	if err != nil {
		t.Fatal(err)
	}
	revision := publishedSiteRevision(&before)
	srv.cfg.PublishMaxBytes = 1

	for _, tc := range []struct {
		name        string
		incremental bool
		wantError   error
		write       func(*testing.T, *tar.Writer)
	}{
		{
			name:        "oversized manifest header",
			incremental: true,
			wantError:   publish.ErrManifestTooLarge,
			write: func(t *testing.T, tw *tar.Writer) {
				// No body is needed to reject an oversized declaration.
				if err := tw.WriteHeader(&tar.Header{Name: ".expose-manifest.json", Typeflag: tar.TypeReg, Size: 1 << 40}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:        "too many target files",
			incremental: true,
			wantError:   publish.ErrTooManyEntries,
			write: func(t *testing.T, tw *tar.Writer) {
				files := make([]domain.PublishedFile, publish.MaxArchiveEntries+1)
				for i := range files {
					name := fmt.Sprintf("file-%05d", i)
					if i == 0 {
						name = "index.html"
					}
					files[i] = domain.PublishedFile{Path: name, Checksum: strings.Repeat("0", 64)}
				}
				metadata, err := json.Marshal(files)
				if err != nil {
					t.Fatal(err)
				}
				if err := tw.WriteHeader(&tar.Header{Name: ".expose-manifest.json", Typeflag: tar.TypeReg, Size: int64(len(metadata))}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(metadata); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "too many empty archive files",
			wantError: publish.ErrTooManyEntries,
			write: func(t *testing.T, tw *tar.Writer) {
				for i := 0; i <= publish.MaxArchiveEntries; i++ {
					name := fmt.Sprintf("file-%05d", i)
					if i == 0 {
						name = "index.html"
					}
					if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg}); err != nil {
						t.Fatal(err)
					}
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			tc.write(t, tw)
			if err := tw.Close(); err != nil && tc.wantError != publish.ErrManifestTooLarge {
				t.Fatal(err)
			}
			if err := gz.Close(); err != nil {
				t.Fatal(err)
			}
			path := uploadPath
			if tc.incremental {
				path += "&incremental=true"
			}
			w := incrementalSiteRequest(srv, http.MethodPost, path, "owner", revision, archive.Bytes())
			if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), tc.wantError.Error()) {
				t.Fatalf("upload: %d %s", w.Code, w.Body.String())
			}
			entries, err := os.ReadDir(srv.publishDir())
			if err != nil || len(entries) != 1 || entries[0].Name() != before.StorageID() {
				t.Fatalf("rejected upload left staging files: %v, %v", entries, err)
			}
			stored, err := st.FindPublishedSite(context.Background(), before.Hostname)
			if err != nil || !reflect.DeepEqual(stored, before) {
				t.Fatalf("rejection changed publication metadata: %+v, %v", stored, err)
			}
			body, err := os.ReadFile(filepath.Join(srv.publishDir(), before.StorageID(), "index.html"))
			if err != nil || string(body) != "old" {
				t.Fatalf("rejection changed published content: %q, %v", body, err)
			}
			public := httptest.NewRecorder()
			srv.handlePublic(public, httptest.NewRequest(http.MethodGet, "https://"+before.Hostname+"/", nil))
			if public.Code != http.StatusOK || public.Body.String() != "old" {
				t.Fatalf("previous publication not routable: %d %q", public.Code, public.Body.String())
			}
		})
	}
}

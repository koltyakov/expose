package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/koltyakov/expose/internal/domain"
)

func TestPubUploadHasNoClientDeadline(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(300 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(domain.PublishedSite{ID: "site_test", Hostname: "docs.example.com"})
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 100 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := uploadPublishedSite(ctx, client, pubUploadOptions{Folder: root, Endpoint: server.URL, Full: true})
	if err != nil || !result.Uploaded {
		t.Fatalf("slow upload: %+v, %v", result, err)
	}
	if client.Timeout != 100*time.Millisecond {
		t.Fatal("upload changed the shared management client timeout")
	}
}

func TestPubUploadStillHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	writeIncrementalCLIFile(t, root, "index.html", "home")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	_, err := uploadPublishedSite(ctx, server.Client(), pubUploadOptions{Folder: root, Endpoint: server.URL, Full: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("upload ignored cancellation: %v", err)
	}
}

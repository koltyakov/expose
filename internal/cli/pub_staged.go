package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/koltyakov/expose/internal/config"
	"github.com/koltyakov/expose/internal/publish"
)

type pubGitFile struct {
	mode, object string
}

// The private source mirrors the Git index, including staging and unstaging.
// Working-tree edits never supply published contents.
type pubStagedWatch struct {
	directory string
	folder    string
	files     map[string]pubGitFile
	pending   map[string]pubGitFile
}

func newPubStagedWatch(ctx context.Context, directory string) (*pubStagedWatch, error) {
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	source := &pubStagedWatch{directory: directory}
	files, err := source.indexFiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("--staged requires Git and a folder in a Git working tree: %w", err)
	}
	if err := source.replace(ctx, files); err != nil {
		return nil, err
	}
	return source, nil
}

func (s *pubStagedWatch) indexFiles(ctx context.Context) (map[string]pubGitFile, error) {
	data, err := s.gitOutput(ctx, "ls-files", "--stage", "-z", "--", ".")
	if err != nil {
		return nil, err
	}
	files := make(map[string]pubGitFile)
	for _, record := range bytes.Split(data, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(header)
		if !ok || len(fields) != 3 {
			return nil, fmt.Errorf("invalid Git index entry")
		}
		if publish.ValidatePath(name) != nil {
			continue
		}
		if fields[2] != "0" {
			return nil, fmt.Errorf("resolve staged conflicts before publishing: %s", name)
		}
		file := pubGitFile{mode: fields[0], object: fields[1]}
		if err := validatePubGitFile(name, file); err != nil {
			return nil, err
		}
		files[name] = file
	}
	return files, nil
}

func (s *pubStagedWatch) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-c", "core.fsmonitor=false", "-C", s.directory}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0")
	return cmd
}

func (s *pubStagedWatch) gitOutput(ctx context.Context, args ...string) ([]byte, error) {
	var output, stderr bytes.Buffer
	cmd := s.command(ctx, args...)
	cmd.Stdout = &archiveLimitWriter{w: &output, remaining: publish.MaxManifestBytes, ctx: ctx}
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("reading Git staging: %w: %s", err, config.SanitizeTerminalString(strings.TrimSpace(stderr.String())))
	}
	return output.Bytes(), nil
}

func validatePubGitFile(name string, file pubGitFile) error {
	if file.mode != "100644" && file.mode != "100755" {
		return fmt.Errorf("publish only accepts regular staged files: %s", name)
	}
	id, err := hex.DecodeString(file.object)
	if err != nil || (len(id) != 20 && len(id) != 32) {
		return fmt.Errorf("invalid staged object: %s", name)
	}
	return nil
}

func (s *pubStagedWatch) sync(ctx context.Context) error {
	if err := s.observe(ctx); err != nil {
		return err
	}
	if s.pending == nil {
		return nil
	}
	if err := s.replace(ctx, s.pending); err != nil {
		return err
	}
	s.pending = nil
	return nil
}

// Observe index changes while an upload is running without mutating its source.
func (s *pubStagedWatch) observe(ctx context.Context) error {
	next, err := s.indexFiles(ctx)
	if err != nil {
		return err
	}
	if maps.Equal(next, s.files) {
		s.pending = nil
		return nil
	}
	s.pending = next
	return nil
}

// Build a fresh source from immutable blobs, never from working-tree contents.
func (s *pubStagedWatch) replace(ctx context.Context, files map[string]pubGitFile) error {
	if len(files) > publish.MaxFiles {
		return fmt.Errorf("site exceeds publish limits")
	}
	if _, exists := files["index.html"]; !exists {
		return fmt.Errorf("staged watch requires a root index.html in the Git index")
	}
	folder, err := os.MkdirTemp("", "expose-staged-*")
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(folder)
		}
	}()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	if err := s.materialize(ctx, folder, files, names); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	s.close()
	s.folder, s.files = folder, files
	keep = true
	return nil
}

func (s *pubStagedWatch) materialize(ctx context.Context, folder string, files map[string]pubGitFile, names []string) error {
	var total int64
	changed := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(folder, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		// Reuse unchanged private files instead of reading their blobs again.
		if s.folder != "" && s.files[name] == files[name] {
			old := filepath.Join(s.folder, filepath.FromSlash(name))
			info, err := os.Stat(old)
			if err == nil && info.Mode().IsRegular() && os.Link(old, path) == nil {
				total += info.Size()
				if total > publish.MaxExpandedBytes {
					return fmt.Errorf("site exceeds publish limits")
				}
				continue
			}
		}
		changed = append(changed, name)
	}
	names = changed
	if len(names) == 0 {
		return nil
	}
	var input strings.Builder
	for _, name := range names {
		input.WriteString(files[name].object + "\n")
	}
	cmd := s.command(ctx, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(input.String())
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	for _, name := range names {
		header, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading staged contents: %w", err)
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != files[name].object || fields[1] != "blob" {
			return fmt.Errorf("invalid staged blob: %s", name)
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > publish.MaxExpandedBytes-total {
			return fmt.Errorf("site exceeds publish limits")
		}
		total += size
		path := filepath.Join(folder, filepath.FromSlash(name))
		mode := os.FileMode(0600)
		if files[name].mode == "100755" {
			mode = 0700
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(file, reader, size)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if end, err := reader.ReadByte(); err != nil || end != '\n' {
			return fmt.Errorf("invalid staged blob terminator: %s", name)
		}
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		return fmt.Errorf("reading staged contents: %w: %s", err, config.SanitizeTerminalString(strings.TrimSpace(stderr.String())))
	}
	return nil
}

func (s *pubStagedWatch) close() {
	if s.folder != "" {
		_ = os.RemoveAll(s.folder)
	}
}

func (opts pubUploadOptions) watchSnapshot(ctx context.Context) (map[string]os.FileInfo, error) {
	folder := opts.Folder
	if opts.Staged != nil {
		if err := opts.Staged.sync(ctx); err != nil {
			return nil, err
		}
		folder = opts.Staged.folder
	}
	return publish.FileSnapshot(folder)
}

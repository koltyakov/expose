package cli

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/koltyakov/expose/internal/publish"
)

// Notifications are hints. The regular snapshot is still authoritative.
type pubWatchNotifier struct {
	*fsnotify.Watcher
	root, index string
}

func newPubWatchNotifier(ctx context.Context, opts pubUploadOptions) *pubWatchNotifier {
	root, err := filepath.Abs(opts.Folder)
	if err != nil {
		return nil
	}
	index := ""
	if opts.Staged != nil {
		path, err := opts.Staged.gitOutput(ctx, "rev-parse", "--path-format=absolute", "--git-path", "index")
		if err != nil {
			return nil
		}
		index = filepath.Clean(strings.TrimRight(string(path), "\r\n"))
		root = filepath.Dir(index)
	}
	w, err := fsnotify.NewBufferedWatcher(64)
	if err != nil {
		return nil
	}
	n := &pubWatchNotifier{Watcher: w, root: root, index: index}
	if index != "" {
		err = w.Add(root) // Git replaces the index by rename.
	} else {
		err = n.addTree(root)
	}
	if err != nil {
		_ = w.Close()
		return nil
	}
	return n
}

func (n *pubWatchNotifier) public(path string) bool {
	rel, err := filepath.Rel(n.root, path)
	return err == nil && (rel == "." || publish.ValidatePath(filepath.ToSlash(rel)) == nil)
}

func (n *pubWatchNotifier) addTree(dir string) error {
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || !entry.IsDir() {
			return err
		}
		if !n.public(path) {
			return fs.SkipDir
		}
		return n.Add(path)
	})
}

func (n *pubWatchNotifier) changed(event fsnotify.Event) (bool, error) {
	if event.Name == n.root && (event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename)) {
		return true, os.ErrNotExist // use polling until the folder reappears
	}
	if n.index != "" {
		return event.Name == n.index, nil
	}
	if !n.public(event.Name) {
		return false, nil
	}
	if event.Has(fsnotify.Create) {
		if info, err := os.Lstat(event.Name); err == nil && info.IsDir() {
			return true, n.addTree(event.Name)
		}
	}
	return true, nil
}

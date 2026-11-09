package sshbackend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OwnerLookup resolves an existing local account to its real numeric ownership.
type OwnerLookup func(string) (uid, gid int, err error)

// Seed installs a fully validated scene below root. It refuses symlink parents
// and special files, and replaces each regular file atomically. Callers must
// complete initialization before starting any untrusted session.
func Seed(root string, m Manifest, lookup OwnerLookup) error {
	if err := m.Validate(); err != nil {
		return err
	}
	owners := map[string][2]int{}
	for _, name := range sceneOwners(m) {
		uid, gid, err := lookup(name)
		if err != nil || uid < 0 || gid < 0 {
			return fmt.Errorf("resolve scene owner %q: %w", name, errors.Join(err, errors.New("invalid local account")))
		}
		owners[name] = [2]int{uid, gid}
	}
	for _, dir := range m.Directories {
		if err := safeParents(root, dir.Path, true); err != nil {
			return err
		}
	}
	for _, file := range m.Files {
		if err := safeParents(root, file.Path, false); err != nil {
			return err
		}
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	dirs := append([]Directory(nil), m.Directories...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i].Path) < len(dirs[j].Path) })
	for _, dir := range dirs {
		name := strings.TrimPrefix(dir.Path, "/")
		if err := r.MkdirAll(name, 0o755); err != nil {
			return fmt.Errorf("create scene directory %q: %w", dir.Path, err)
		}
		f, err := r.Open(name)
		if err != nil {
			return err
		}
		ids := owners[dir.Owner]
		err = errors.Join(f.Chown(ids[0], ids[1]), f.Chmod(os.FileMode(dir.Mode)))
		err = errors.Join(err, f.Close())
		if err != nil {
			return fmt.Errorf("set scene directory %q ownership/mode: %w", dir.Path, err)
		}
	}
	for _, file := range m.Files {
		name := strings.TrimPrefix(file.Path, "/")
		if err := r.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		staged := name + ".seed-" + hex.EncodeToString(nonce[:])
		f, err := r.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("stage scene file %q: %w", file.Path, err)
		}
		_, writeErr := f.WriteString(file.Content)
		ids := owners[file.Owner]
		writeErr = errors.Join(writeErr, f.Chown(ids[0], ids[1]), f.Chmod(os.FileMode(file.Mode)), f.Sync(), f.Close())
		if writeErr == nil {
			writeErr = r.Rename(staged, name)
		}
		if writeErr != nil {
			_ = r.Remove(staged)
			return fmt.Errorf("install scene file %q: %w", file.Path, writeErr)
		}
	}
	return nil
}

func sceneOwners(m Manifest) []string {
	set := map[string]bool{}
	for _, d := range m.Directories {
		set[d.Owner] = true
	}
	for _, f := range m.Files {
		set[f.Owner] = true
	}
	var names []string
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func safeParents(root, name string, directory bool) error {
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	current := root
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect scene path %q: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || ((i < len(parts)-1 || directory) && !info.IsDir()) || (i == len(parts)-1 && !directory && !info.Mode().IsRegular()) {
			return fmt.Errorf("scene path %q contains a symlink or incompatible file", name)
		}
	}
	return nil
}

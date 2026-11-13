package instance

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ensureContainerDir makes path a real directory with mode, where path lies
// inside a directory a honeypot container writes to (cowrie's log/tty in its
// logs mount). The container can leave anything at that path, and a symlink
// there would make MkdirAll and Chmod change a directory outside the instance
// (the host user's, or with QPot run as root, any). Whatever is not a real
// directory is removed (a symlink itself, never what it points at) and the
// directory made again; its mode is set through a handle that does not follow
// a symlink swapped in meanwhile.
func ensureContainerDir(path string, mode fs.FileMode) error {
	fi, err := os.Lstat(path)
	switch {
	case err == nil && fi.IsDir():
	case err == nil:
		slog.Warn("Replacing what a honeypot left where its directory belongs", "path", path, "type", fi.Mode().Type().String())
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		if err := os.Mkdir(path, 0o750); err != nil {
			return err
		}
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	default:
		return err
	}
	return chmodDirNoFollow(path, mode)
}

// ensureContainerDirIn makes rel, and each folder above it, a real directory
// with mode inside root, a volume a honeypot container writes to (dionaea's
// data/ for roots/ftp). Every step goes through os.Root, so a symlink the
// container left on the way can never lead outside the volume. Whatever is
// not a directory is removed (a symlink itself, never what it points at) and
// the directory made again. A folder the container made itself may not be
// ours to chmod; it stays as the container left it.
func ensureContainerDirIn(root, rel string, mode fs.FileMode) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for i := range parts {
		p := filepath.Join(parts[:i+1]...)
		made := false
		fi, err := r.Lstat(p)
		switch {
		case err == nil && fi.IsDir():
		case err == nil:
			slog.Warn("Replacing what a honeypot left where its directory belongs", "path", filepath.Join(root, p), "type", fi.Mode().Type().String())
			if err := r.Remove(p); err != nil {
				return fmt.Errorf("remove %s: %w", filepath.Join(root, p), err)
			}
			if err := r.Mkdir(p, 0o750); err != nil {
				return err
			}
			made = true
		case errors.Is(err, fs.ErrNotExist):
			if err := r.Mkdir(p, 0o750); err != nil {
				return err
			}
			made = true
		default:
			return err
		}
		if !made && fi.Mode().Perm() == mode.Perm() {
			continue
		}
		if err := r.Chmod(p, mode); err != nil {
			if made {
				return err
			}
			slog.Warn("Could not set the mode of a honeypot folder", "path", filepath.Join(root, p), "error", err)
		}
	}
	return nil
}

// ensureHoneypotLogs creates the logs a honeypot appends to (deployProfile's
// Logs) in its logs volume dir, empty, as QPot's own files that the
// container may write to, so that the disk guard can keep room beyond their
// end (diskguard.KeepLogRoom). A log that is there already is left as it is,
// whoever made it. The folder is the container's: every name is created
// inside it through os.Root, never through a link, and never over a file.
func ensureHoneypotLogs(dir string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range names {
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o666)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create the log %s: %w", name, err)
		}
		// The umask took write access from the container's user; it is a
		// different user from QPot's.
		err = f.Chmod(0o666)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return fmt.Errorf("create the log %s: %w", name, err)
		}
	}
	return nil
}

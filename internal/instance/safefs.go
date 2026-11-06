package instance

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
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

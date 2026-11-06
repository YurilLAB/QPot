//go:build unix

package instance

import (
	"io/fs"
	"os"
	"syscall"
)

// chmodDirNoFollow sets the mode of the directory at path, failing if path is
// (or has become) a symlink rather than following it.
func chmodDirNoFollow(path string, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(mode)
}

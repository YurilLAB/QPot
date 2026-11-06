//go:build !unix

package instance

import (
	"fmt"
	"io/fs"
	"os"
)

// chmodDirNoFollow sets the mode of the directory at path, refusing a symlink.
// Windows has no O_NOFOLLOW; Chmod there only sets the read-only attribute.
func chmodDirNoFollow(path string, mode fs.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return os.Chmod(path, mode)
}

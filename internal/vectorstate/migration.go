package vectorstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"

	"github.com/qpot/qpot/internal/hostsetup"
)

const legacyDir = "collector-state"

// MigrateLegacy adopts the earlier collector-state directory without changing
// cursor bytes or file identity. Call while collector startup and the instance
// lifecycle are serialized. Conflicts require operator review; states are never
// merged, discarded, copied between filesystems or silently reseeded.
func MigrateLegacy(dataPath string) error {
	return migrateLegacy(dataPath, nil, nil)
}

func migrateLegacy(dataPath string, rename func(*os.Root, string, string) error, syncParent func(*os.Root) error) error {
	info, err := os.Lstat(dataPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return hostsetup.E("QP-INST-012").Wrap(err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return hostsetup.E("QP-INST-012").WithWhy("The instance path is not an ordinary directory.")
	}
	root, err := os.OpenRoot(dataPath)
	if err != nil {
		return hostsetup.E("QP-INST-012").Wrap(err)
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return hostsetup.E("QP-INST-012").WithWhy("The instance directory changed while opening collector state.").Wrap(err)
	}
	exists := func(name string) (bool, error) {
		entry, err := root.Lstat(name)
		if os.IsNotExist(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("collector state %s must be an ordinary directory", name)
		}
		return true, nil
	}
	oldExists, err := exists(legacyDir)
	if err != nil {
		return hostsetup.E("QP-INST-012").Wrap(err)
	}
	newExists, err := exists(Dir)
	if err != nil {
		return hostsetup.E("QP-INST-012").Wrap(err)
	}
	if oldExists && newExists {
		return hostsetup.E("QP-INST-012").WithWhy("Both legacy and canonical collector state exist; neither was changed.")
	}
	if !oldExists && !newExists {
		return nil
	}
	state := Dir
	if oldExists {
		state = legacyDir
	}
	count := 0
	if err := validateMigrationTree(root, state, 0, &count); err != nil {
		return hostsetup.E("QP-INST-012").Wrap(err)
	}
	if oldExists {
		if rename == nil {
			rename = func(root *os.Root, from, to string) error { return root.Rename(from, to) }
		}
		if err := rename(root, legacyDir, Dir); err != nil {
			return hostsetup.E("QP-INST-012").WithWhy("Collector state could not be renamed safely; legacy state was retained.").Wrap(err)
		}
	}
	if syncParent == nil {
		syncParent = syncMigrationParent
	}
	if err := syncParent(root); err != nil {
		return hostsetup.E("QP-INST-012").WithWhy("Collector state is at its canonical location, but directory durability is uncertain. Keep that state and retry; do not restore or reseed.").Wrap(err)
	}
	return nil
}

func validateMigrationTree(root *os.Root, dir string, depth int, count *int) error {
	if depth > maxDepth {
		return errors.New("collector state exceeds the migration depth limit")
	}
	folder, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer folder.Close()
	for {
		entries, readErr := folder.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, entry := range entries {
			*count++
			if *count > maxFiles {
				return errors.New("collector state exceeds the migration entry limit")
			}
			rel := path.Join(dir, entry.Name())
			info, err := root.Lstat(rel)
			if err != nil {
				return err
			}
			switch {
			case info.IsDir():
				if err := validateMigrationTree(root, rel, depth+1, count); err != nil {
					return err
				}
			case info.Mode().IsRegular():
			default:
				return fmt.Errorf("collector state %s is not an ordinary directory or file", rel)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
	}
}

func syncMigrationParent(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil // Windows does not support syncing directory handles this way.
	}
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

//go:build unix

package instance

import (
	"io/fs"
	"os"
	"syscall"
)

func sshStoreOwned(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

func sshStoreSafeAncestor(info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && (st.Uid == 0 || st.Uid == uint32(os.Geteuid())) &&
		(info.Mode().Perm()&0o022 == 0 || info.IsDir() && info.Mode()&os.ModeSticky != 0)
}

//go:build unix

package cleanup

import (
	"io/fs"
	"os"
	"syscall"
)

// noFollow refuses to open a symlink in the last path component.
const noFollow = syscall.O_NOFOLLOW
const evidenceNonBlock = syscall.O_NONBLOCK

// onDisk is the space a file takes: its allocated blocks, so a sparse file
// counts what it holds and not its apparent size.
func onDisk(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks >= 0 {
		return int64(st.Blocks) * 512
	}
	return fi.Size()
}

func singleEvidenceLink(_ *os.Root, _ string, fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 1
}

//go:build !windows

package hostsetup

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// interruptProcess asks p to stop the way Ctrl-C does, so a package manager
// can finish its current write and leave its database consistent.
func interruptProcess(p *os.Process) error { return p.Signal(os.Interrupt) }

// freeBytes returns the space available to unprivileged users at path.
func freeBytes(path string) int64 {
	n, _ := dataFreeBytes(path)
	return n
}

// dataFreeBytes returns the space available to unprivileged users at path
// and whether it could be read: a full disk is 0 and true.
func dataFreeBytes(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	n := int64(st.Bavail) * int64(st.Bsize) // #nosec G115 -- sizes fit int64
	if n < 0 {
		return 0, false
	}
	return n, true
}

// oNoFollow makes an open fail when the last element of the path is a link.
const oNoFollow = syscall.O_NOFOLLOW

// notPrivate says why a folder is not private to this user ("" when it is):
// it must belong to the effective user and give group and others no access.
func notPrivate(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "its owner cannot be read"
	}
	if int64(st.Uid) != int64(os.Geteuid()) {
		return fmt.Sprintf("it belongs to user %d, not to you", st.Uid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Sprintf("other users can use it (mode %04o)", perm)
	}
	return ""
}

// unsafeParent says why another user could move or replace dir ("" when no
// one but this user and root can): every folder above it must belong to root
// or to this user, and one others may write to must be sticky (like /tmp).
func unsafeParent(dir string) string {
	p, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		return "the folder it is in cannot be read"
	}
	me := int64(os.Geteuid())
	for {
		fi, err := os.Stat(p)
		if err != nil {
			return "the folder " + p + " cannot be read"
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return "the owner of " + p + " cannot be read"
		}
		if uid := int64(st.Uid); uid != 0 && uid != me {
			return fmt.Sprintf("%s belongs to user %d", p, uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Sprintf("other users can rename things in %s (mode %04o, not sticky)", p, fi.Mode().Perm())
		}
		up := filepath.Dir(p)
		if up == p {
			return ""
		}
		p = up
	}
}

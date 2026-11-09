//go:build !unix

package instance

import "io/fs"

// Windows user-profile ACLs provide ownership isolation; POSIX UID/mode tests
// are unavailable. Structural no-symlink and matching ownership records remain.
func sshStoreOwned(info fs.FileInfo) bool        { return true }
func sshStoreSafeAncestor(info fs.FileInfo) bool { return true }

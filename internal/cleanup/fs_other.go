//go:build !unix

package cleanup

import "io/fs"

// noFollow: os.Root already refuses a symlink that leaves it; the opened
// file is compared with the listed one before it is emptied.
const noFollow = 0

// onDisk is the space a file takes.
func onDisk(fi fs.FileInfo) int64 { return fi.Size() }

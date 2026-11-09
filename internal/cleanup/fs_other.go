//go:build !unix && !windows

package cleanup

import (
	"io/fs"
	"os"
)

// noFollow: os.Root already refuses a symlink that leaves it; the opened
// file is compared with the listed one before it is emptied.
const noFollow = 0
const evidenceNonBlock = 0

// onDisk is the space a file takes.
func onDisk(fi fs.FileInfo) int64 { return fi.Size() }

// Without a verified native link count, retain the evidence conservatively.
func singleEvidenceLink(*os.Root, string, fs.FileInfo) bool { return false }

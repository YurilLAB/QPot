//go:build windows

package cleanup

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// noFollow: os.Root already refuses a symlink that leaves it; the opened
// file is compared with the listed one before it is emptied.
const noFollow = 0
const evidenceNonBlock = 0

// onDisk is the space a file takes.
func onDisk(fi fs.FileInfo) int64 { return fi.Size() }

// singleEvidenceLink asks Windows for the file's link count, so a hard link
// a guest made into its recording does not pass as a file of its own. The
// open file must still be the one listed.
func singleEvidenceLink(root *os.Root, rel string, fi fs.FileInfo) bool {
	f, err := root.Open(rel)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(fi, opened) {
		return false
	}
	var data windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &data); err != nil {
		return false
	}
	return data.NumberOfLinks == 1
}

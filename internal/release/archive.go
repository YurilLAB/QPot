package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"time"
)

// File is one file in a release archive.
type File struct {
	Name string // path inside the archive, e.g. "qpot"
	Mode int64  // permission bits, e.g. 0o755
	Data []byte
}

// TarGz writes files as a gzip-compressed tar archive. The output depends
// only on the files and mtime (fixed owner, order, header fields and gzip
// header), so the same build gives byte-identical archives.
func TarGz(w io.Writer, files []File, mtime time.Time) error {
	gz, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
	if err != nil {
		return err
	}
	gz.ModTime = mtime.UTC()
	gz.OS = 3 // Unix, whatever system builds it
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if !archiveNameOK(f.Name) {
			return fmt.Errorf("release: bad archive member name %q", f.Name)
		}
		hdr := &tar.Header{
			Typeflag: tar.TypeReg, Name: f.Name, Mode: f.Mode & 0o777, Size: int64(len(f.Data)),
			ModTime: mtime.UTC(), Uname: "root", Gname: "root", Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Zip writes files as a zip archive, as deterministically as TarGz.
func Zip(w io.Writer, files []File, mtime time.Time) error {
	zw := zip.NewWriter(w)
	for _, f := range files {
		if !archiveNameOK(f.Name) {
			return fmt.Errorf("release: bad archive member name %q", f.Name)
		}
		hdr := &zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: mtime.UTC()}
		hdr.SetMode(0o644)
		if f.Mode&0o111 != 0 {
			hdr.SetMode(0o755)
		}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, bytes.NewReader(f.Data)); err != nil {
			return err
		}
	}
	return zw.Close()
}

// archiveNameOK allows only plain names at the top of the archive: the
// installers extract one known member, and nothing else in an archive may
// point anywhere else.
func archiveNameOK(name string) bool { return ValidName(name) }

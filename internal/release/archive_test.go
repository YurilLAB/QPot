package release

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"time"
)

var testFiles = []File{
	{Name: "qpot", Mode: 0o755, Data: []byte("program")},
	{Name: "LICENSE", Mode: 0o644, Data: []byte("license text")},
}

func TestTarGzIsReproducible(t *testing.T) {
	mtime := time.Date(2026, 11, 1, 12, 0, 0, 0, time.FixedZone("AEST", 10*3600))
	var a, b, c bytes.Buffer
	for _, buf := range []*bytes.Buffer{&a, &b} {
		if err := TarGz(buf, testFiles, mtime); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two builds of the same files differ")
	}
	if err := TarGz(&c, testFiles, mtime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Bytes(), c.Bytes()) {
		t.Fatal("the time stamp does not reach the archive")
	}
	gz, err := gzip.NewReader(bytes.NewReader(a.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if gz.OS != 3 || !gz.ModTime.Equal(mtime) {
		t.Errorf("gzip header OS=%d mtime=%v", gz.OS, gz.ModTime)
	}
	tr := tar.NewReader(gz)
	for i := 0; ; i++ {
		h, err := tr.Next()
		if err == io.EOF {
			if i != len(testFiles) {
				t.Errorf("%d members, want %d", i, len(testFiles))
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		want := testFiles[i]
		data, _ := io.ReadAll(tr)
		if h.Name != want.Name || h.Mode != want.Mode || !bytes.Equal(data, want.Data) ||
			h.Uname != "root" || h.Uid != 0 || !h.ModTime.Equal(mtime) || h.Typeflag != tar.TypeReg {
			t.Errorf("member %d: %+v", i, h)
		}
	}
}

func TestZipIsReproducible(t *testing.T) {
	mtime := time.Date(2026, 11, 1, 2, 0, 0, 0, time.UTC)
	var a, b bytes.Buffer
	for _, buf := range []*bytes.Buffer{&a, &b} {
		if err := Zip(buf, testFiles, mtime); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two builds of the same files differ")
	}
	zr, err := zip.NewReader(bytes.NewReader(a.Bytes()), int64(a.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(testFiles) {
		t.Fatalf("%d members", len(zr.File))
	}
	for i, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		_ = rc.Close()
		want := testFiles[i]
		if f.Name != want.Name || int64(f.Mode().Perm()) != want.Mode || !bytes.Equal(data, want.Data) {
			t.Errorf("member %d: %s %v", i, f.Name, f.Mode())
		}
	}
}

func TestArchivesRefuseBadNames(t *testing.T) {
	for _, n := range []string{"", "../qpot", "bin/qpot", "/qpot", `..\qpot`, "a b"} {
		files := []File{{Name: n, Mode: 0o755, Data: []byte("x")}}
		if err := TarGz(io.Discard, files, time.Unix(0, 0)); err == nil {
			t.Errorf("TarGz accepted %q", n)
		}
		if err := Zip(io.Discard, files, time.Unix(0, 0)); err == nil {
			t.Errorf("Zip accepted %q", n)
		}
	}
}

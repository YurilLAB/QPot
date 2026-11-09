//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestHostReadableSessionLogPreservesEvidence(t *testing.T) {
	for _, mode := range []os.FileMode{0, 0o600, 0o640, 0o644, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "sessions.json")
			var before os.FileInfo
			if mode != 0 {
				if err := os.WriteFile(name, []byte("before\n"), mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(name, mode); err != nil {
					t.Fatal(err)
				}
				var err error
				before, err = os.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
			}
			file, err := openSessionLog(name, true)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.WriteString("after\n")
			if err := errors.Join(writeErr, file.Close()); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(name)
			wantMode := os.FileMode(0o644)
			if mode&0o004 != 0 {
				wantMode = mode // keep Desktop's existing readable synthetic mode
			}
			if err != nil || after.Mode().Perm() != wantMode || before != nil && !os.SameFile(before, after) {
				t.Fatalf("host readability lost mode/identity: %v %v", after, err)
			}
			want := "after\n"
			if before != nil {
				want = "before\n" + want
			}
			if data, err := os.ReadFile(name); err != nil || string(data) != want {
				t.Fatalf("host-readable logger truncated evidence: %q %v", data, err)
			}
		})
	}
}

func TestHostReadableSessionLogRefusesUnsafeTargets(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "parent symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir, outside := t.TempDir(), t.TempDir()
			name := filepath.Join(dir, "sessions.json")
			target := filepath.Join(outside, "kept")
			if err := os.WriteFile(target, []byte("preserved\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, name)
			case "hardlink":
				err = os.Link(target, name)
			case "fifo":
				err = syscall.Mkfifo(name, 0o600)
			case "directory":
				err = os.Mkdir(name, 0o700)
			default:
				err = os.Symlink(outside, filepath.Join(dir, "linked"))
				name = filepath.Join(dir, "linked", "sessions.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			file, err := openSessionLog(name, true)
			if file != nil {
				file.Close()
			}
			if err == nil {
				t.Fatal("permission widening accepted an unsafe target")
			}
			after, err := os.Stat(target)
			if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != before.Mode().Perm() {
				t.Fatalf("rejection changed unrelated target mode/identity: %v", err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "preserved\n" {
				t.Fatalf("rejection changed unrelated bytes: %q %v", data, err)
			}
			if kind == "parent symlink" {
				if _, err := os.Lstat(name); !os.IsNotExist(err) {
					t.Fatalf("rejection created a log through its parent symlink: %v", err)
				}
			}
		})
	}
}

func TestHostReadableSessionLogWithRestrictiveUmask(t *testing.T) {
	if os.Getenv("QPOT_TEST_LOG_UMASK_CHILD") == "1" {
		syscall.Umask(0o077)
		file, err := openSessionLog(os.Getenv("QPOT_TEST_LOG_UMASK_PATH"), true)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	name := filepath.Join(t.TempDir(), "new", "sessions.json")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHostReadableSessionLogWithRestrictiveUmask$")
	cmd.Env = append(os.Environ(), "QPOT_TEST_LOG_UMASK_CHILD=1", "QPOT_TEST_LOG_UMASK_PATH="+name)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated umask077 logger: %v %s", err, output)
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("host-readable mode was removed by umask077: %v %v", info, err)
	}
}

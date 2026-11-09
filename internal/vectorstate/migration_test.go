package vectorstate

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/qpot/qpot/internal/hostsetup"
)

func requireMigrationFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil || hostsetup.AsError(err).Code != "QP-INST-012" {
		t.Fatalf("migration did not fail with its stable code: %v", err)
	}
}

func migrationIdentitySnapshot(t *testing.T, name string) os.FileInfo {
	t.Helper()
	// File.Stat eagerly captures Windows volume/file IDs. Path-based Stat can
	// defer that lookup until SameFile, when a successful rename removed name.
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	info, statErr := file.Stat()
	if err := errors.Join(statErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestMigrateLegacyPreservesCursorsAndInodes(t *testing.T) {
	data := t.TempDir()
	source := filepath.Join(data, legacyDir)
	name := filepath.Join(source, "cowrie_logs", "checkpoints.json")
	content := `{"version":"1","checkpoints":[{"fingerprint":{"first_lines_checksum":123},"position":42}]}`
	writeFile(t, name, content)
	before := migrationIdentitySnapshot(t, name)
	oldDirectory := migrationIdentitySnapshot(t, source)
	if err := MigrateLegacy(data); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(data, Dir, "cowrie_logs", "checkpoints.json")
	actual, err := os.ReadFile(target)
	if err != nil || string(actual) != content {
		t.Fatalf("checkpoint bytes changed: %q %v", actual, err)
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("checkpoint identity changed: %v", err)
	}
	newDirectory, err := os.Stat(filepath.Join(data, Dir))
	if err != nil || !os.SameFile(oldDirectory, newDirectory) {
		t.Fatalf("state directory was copied instead of renamed: %v", err)
	}
	if got := Load(data, "cowrie_logs"); len(got) != 1 || got[123] != 42 {
		t.Fatalf("delivered cursor was not adopted: %v", got)
	}
	if _, err := os.Lstat(source); !os.IsNotExist(err) {
		t.Fatalf("legacy directory remains: %v", err)
	}
	if err := MigrateLegacy(data); err != nil {
		t.Fatalf("canonical state is not idempotent: %v", err)
	}
}

func TestMigrateLegacyNoStateDoesNotCreateDirectories(t *testing.T) {
	data := filepath.Join(t.TempDir(), "not-created")
	if err := MigrateLegacy(data); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(data); !os.IsNotExist(err) {
		t.Fatalf("migration invented an empty state root: %v", err)
	}
}

func TestMigrateLegacyRefusesConflictingStates(t *testing.T) {
	for _, populated := range []bool{false, true} {
		data := t.TempDir()
		for _, dir := range []string{legacyDir, Dir} {
			if err := os.Mkdir(filepath.Join(data, dir), 0o750); err != nil {
				t.Fatal(err)
			}
			if populated {
				writeFile(t, filepath.Join(data, dir, "checkpoint"), dir)
			}
		}
		requireMigrationFailure(t, MigrateLegacy(data))
		for _, dir := range []string{legacyDir, Dir} {
			if _, err := os.Stat(filepath.Join(data, dir)); err != nil {
				t.Fatal("migration removed a conflicting state")
			}
			if populated {
				got, err := os.ReadFile(filepath.Join(data, dir, "checkpoint"))
				if err != nil || string(got) != dir {
					t.Fatal("migration merged or replaced conflicting cursors")
				}
			}
		}
	}
}

func TestMigrateLegacyRefusesFilesAndSymlinks(t *testing.T) {
	for _, dir := range []string{legacyDir, Dir} {
		t.Run(dir+" file", func(t *testing.T) {
			data := t.TempDir()
			writeFile(t, filepath.Join(data, dir), "preserved")
			requireMigrationFailure(t, MigrateLegacy(data))
			got, err := os.ReadFile(filepath.Join(data, dir))
			if err != nil || string(got) != "preserved" {
				t.Fatal("migration changed a non-directory state")
			}
		})
		t.Run(dir+" symlink", func(t *testing.T) {
			data, outside := t.TempDir(), t.TempDir()
			writeFile(t, filepath.Join(outside, "cursor"), "outside")
			if err := os.Symlink(outside, filepath.Join(data, dir)); err != nil {
				t.Skip(err)
			}
			requireMigrationFailure(t, MigrateLegacy(data))
			got, err := os.ReadFile(filepath.Join(outside, "cursor"))
			if err != nil || string(got) != "outside" {
				t.Fatal("migration followed a state symlink")
			}
		})
	}
	data := t.TempDir()
	writeFile(t, filepath.Join(data, "ordinary-file"), "preserved")
	requireMigrationFailure(t, MigrateLegacy(filepath.Join(data, "ordinary-file")))
}

func TestMigrateLegacyRefusesNonordinaryContents(t *testing.T) {
	t.Run("nested symlink", func(t *testing.T) {
		data := t.TempDir()
		writeFile(t, filepath.Join(data, legacyDir, "kept"), "cursor")
		if err := os.Symlink(t.TempDir(), filepath.Join(data, legacyDir, "link")); err != nil {
			t.Skip(err)
		}
		requireMigrationFailure(t, MigrateLegacy(data))
		if _, err := os.Stat(filepath.Join(data, legacyDir, "kept")); err != nil {
			t.Fatal("state moved before its contents were validated")
		}
	})
	t.Run("socket", func(t *testing.T) {
		data := t.TempDir()
		if err := os.Mkdir(filepath.Join(data, legacyDir), 0o750); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("unix", filepath.Join(data, legacyDir, "s"))
		if err != nil {
			t.Skip(err)
		}
		defer listener.Close()
		requireMigrationFailure(t, MigrateLegacy(data))
	})
}

func TestMigrateLegacyBoundsDirectoryTraversal(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, legacyDir)
	for range maxDepth + 2 {
		dir = filepath.Join(dir, "d")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	requireMigrationFailure(t, MigrateLegacy(data))
	if _, err := os.Stat(filepath.Join(data, Dir)); !os.IsNotExist(err) {
		t.Fatal("over-depth state was partially migrated")
	}
}

func TestMigrateLegacyRenameFailureRetainsOriginal(t *testing.T) {
	data := t.TempDir()
	name := filepath.Join(data, legacyDir, "cursor")
	writeFile(t, name, "delivered")
	injected := errors.New("injected cross-filesystem rename refusal")
	err := migrateLegacy(data, func(*os.Root, string, string) error { return injected }, nil)
	requireMigrationFailure(t, err)
	if !errors.Is(err, injected) {
		t.Fatal("rename failure lost its cause")
	}
	got, err := os.ReadFile(name)
	if err != nil || string(got) != "delivered" {
		t.Fatal("failed rename changed original cursors")
	}
	if _, err := os.Stat(filepath.Join(data, Dir)); !os.IsNotExist(err) {
		t.Fatal("rename failure created a second empty state")
	}
}

func TestMigrateLegacySyncFailureDoesNotClaimRollback(t *testing.T) {
	data := t.TempDir()
	before := []byte("delivered cursor")
	writeFile(t, filepath.Join(data, legacyDir, "cursor"), string(before))
	err := migrateLegacy(data, nil, func(*os.Root) error { return errors.New("injected directory sync failure") })
	requireMigrationFailure(t, err)
	got, err := os.ReadFile(filepath.Join(data, Dir, "cursor"))
	if err != nil || !bytes.Equal(got, before) {
		t.Fatal("committed migration was rolled back or discarded")
	}
	if _, err := os.Stat(filepath.Join(data, legacyDir)); !os.IsNotExist(err) {
		t.Fatal("sync failure revived legacy state")
	}
	if err := MigrateLegacy(data); err != nil {
		t.Fatalf("canonical retry failed: %v", err)
	}
}

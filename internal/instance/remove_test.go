package instance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRemoveDeletesOnlyTheInstanceDirectory: `qpot instance remove <name>`
// deleted whatever data_path the instance's config.yaml named - a hand edit,
// or a ~/.qpot restored from another home, and it took a directory that was
// never the instance's with it - and left the instance's own directory
// behind. It now removes the instance's directory, and leaves a data_path
// outside it in place.
func TestRemoveDeletesOnlyTheInstanceDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	precious := filepath.Join(home, "precious")
	if err := os.MkdirAll(precious, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(precious, "thesis.txt"), []byte("years of work"), 0o600); err != nil {
		t.Fatal(err)
	}
	inst := filepath.Join(home, ".qpot", "instances", "victim")
	if err := os.MkdirAll(inst, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := "instance_name: victim\ndata_path: " + filepath.ToSlash(precious) + "\n"
	if err := os.WriteFile(filepath.Join(inst, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Remove(context.Background(), "victim"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(precious, "thesis.txt")); err != nil {
		t.Errorf("Remove(victim) deleted %s, outside the instance: %v", precious, err)
	}
	if _, err := os.Stat(inst); !os.IsNotExist(err) {
		t.Errorf("the instance directory %s is still there (%v)", inst, err)
	}
}

// TestRemoveDeletesTheInstanceData: the usual instance, its data in its own
// directory, is removed whole.
func TestRemoveDeletesTheInstanceData(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inst := filepath.Join(home, ".qpot", "instances", "plain")
	if err := os.MkdirAll(filepath.Join(inst, "honeypots", "cowrie"), 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := "instance_name: plain\ndata_path: " + filepath.ToSlash(inst) + string(filepath.Separator) + "\n"
	if err := os.WriteFile(filepath.Join(inst, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(context.Background(), "plain"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(inst); !os.IsNotExist(err) {
		t.Fatalf("the instance directory %s is still there (%v)", inst, err)
	}
}

// TestRemoveUsesTheHelperForContainerOwnedFiles: what the containers wrote
// belongs to their users, and the user who runs qpot cannot delete it. Found
// in the lab: `qpot instance remove` stopped with "permission denied" on the
// collector's log backup. The helper is asked, once, for the instance's own
// directory, and only when plain deletion was refused.
func TestRemoveUsesTheHelperForContainerOwnedFiles(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs a user who can be refused a deletion")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	inst := filepath.Join(home, ".qpot", "instances", "owned")
	locked := filepath.Join(inst, "backup", "logs")
	if err := os.MkdirAll(locked, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "cowrie.log"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := "instance_name: owned\ndata_path: " + inst + "/\n"
	if err := os.WriteFile(filepath.Join(inst, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// A folder this user may not change: its file cannot be unlinked.
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	real := removeHelper
	t.Cleanup(func() { removeHelper = real })
	var asked []string
	removeHelper = func(_ context.Context, dir string, keep []string) error {
		asked = append(asked, dir+" keep "+strings.Join(keep, ","))
		return errors.New("no docker here")
	}
	err := Remove(context.Background(), "owned")
	if err == nil || !strings.Contains(err.Error(), "permission denied") || !strings.Contains(err.Error(), "as root") {
		t.Fatalf("Remove with a failing helper: %v", err)
	}
	if len(asked) != 1 {
		t.Fatalf("the helper was asked %d times, want 1", len(asked))
	}

	// A helper that does what root can.
	removeHelper = func(_ context.Context, dir string, keep []string) error {
		asked = append(asked, dir+" keep "+strings.Join(keep, ","))
		if err := os.Chmod(locked, 0o700); err != nil {
			return err
		}
		return removeAllBut(dir, keep...)
	}
	// The first attempt removed config.yaml; Remove needs the instance's
	// settings, as it would find them on a real instance.
	if err := os.WriteFile(filepath.Join(inst, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(context.Background(), "owned"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(inst); !os.IsNotExist(err) {
		t.Fatalf("the instance directory is still there (%v)", err)
	}
	want := inst + " keep " + sshCellsLockName + "," + sshFoldersLockName
	if len(asked) != 2 || asked[1] != want {
		t.Fatalf("the helper was asked for %q, want %q", asked, want)
	}
	// The script deletes nothing it was told to keep and nothing outside.
	if strings.Contains(removeHelperScript, "/i/..") || !strings.Contains(removeHelperScript, "-mindepth 1 -maxdepth 1") {
		t.Error("the helper script is not limited to the entries of the mounted folder")
	}
}

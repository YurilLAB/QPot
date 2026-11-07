package instance

import (
	"context"
	"os"
	"path/filepath"
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

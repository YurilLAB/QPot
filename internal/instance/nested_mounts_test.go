package instance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

// With HiFi the collector reads the cells' records from a private store,
// mounted cell by cell inside /data/honeypots, which is itself a read-only
// mount. Found by starting a HiFi instance with `qpot up` on real Docker: the
// runtime could not create the inner mount points ("read-only file system")
// and the collector never started. Each inner mount must have its mount point
// in the outer mount's host folder.
func TestNestedCollectorMountPoints(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cfg := config.Default("nested-mounts")
	cfg.DataPath = filepath.Join(t.TempDir(), "instance")
	enableOnly(cfg, sshProxyHoneypot)
	mounts, err := collectorMounts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	byContainer := map[string]collectorMount{}
	for _, m := range mounts {
		byContainer[m.Container] = m
	}
	if _, ok := byContainer["/data/honeypots"]; !ok {
		t.Fatal("the collector no longer mounts /data/honeypots: this test needs rewriting")
	}
	nested := nestedMountPoints(mounts)
	got := map[string]bool{}
	for _, np := range nested {
		if filepath.ToSlash(np.OuterHost) != filepath.ToSlash(cfg.DataPath)+"/honeypots" {
			t.Errorf("mount point %s is placed in %s, not in the instance's honeypots folder", np.Rel, np.OuterHost)
		}
		got[np.Rel] = true
	}
	want := []string{"ssh-proxy/logs/broker"}
	for _, service := range SSHCellLogServices() {
		want = append(want, "ssh-proxy/logs/cells/"+service)
	}
	for _, rel := range want {
		if !got[rel] {
			t.Errorf("no mount point planned for %s", rel)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d mount points planned, want %d: %v", len(got), len(want), got)
	}
	// Every mount inside another one is covered, whatever is added later.
	for _, inner := range mounts {
		for _, outer := range mounts {
			if strings.HasPrefix(inner.Container, outer.Container+"/") && !got[strings.TrimPrefix(inner.Container, "/data/honeypots/")] {
				t.Errorf("mount %s lies inside %s and has no mount point planned", inner.Container, outer.Container)
			}
		}
	}

	// The deepest enclosing mount is the one that must hold the folder.
	deep := nestedMountPoints([]collectorMount{
		{Host: "/h/a", Container: "/data/a"},
		{Host: "/h/ab", Container: "/data/a/b"},
		{Host: "/h/abc", Container: "/data/a/b/c"},
		{Host: "/h/other", Container: "/data/ab"},
	})
	if len(deep) != 2 || deep[0] != (nestedMountPoint{"/h/a", "b"}) || deep[1] != (nestedMountPoint{"/h/ab", "c"}) {
		t.Errorf("nested mount points: %+v", deep)
	}

	// Creating them never follows a link out of the outer folder.
	outer := filepath.Join(t.TempDir(), "honeypots")
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outer, "ssh-proxy"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(outer, "ssh-proxy", "logs")); err != nil {
		t.Skipf("cannot make a symlink here: %v", err)
	}
	if err := ensureContainerDirIn(outer, "ssh-proxy/logs/cells/ssh-backend-1", 0o750); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Errorf("the mount point was created through a link, outside the outer folder: %v", entries)
	}
	if fi, err := os.Lstat(filepath.Join(outer, "ssh-proxy", "logs", "cells", "ssh-backend-1")); err != nil || !fi.IsDir() {
		t.Errorf("the mount point was not created: %v", err)
	}
}

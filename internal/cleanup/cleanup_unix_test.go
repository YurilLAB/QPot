//go:build unix

package cleanup

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestSymlinksAreNeverFollowed: a honeypot plants symlinks to files and
// folders outside its folder; cleanup leaves the targets, and the links.
func TestSymlinksAreNeverFollowed(t *testing.T) {
	cfg := testInstance(t)
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, make([]byte, 3<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-40 * day)
	_ = os.Chtimes(victim, old, old)
	hp := filepath.Join(cfg.DataPath, "honeypots", "cowrie")
	put(t, cfg, "honeypots/cowrie/dl/real", 10, time.Hour)
	links := map[string]string{
		"dl/to-file":         victim,
		"dl/to-dir":          outside,
		"logs/cowrie.json":   victim, // a log the collector reads, over the log limit
		"logs/tty/to-dir":    outside,
		"logs/old.json.1":    victim,
		"../dionaea-escape":  outside,
		"logs/nested/a.json": victim,
	}
	for rel, target := range links {
		p := filepath.Join(hp, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	// A capture folder replaced by a link.
	if err := os.MkdirAll(filepath.Join(cfg.DataPath, "honeypots", "dionaea", "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cfg.DataPath, "honeypots", "dionaea", "data", "binaries")); err != nil {
		t.Fatal(err)
	}
	lim := limits()
	lim.HoneypotLimit = func(string) int64 { return 1 } // prune everything it may
	rep := Run(context.Background(), cfg, lim, Options{Now: now, CollectorRunning: true})
	fi, err := os.Stat(victim)
	if err != nil || fi.Size() != 3<<20 {
		t.Fatalf("the target outside was changed: %v %v", fi, err)
	}
	for rel := range links {
		if _, err := os.Lstat(filepath.Join(hp, rel)); err != nil {
			t.Errorf("the link %s was removed: %v", rel, err)
		}
	}
	if exists(filepath.Join(hp, "dl/real")) {
		t.Error("control: the real capture was kept under a 1-byte limit")
	}
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %v", rep.Errors)
	}
}

// fakeHelper does what it is asked as if it were root (it makes the folders
// writable first), and records the calls.
type fakeHelper struct {
	removes, empties, reads [][]string
	dirs                    []string
}

func (f *fakeHelper) Remove(_ context.Context, dir string, rels []string) error {
	f.dirs = append(f.dirs, dir)
	f.removes = append(f.removes, rels)
	for _, r := range rels {
		p := filepath.Join(dir, r)
		_ = filepath.WalkDir(dir, func(q string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(q, 0o755)
			}
			return nil
		})
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeHelper) FirstLines(_ context.Context, dir string, rels []string) ([][]byte, error) {
	f.dirs = append(f.dirs, dir)
	f.reads = append(f.reads, rels)
	var out [][]byte
	for _, r := range rels {
		p := filepath.Join(dir, r)
		_ = os.Chmod(p, 0o644)
		data, err := os.ReadFile(p)
		if i := bytes.IndexByte(data, '\n'); err == nil && i >= 0 {
			out = append(out, data[:i+1])
		} else {
			out = append(out, nil)
		}
	}
	return out, nil
}

func (f *fakeHelper) Empty(_ context.Context, dir string, rels []string, upTo []int64) error {
	f.dirs = append(f.dirs, dir)
	f.empties = append(f.empties, rels)
	for i, r := range rels {
		p := filepath.Join(dir, r)
		if fi, err := os.Lstat(p); err != nil || fi.Size() > upTo[i] {
			continue // as the helper's script: only what was delivered
		}
		_ = os.Chmod(p, 0o644)
		if err := os.Truncate(p, 0); err != nil {
			return err
		}
	}
	return nil
}

// TestPermissionErrorsGoToTheHelper: files a container's own user owns are
// removed and emptied through the helper, with the honeypot folder mounted.
func TestPermissionErrorsGoToTheHelper(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is never refused")
	}
	cfg := testInstance(t)
	sample := put(t, cfg, "honeypots/cowrie/dl/old", 100, 40*day)
	log := putLog(t, cfg, "honeypots/cowrie/logs/cowrie.json", 3072, 1024, time.Minute)
	deliver(t, cfg, "cowrie", log, -1)
	day := putBackupDay(t, cfg, now.Add(-40*day), 100)
	locked := []string{filepath.Dir(sample), day, filepath.Dir(day)}
	for _, d := range locked {
		if err := os.Chmod(d, 0o555); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(log, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, d := range locked {
			_ = os.Chmod(d, 0o755)
		}
	})

	// Without a helper the run reports what it could not do.
	rep := Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if !exists(sample) || size(t, log) == 0 || len(rep.Errors) == 0 {
		t.Fatalf("without a helper: sample kept %v, log %d bytes, errors %v", exists(sample), size(t, log), rep.Errors)
	}

	h := &fakeHelper{}
	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true, Helper: h})
	if exists(sample) || size(t, log) != 0 || exists(day) {
		t.Fatalf("with the helper: sample kept %v, log %d bytes, day kept %v (errors %v)", exists(sample), size(t, log), exists(day), rep.Errors)
	}
	if rep.Removed != 2 || rep.Emptied != 1 {
		t.Errorf("report counted %d removed %d emptied", rep.Removed, rep.Emptied)
	}
	hp := filepath.Join(cfg.DataPath, "honeypots", "cowrie")
	want := []string{filepath.Join(hp, "dl"), filepath.Join(hp, "logs"), filepath.Join(cfg.DataPath, "backup")}
	for _, d := range h.dirs {
		if !slices.Contains(want, d) {
			t.Errorf("the helper mounted %s, not a honeypot volume or the backup folder", d)
		}
	}
	if strings.Join(h.removes[0], ",") != "old" || strings.Join(h.empties[0], ",") != "cowrie.json" {
		t.Errorf("helper paths: removes %q empties %q", h.removes, h.empties)
	}
}

// TestASwappedFolderCannotLeadOutOfItsVolume: after listing, a honeypot
// swaps a capture folder inside its volume for a link to the honeypot's own
// folder, where the host keeps its config. Removing the listed name acts
// inside the volume, so the host's file stays.
func TestASwappedFolderCannotLeadOutOfItsVolume(t *testing.T) {
	cfg := testInstance(t)
	hp := filepath.Join(cfg.DataPath, "honeypots", "dionaea")
	victim := put(t, cfg, "honeypots/dionaea/victim.cfg", 10, time.Hour) // host-written, beside the volumes
	put(t, cfg, "honeypots/dionaea/data/binaries/sample", 10, 40*day)
	root, err := os.OpenRoot(hp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files, _, _ := list(root, []string{"data/binaries"})
	i := slices.IndexFunc(files, func(f file) bool { return f.kind == kindCapture })
	if i < 0 || files[i].rel != "data/binaries/sample" {
		t.Fatalf("listed %+v", files)
	}
	// The swap: binaries becomes a link to the honeypot folder, and the
	// listed name now points at the host's file.
	if err := os.RemoveAll(filepath.Join(hp, "data", "binaries")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", filepath.Join(hp, "data", "binaries")); err != nil {
		t.Fatal(err)
	}
	listed := files[i]
	listed.rel = "data/binaries/victim.cfg"
	rep := &Report{}
	area := &Area{Name: "dionaea"}
	act := newActor(rep, area, root, hp, Options{Now: now})
	defer act.close()
	act.remove(context.Background(), listed)
	if !exists(victim) {
		t.Fatal("the host's file beside the volume was removed through the swapped folder")
	}
	if len(rep.Errors) == 0 {
		t.Error("the refused removal was not reported")
	}
	// Negative control: removed relative to the whole honeypot folder, the
	// same name reaches the host's file.
	if err := root.Remove("data/binaries/victim.cfg"); err != nil || exists(victim) {
		t.Fatalf("control: a folder-wide root did not follow the swap (%v)", err)
	}
}

// TestUnreadableLogIsFingerprintedThroughTheHelper: cowrie writes its log
// 0640, so QPot, an ordinary user, cannot read the first line the collector
// fingerprints. The helper reads it; without one the log is not confirmed as
// delivered and stays.
func TestUnreadableLogIsFingerprintedThroughTheHelper(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	cfg := testInstance(t)
	log := putLog(t, cfg, "honeypots/cowrie/logs/cowrie.json", 3072, 1024, time.Minute)
	deliver(t, cfg, "cowrie", log, -1)
	if err := os.Chmod(log, 0o200); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(log); err == nil {
		f.Close()
		t.Fatal("the log is still readable")
	}
	rep := Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if rep.Emptied != 0 || size(t, log) == 0 {
		t.Fatalf("emptied a log it could not fingerprint: %+v", rep)
	}
	h := &fakeHelper{}
	if err := os.Chmod(log, 0o200); err != nil {
		t.Fatal(err)
	}
	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true, Helper: h})
	if rep.Emptied != 1 || size(t, log) != 0 || len(rep.Errors) != 0 {
		t.Fatalf("with the helper: %+v (%d bytes left)", rep, size(t, log))
	}
	if len(h.reads) != 1 || strings.Join(h.reads[0], ",") != "cowrie.json" {
		t.Errorf("helper reads %q", h.reads)
	}
	// Nothing to empty: no helper container is started at all.
	h2 := &fakeHelper{}
	putLog(t, cfg, "honeypots/dionaea/logs/dionaea.json", 3, 100, time.Minute)
	if err := os.Chmod(filepath.Join(cfg.DataPath, "honeypots/dionaea/logs/dionaea.json"), 0o200); err != nil {
		t.Fatal(err)
	}
	Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true, Helper: h2})
	if len(h2.reads) != 0 {
		t.Errorf("read first lines with nothing over a limit: %q", h2.reads)
	}
}

package cleanup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/config"
)

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// testInstance is an instance config whose data folder is a temp dir.
func testInstance(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default("cleanup-test")
	cfg.DataPath = t.TempDir()
	return cfg
}

// put writes size bytes at rel under the instance folder, last changed age ago.
func put(t *testing.T, cfg *config.Config, rel string, size int, age time.Duration) string {
	t.Helper()
	p := filepath.Join(cfg.DataPath, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), size), 0o644); err != nil {
		t.Fatal(err)
	}
	when := now.Add(-age)
	if err := os.Chtimes(p, when, when); err != nil {
		t.Fatal(err)
	}
	return p
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func size(t *testing.T, p string) int64 {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func limits() Limits {
	return Limits{MaxAge: 30 * day, MaxLog: 1 << 20, MaxBackup: 1 << 30}
}

func area(r *Report, name string) Area {
	for _, a := range r.Areas {
		if a.Name == name {
			return a
		}
	}
	return Area{}
}

func TestAgeRemovesOnlyCapturesAndRotatedLogs(t *testing.T) {
	cfg := testInstance(t)
	old, fresh := 40*day, day
	gone := []string{
		put(t, cfg, "honeypots/cowrie/dl/old-sample", 100, old),
		put(t, cfg, "honeypots/cowrie/logs/tty/old-session", 100, old),
		put(t, cfg, "honeypots/cowrie/logs/cowrie.json.2026-09-01", 100, old),
		put(t, cfg, "honeypots/dionaea/data/binaries/old.exe", 100, old),
		put(t, cfg, "honeypots/miniprint/uploads/old-job.pcl", 100, old),
	}
	kept := []string{
		put(t, cfg, "honeypots/cowrie/dl/new-sample", 100, fresh),
		put(t, cfg, "honeypots/cowrie/logs/tty/new-session", 100, fresh),
		// Negative controls: state, config and served files, however old.
		put(t, cfg, "honeypots/cowrie/etc/persona-state.json", 100, old),
		put(t, cfg, "honeypots/dionaea/data/roots/www/index.html", 100, old),
		put(t, cfg, "honeypots/miniprint/data/fs/README", 100, old),
		put(t, cfg, "honeypots/conpot/state/registers", 100, old),
		// A log the collector reads is not aged out while it is stopped.
		put(t, cfg, "honeypots/cowrie/logs/cowrie.json", 100, old),
	}
	rep := Run(context.Background(), cfg, limits(), Options{Now: now})
	for _, p := range gone {
		if exists(p) {
			t.Errorf("%s was kept", p)
		}
	}
	for _, p := range kept {
		if !exists(p) {
			t.Errorf("%s was removed", p)
		}
	}
	if rep.Removed != len(gone) || rep.Emptied != 0 || len(rep.Errors) != 0 {
		t.Errorf("report: removed %d emptied %d errors %v, want %d removed", rep.Removed, rep.Emptied, rep.Errors, len(gone))
	}
	if a := area(rep, "cowrie"); a.Removed != 3 || a.Freed <= 0 {
		t.Errorf("cowrie area %+v", a)
	}

	// With the collector running, the old log it read goes too.
	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if exists(kept[len(kept)-1]) || rep.Removed != 1 {
		t.Errorf("collected old log: removed %d, still there %v", rep.Removed, exists(kept[len(kept)-1]))
	}
}

func TestLogsAreEmptiedOnlyWhileTheCollectorRuns(t *testing.T) {
	cfg := testInstance(t)
	big := put(t, cfg, "honeypots/cowrie/logs/cowrie.json", 3<<20, time.Minute)
	small := put(t, cfg, "honeypots/dionaea/logs/dionaea.json", 100, time.Minute)
	before, _ := os.Stat(big)

	rep := Run(context.Background(), cfg, limits(), Options{Now: now})
	if size(t, big) != 3<<20 || rep.Emptied != 0 {
		t.Fatalf("emptied with the collector stopped: %d bytes left, %d emptied", size(t, big), rep.Emptied)
	}
	if len(rep.Notes) == 0 || !strings.Contains(rep.Notes[0], "collector is not running") {
		t.Errorf("no note about the stopped collector: %q", rep.Notes)
	}

	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if size(t, big) != 0 || rep.Emptied != 1 {
		t.Fatalf("not emptied with the collector running: %d bytes left, %d emptied", size(t, big), rep.Emptied)
	}
	after, _ := os.Stat(big)
	if !os.SameFile(before, after) {
		t.Error("the log was replaced, not emptied: the honeypot would write to a removed file")
	}
	if size(t, small) != 100 {
		t.Error("a log under the limit was emptied")
	}
}

func TestStorageLimitRemovesOldestFirst(t *testing.T) {
	cfg := testInstance(t)
	var samples []string
	for i := 0; i < 10; i++ {
		// sample 0 is the oldest; all are within the age limit.
		samples = append(samples, put(t, cfg, filepath.ToSlash(filepath.Join("honeypots/cowrie/dl", "s"+string(rune('0'+i)))), 64<<10, time.Duration(10-i)*time.Hour))
	}
	state := put(t, cfg, "honeypots/cowrie/etc/userdb.txt", 64<<10, time.Hour)
	lim := limits()
	used := area(Run(context.Background(), cfg, lim, Options{Now: now, DryRun: true}), "cowrie").Bytes
	// A limit that holds about half of what is there.
	lim.HoneypotLimit = func(name string) int64 {
		if name == "cowrie" {
			return used / 2
		}
		return 0
	}
	rep := Run(context.Background(), cfg, lim, Options{Now: now})
	a := area(rep, "cowrie")
	if a.Over || a.Bytes > int64(float64(used/2)*keepFraction) {
		t.Errorf("cowrie still at %d of limit %d", a.Bytes, used/2)
	}
	// The oldest went, the newest stayed.
	if exists(samples[0]) || !exists(samples[9]) {
		t.Errorf("oldest kept %v, newest kept %v", exists(samples[0]), exists(samples[9]))
	}
	firstKept := slices.IndexFunc(samples, exists)
	for _, p := range samples[firstKept:] {
		if !exists(p) {
			t.Errorf("%s removed while an older sample was kept", p)
		}
	}
	if !exists(state) {
		t.Error("state was removed to meet the limit")
	}
}

func TestStorageLimitThatOnlyStateExceedsIsReported(t *testing.T) {
	cfg := testInstance(t)
	put(t, cfg, "honeypots/cowrie/etc/big-state", 256<<10, time.Hour)
	lim := limits()
	lim.HoneypotLimit = func(string) int64 { return 64 << 10 }
	rep := Run(context.Background(), cfg, lim, Options{Now: now, CollectorRunning: true})
	if a := area(rep, "cowrie"); !a.Over || a.Removed != 0 {
		t.Errorf("area %+v: want over its limit with nothing removed", a)
	}
	if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.Contains(n, "cowrie is still above its limit") }) {
		t.Errorf("notes %q", rep.Notes)
	}
}

func putBackupDay(t *testing.T, cfg *config.Config, d time.Time, size int) string {
	return filepath.Dir(put(t, cfg, "backup/logs/"+d.Format("2006/01/02")+"/cowrie.log", size, 0))
}

func TestBackupDays(t *testing.T) {
	cfg := testInstance(t)
	today := putBackupDay(t, cfg, now, 64<<10)
	yesterday := putBackupDay(t, cfg, now.Add(-day), 64<<10)
	lastWeek := putBackupDay(t, cfg, now.Add(-7*day), 64<<10)
	old := putBackupDay(t, cfg, now.Add(-40*day), 64<<10)
	unrelated := put(t, cfg, "backup/notes.txt", 10, 400*day)
	// A day folder a failed run left empty still goes.
	emptyOld := filepath.Join(cfg.DataPath, "backup", "logs", now.Add(-50*day).Format("2006/01/02"))
	if err := os.MkdirAll(emptyOld, 0o755); err != nil {
		t.Fatal(err)
	}

	rep := Run(context.Background(), cfg, limits(), Options{Now: now})
	if exists(old) || !exists(lastWeek) || !exists(yesterday) || !exists(today) || !exists(unrelated) {
		t.Fatalf("age pass: old %v lastWeek %v yesterday %v today %v unrelated %v",
			exists(old), exists(lastWeek), exists(yesterday), exists(today), exists(unrelated))
	}
	if exists(filepath.Dir(old)) {
		t.Error("the emptied month folder was left")
	}
	if exists(emptyOld) {
		t.Error("an empty old day folder was left")
	}
	if a := area(rep, "backup"); a.Removed != 2 {
		t.Errorf("backup area %+v", a)
	}

	// Over its limit: oldest days go, never the current one.
	lim := limits()
	lim.MaxBackup = 32 << 10
	rep = Run(context.Background(), cfg, lim, Options{Now: now})
	if exists(lastWeek) || exists(yesterday) || !exists(today) {
		t.Errorf("limit pass: lastWeek %v yesterday %v today %v", exists(lastWeek), exists(yesterday), exists(today))
	}
	if a := area(rep, "backup"); !a.Over {
		t.Errorf("backup area %+v: today alone is above the limit", a)
	}
}

func TestDryRunChangesNothing(t *testing.T) {
	cfg := testInstance(t)
	paths := []string{
		put(t, cfg, "honeypots/cowrie/dl/old", 100, 40*day),
		put(t, cfg, "honeypots/cowrie/logs/cowrie.json", 3<<20, time.Minute),
		putBackupDay(t, cfg, now.Add(-40*day), 100),
	}
	dry := Run(context.Background(), cfg, limits(), Options{Now: now, DryRun: true, CollectorRunning: true})
	for _, p := range paths {
		if !exists(p) {
			t.Fatalf("dry run removed %s", p)
		}
	}
	if size(t, paths[1]) != 3<<20 {
		t.Fatal("dry run emptied a log")
	}
	real := Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if dry.Removed != real.Removed || dry.Emptied != real.Emptied || dry.Removed != 2 || dry.Emptied != 1 {
		t.Errorf("dry run said %d removed %d emptied; the run did %d and %d", dry.Removed, dry.Emptied, real.Removed, real.Emptied)
	}
}

func TestEmptyRefusesAFileThatChanged(t *testing.T) {
	cfg := testInstance(t)
	a := put(t, cfg, "honeypots/cowrie/logs/a.json", 100, 0)
	b := put(t, cfg, "honeypots/cowrie/logs/b.json", 100, 0)
	root, err := os.OpenRoot(filepath.Join(cfg.DataPath, "honeypots/cowrie/logs"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	infoB, _ := os.Lstat(b)
	// a's path with b's listing: another file now has the name.
	if err := emptyFile(root, "a.json", infoB); !errors.Is(err, errChanged) {
		t.Fatalf("emptyFile = %v, want errChanged", err)
	}
	if size(t, a) != 100 {
		t.Fatal("emptied a file that was not the one listed")
	}
	// Control: the right listing empties it.
	infoA, _ := os.Lstat(a)
	if err := emptyFile(root, "a.json", infoA); err != nil || size(t, a) != 0 {
		t.Fatalf("emptyFile = %v, size %d", err, size(t, a))
	}
}

func TestLimitsFor(t *testing.T) {
	cfg := testInstance(t)
	cfg.Cleanup.MaxAgeDays, cfg.Cleanup.MaxLogMB, cfg.Cleanup.MaxBackupMB = 7, 10, 20
	cfg.Security.ResourceLimits.MaxStorageGB = 3
	hp := cfg.Honeypots["cowrie"]
	hp.Resources.UseCustomLimits, hp.Resources.MaxStorageGB = true, 1
	cfg.Honeypots["cowrie"] = hp
	l := LimitsFor(cfg)
	if l.MaxAge != 7*day || l.MaxLog != 10<<20 || l.MaxBackup != 20<<20 {
		t.Errorf("limits %+v", l)
	}
	if l.HoneypotLimit("cowrie") != 1<<30 || l.HoneypotLimit("dionaea") != 3<<30 {
		t.Errorf("honeypot limits: cowrie %d dionaea %d", l.HoneypotLimit("cowrie"), l.HoneypotLimit("dionaea"))
	}
}

func TestDockerHelperArguments(t *testing.T) {
	var calls [][]string
	d := &DockerHelper{Image: "img@sha256:x", Run: func(_ context.Context, args ...string) error {
		calls = append(calls, args)
		return nil
	}}
	dir := filepath.Join(t.TempDir(), "honeypots", "cowrie")
	if !filepath.IsAbs(dir) {
		t.Fatal("temp dir not absolute")
	}
	var rels []string
	for i := 0; i < helperBatch+5; i++ {
		rels = append(rels, "dl/-rf "+string(rune('a'+i%26)))
	}
	if err := d.Remove(context.Background(), dir, rels); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("%d containers for %d paths, want 2", len(calls), len(rels))
	}
	args := strings.Join(calls[0], " ")
	for _, want := range []string{"--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--mount type=bind,source=" + dir + ",target=/c", "--entrypoint rm img@sha256:x -rf -- /c/dl/-rf a"} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
	if err := d.Empty(context.Background(), dir, []string{"logs/cowrie.json"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls[2][len(calls[2])-6:], " "); got != "img@sha256:x -c -s 0 -- /c/logs/cowrie.json" {
		t.Errorf("empty args end %q", got)
	}
	// Negative controls: nothing outside dir, no relative or odd mounts.
	for _, bad := range [][2]string{{dir, "../escape"}, {dir, "/etc/passwd"}, {"relative/dir", "x"}, {dir + ",target=/etc", "x"}} {
		if err := d.Remove(context.Background(), bad[0], []string{bad[1]}); err == nil {
			t.Errorf("Remove(%q, %q) accepted", bad[0], bad[1])
		}
	}
	if len(calls) != 3 {
		t.Errorf("a refused request still ran docker (%d calls)", len(calls))
	}
}

package instance

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/config"
)

const scrubTestID = "qp_scrubscrubscrubscrubscru"

func scrubConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Default("scrub")
	cfg.QPotID = scrubTestID
	cfg.DataPath = filepath.Join(t.TempDir(), "instance")
	cfg.ConfigPath = filepath.Join(cfg.DataPath, "config.yaml")
	if err := os.MkdirAll(cfg.DataPath, 0o700); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// oldBackupLine is a backup line as the collector wrote it before the fix.
func oldBackupLine(i int) string {
	return `{"honeypot":"cowrie","message":"event ` + strings.Repeat("x", i%97) + `","qpot_id":"` + scrubTestID + `","qpot_instance":"scrub"}` + "\n"
}

func writeBackup(t *testing.T, cfg *config.Config, rel string, lines int) string {
	t.Helper()
	p := filepath.Join(cfg.DataPath, "backup", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := range lines {
		b.WriteString(oldBackupLine(i))
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// stubScrubDocker replaces the collector stop and the helper, and counts them.
func stubScrubDocker(t *testing.T, helper func(dir, oldID, newID string) error) (stops, helps *int) {
	t.Helper()
	stops, helps = new(int), new(int)
	oldStop, oldHelper := scrubStopCollector, scrubHelper
	t.Cleanup(func() { scrubStopCollector, scrubHelper = oldStop, oldHelper })
	scrubStopCollector = func(context.Context, *config.Config) error { *stops++; return nil }
	scrubHelper = func(_ context.Context, dir, oldID, newID string) error {
		*helps++
		if helper == nil {
			t.Error("the helper container was asked for")
			return nil
		}
		return helper(dir, oldID, newID)
	}
	return stops, helps
}

// TestOverwriteInFileEveryOffset places the QPot ID at every position around
// the read window's edge: each one is replaced, nothing else changes, and
// the file keeps its size.
func TestOverwriteInFileEveryOffset(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	sensor := config.SensorIDFor(scrubTestID)
	const window = 1 << 20
	for _, at := range []int{0, 1, window - 28, window - 27, window - 26, window - 14, window - 1, window, window + 1, 2*window - 13, 3 * window} {
		before := bytes.Repeat([]byte("abcdefghij"), (3*window+200)/10)
		copy(before[at:], scrubTestID)
		// Two more back to back at the end, and one cut short (not an ID).
		tail := len(before) - 2*len(scrubTestID)
		copy(before[tail:], scrubTestID+scrubTestID)
		copy(before[100:], scrubTestID[:20])
		if err := os.WriteFile(filepath.Join(dir, "f.log"), before, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := overwriteInFile(root, "f.log", []byte(scrubTestID), []byte(sensor)); err != nil {
			t.Fatalf("offset %d: %v", at, err)
		}
		after, err := os.ReadFile(filepath.Join(dir, "f.log"))
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.ReplaceAll(before, []byte(scrubTestID), []byte(sensor))
		if !bytes.Equal(after, want) {
			t.Fatalf("offset %d: the file is not the original with each ID replaced (len %d, want %d; IDs left %d)",
				at, len(after), len(want), bytes.Count(after, []byte(scrubTestID)))
		}
		has, err := fileContains(root, "f.log", []byte(scrubTestID))
		if err != nil || has {
			t.Fatalf("offset %d: fileContains = %v, %v after the rewrite", at, has, err)
		}
		if has, err := fileContains(root, "f.log", []byte(sensor)); err != nil || !has {
			t.Fatalf("offset %d: the sensor ID is not found (%v)", at, err)
		}
	}
}

func TestScrubLogBackupsOnce(t *testing.T) {
	cfg := scrubConfig(t)
	stops, _ := stubScrubDocker(t, nil)
	a := writeBackup(t, cfg, "logs/2026/11/09/cowrie.log", 5000)
	b := writeBackup(t, cfg, "logs/2026/11/10/dionaea.log", 3)
	clean := filepath.Join(cfg.DataPath, "backup", "logs", "2026", "11", "10", "conpot.log")
	if err := os.WriteFile(clean, []byte(`{"honeypot":"conpot"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Not a backup log, and outside the backup folder: neither is touched.
	other := filepath.Join(cfg.DataPath, "backup", "logs", "notes.txt")
	outside := filepath.Join(cfg.DataPath, "qpot.id")
	for _, p := range []string{other, outside} {
		if err := os.WriteFile(p, []byte(scrubTestID), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sizeBefore := map[string]int64{}
	for _, p := range []string{a, b, clean} {
		st, _ := os.Stat(p)
		sizeBefore[p] = st.Size()
	}

	m := &Manager{config: cfg}
	if BackupsScrubbed(cfg) {
		t.Fatal("marked scrubbed before anything ran")
	}
	if err := m.scrubLogBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *stops != 1 {
		t.Errorf("the collector was stopped %d times, want once", *stops)
	}
	sensor := cfg.SensorID()
	for _, p := range []string{a, b, clean} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(scrubTestID)) {
			t.Errorf("%s still carries the QPot ID", p)
		}
		if int64(len(data)) != sizeBefore[p] {
			t.Errorf("%s changed size: %d -> %d", p, sizeBefore[p], len(data))
		}
		if p != clean && bytes.Count(data, []byte(`"qpot_id":"`+sensor+`"`)) != bytes.Count(data, []byte("\n")) {
			t.Errorf("%s: not every line carries the sensor ID", p)
		}
	}
	for _, p := range []string{other, outside} {
		if data, _ := os.ReadFile(p); string(data) != scrubTestID {
			t.Errorf("%s was rewritten", p)
		}
	}
	if !BackupsScrubbed(cfg) {
		t.Fatal("no marker after a complete scrub")
	}
	// Done once: later starts do not read the backups or stop the collector.
	writeBackup(t, cfg, "logs/2026/11/11/cowrie.log", 1)
	if err := m.scrubLogBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *stops != 1 {
		t.Errorf("a second start stopped the collector again (%d)", *stops)
	}
}

// TestScrubNothingToDo: a new instance, or one whose backups never held the
// ID, is marked without the collector being stopped.
func TestScrubNothingToDo(t *testing.T) {
	for _, withBackups := range []bool{false, true} {
		cfg := scrubConfig(t)
		stops, _ := stubScrubDocker(t, nil)
		if withBackups {
			p := filepath.Join(cfg.DataPath, "backup", "logs", "2026", "11", "11")
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "cowrie.log"), []byte(`{"sensor_id":"`+cfg.SensorID()+`"}`+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := (&Manager{config: cfg}).scrubLogBackups(t.Context()); err != nil {
			t.Fatal(err)
		}
		if *stops != 0 || !BackupsScrubbed(cfg) {
			t.Errorf("backups=%v: stops=%d scrubbed=%v", withBackups, *stops, BackupsScrubbed(cfg))
		}
	}
}

// TestScrubUsesHelperForFilesItMayNotChange: backups the collector's root
// wrote are read-only to the operator on Linux. The helper is asked, and
// the marker is written only once no file carries the ID.
func TestScrubUsesHelperForFilesItMayNotChange(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file this process may read but not write")
	}
	cfg := scrubConfig(t)
	p := writeBackup(t, cfg, "logs/2026/11/09/cowrie.log", 10)
	if err := os.Chmod(p, 0o444); err != nil {
		t.Fatal(err)
	}
	fail := true
	_, helps := stubScrubDocker(t, func(dir, oldID, newID string) error {
		if dir != filepath.Join(cfg.DataPath, "backup") || oldID != scrubTestID || newID != cfg.SensorID() {
			t.Errorf("helper asked with %q %q %q", dir, oldID, newID)
		}
		if fail {
			return nil // a helper that did nothing
		}
		if err := os.Chmod(p, 0o644); err != nil {
			return err
		}
		data, _ := os.ReadFile(p)
		return os.WriteFile(p, bytes.ReplaceAll(data, []byte(oldID), []byte(newID)), 0o644)
	})
	m := &Manager{config: cfg}
	if err := m.scrubLogBackups(t.Context()); err == nil || BackupsScrubbed(cfg) {
		t.Fatalf("a scrub that left the ID in place reported success (err=%v)", err)
	}
	fail = false
	if err := m.scrubLogBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *helps != 2 || !BackupsScrubbed(cfg) {
		t.Errorf("helps=%d scrubbed=%v", *helps, BackupsScrubbed(cfg))
	}
}

// TestScrubHelperLive runs the real helper container over root-owned files.
func TestScrubHelperLive(t *testing.T) {
	if os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 to run the scrub helper container")
	}
	if exec.Command("docker", "image", "inspect", CollectorImage).Run() != nil {
		t.Skip("collector image not present locally")
	}
	cfg := scrubConfig(t)
	dir := filepath.Join(cfg.DataPath, "backup")
	a := writeBackup(t, cfg, "logs/2026/11/09/cowrie.log", 2000)
	clean := writeBackup(t, cfg, "logs/2026/11/09/empty.log", 0)
	// Hand the files to root, as the collector's own are, and take them
	// back afterwards so the test folder can be removed.
	chown := func(owner string) {
		out, err := exec.Command("docker", "run", "--rm", "--network", "none", "--user", "0:0", "--mount", "type=bind,source="+dir+",target=/c",
			"--entrypoint", "sh", CollectorImage, "-c", "chown -R "+owner+" /c && chmod -R go-w /c").CombinedOutput()
		if err != nil {
			t.Fatalf("chown %s: %v %s", owner, err, out)
		}
	}
	chown("0:0")
	t.Cleanup(func() { chown(strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())) })

	oldStop := scrubStopCollector
	scrubStopCollector = func(context.Context, *config.Config) error { return nil }
	t.Cleanup(func() { scrubStopCollector = oldStop })
	if err := (&Manager{config: cfg}).scrubLogBackups(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(scrubTestID)) || bytes.Count(data, []byte(cfg.SensorID())) != 2000 {
		t.Fatalf("helper left %d QPot IDs and wrote %d sensor IDs", bytes.Count(data, []byte(scrubTestID)), bytes.Count(data, []byte(cfg.SensorID())))
	}
	if st, err := os.Stat(clean); err != nil || st.Size() != 0 {
		t.Errorf("an untouched backup changed: %v", err)
	}
	if !BackupsScrubbed(cfg) {
		t.Error("no marker after the helper's scrub")
	}
	// A wrong-length ID is refused by the helper itself.
	if err := scrubHelper(t.Context(), dir, "short", cfg.SensorID()); err == nil {
		t.Error("the helper accepted an ID of the wrong length")
	}
}

// FuzzOverwriteInFile: whatever the file holds and wherever the QPot ID
// stands in it, the rewrite equals replacing every occurrence, keeps the
// size, and leaves no occurrence behind.
func FuzzOverwriteInFile(f *testing.F) {
	f.Add([]byte("x"), uint32(0), uint8(1))
	f.Add([]byte(scrubTestID[:26]), uint32(1<<20-13), uint8(3))
	f.Add([]byte("{\"qpot_id\":\""), uint32(1<<20), uint8(2))
	sensor := config.SensorIDFor(scrubTestID)
	dir := f.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { root.Close() })
	f.Fuzz(func(t *testing.T, filler []byte, gap uint32, copies uint8) {
		if len(filler) == 0 {
			filler = []byte{0}
		}
		// Up to 3 MiB: IDs separated by a gap that walks them across the
		// read window's edge.
		var before []byte
		pad := bytes.Repeat(filler, int(gap%(1<<20+64))/len(filler)+1)[:gap%(1<<20+64)]
		for range copies%6 + 1 {
			before = append(before, pad...)
			before = append(before, scrubTestID...)
		}
		before = append(before, filler...)
		if err := os.WriteFile(filepath.Join(dir, "f.log"), before, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := overwriteInFile(root, "f.log", []byte(scrubTestID), []byte(sensor)); err != nil {
			t.Fatal(err)
		}
		after, err := os.ReadFile(filepath.Join(dir, "f.log"))
		if err != nil {
			t.Fatal(err)
		}
		if want := bytes.ReplaceAll(before, []byte(scrubTestID), []byte(sensor)); !bytes.Equal(after, want) {
			t.Fatalf("rewrite differs from replacing every occurrence (len %d, want %d, IDs left %d)", len(after), len(want), bytes.Count(after, []byte(scrubTestID)))
		}
		if has, err := fileContains(root, "f.log", []byte(scrubTestID)); err != nil || has {
			t.Fatalf("fileContains = %v, %v after the rewrite", has, err)
		}
	})
}

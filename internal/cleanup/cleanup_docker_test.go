//go:build linux

package cleanup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/instance"
	"github.com/qpot/qpot/internal/vectorstate"
)

// dockerTest skips unless QPOT_TEST_DOCKER=1. It needs Docker, the collector's
// image and an ordinary user in the docker group: root may change any file
// itself, so it would never need the helper.
func dockerTest(t *testing.T) {
	t.Helper()
	if os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 to run the cleanup helper in real containers")
	}
	if out, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", instance.CollectorImage).CombinedOutput(); err != nil {
		t.Fatalf("QPOT_TEST_DOCKER=1 needs Docker and the collector image (docker pull %s): %v: %s", instance.CollectorImage, err, out)
	}
	if os.Geteuid() == 0 {
		t.Fatal("QPOT_TEST_DOCKER=1 must run as an ordinary user in the docker group, as QPot does")
	}
}

// asContainerRoot runs script with sh in the collector's image as root, with
// dir mounted at /w and env set.
func asContainerRoot(t *testing.T, dir, script string, env ...string) {
	t.Helper()
	args := []string{"run", "--rm", "--network", "none", "--user", "0:0",
		"--mount", "type=bind,source=" + dir + ",target=/w"}
	for _, e := range env {
		args = append(args, "--env", e)
	}
	args = append(args, "--entrypoint", "sh", instance.CollectorImage, "-ec", script)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("container: %v: %s", err, out)
	}
}

// TestDockerHelperForReal: files a honeypot's own user wrote, which QPot
// running as an ordinary user may not remove or empty, stay without the
// helper and are removed and emptied by the real helper container. A log is
// emptied in place. Links the honeypot planted towards a file outside its
// volume lead nowhere inside the helper, which mounts only that volume; with
// the whole instance folder mounted the same link would reach the file.
func TestDockerHelperForReal(t *testing.T) {
	dockerTest(t)
	cfg := testInstance(t)
	data := cfg.DataPath
	// What the containers leave belongs to other users; give it back so the
	// temp folder can be removed.
	t.Cleanup(func() {
		asContainerRoot(t, data, fmt.Sprintf("chown -R %d:%d /w", os.Getuid(), os.Getgid()))
	})
	keep := put(t, cfg, "outside/keep", 4096, 0)
	keep2 := put(t, cfg, "outside2/keep", 4096, 0)
	oldDay := now.Add(-40 * day).Format("2006/01/02")
	today := now.Format("2006/01/02")
	asContainerRoot(t, data, `
h=/w/honeypots/cowrie
mkdir -p "$h/dl" "$h/logs" "/w/backup/logs/$OLD_DAY" "/w/backup/logs/$TODAY"
head -c 65536 /dev/zero > "$h/dl/old-sample"
head -c 65536 /dev/zero > "$h/dl/new-sample"
head -c 65536 /dev/zero > "$h/logs/cowrie.json.1"
yes '{"e":"x"}' | head -n 209716 > "$h/logs/cowrie.json"
head -c 65536 /dev/zero > "/w/backup/logs/$OLD_DAY/cowrie.log"
head -c 65536 /dev/zero > "/w/backup/logs/$TODAY/cowrie.log"
ln -s ../../../outside "$h/dl/rel-link"
ln -s ../../../outside2 "$h/dl/rel-link2"
ln -s "$OUTSIDE" "$h/dl/abs-link"
touch -d "$OLD" "$h/dl/old-sample" "$h/logs/cowrie.json.1"
touch -d "$RECENT" "$h/dl/new-sample" "$h/logs/cowrie.json"
chown -R 2000:2000 "$h"
chmod 0755 "$h" "$h/dl" "$h/logs"
chmod 0640 "$h/logs/cowrie.json"
`,
		"OLD_DAY="+oldDay, "TODAY="+today, "OUTSIDE="+filepath.Dir(keep),
		"OLD="+now.Add(-40*day).Format(time.DateTime), "RECENT="+now.Add(-time.Hour).Format(time.DateTime))

	hp := filepath.Join(data, "honeypots", "cowrie")
	dl := filepath.Join(hp, "dl")
	oldSample := filepath.Join(dl, "old-sample")
	newSample := filepath.Join(dl, "new-sample")
	rotated := filepath.Join(hp, "logs", "cowrie.json.1")
	log := filepath.Join(hp, "logs", "cowrie.json")
	oldBackup := filepath.Join(data, "backup", "logs", filepath.FromSlash(oldDay))
	todayBackup := filepath.Join(data, "backup", "logs", filepath.FromSlash(today))
	logBefore, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	// On the host the links do lead to the files outside.
	for _, p := range []string{filepath.Join(dl, "rel-link", "keep"), filepath.Join(dl, "abs-link", "keep"), filepath.Join(dl, "rel-link2", "keep")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("the planted link does not lead out on the host: %v", err)
		}
	}

	logSize := logBefore.Size()
	// The collector has all of the log. Its first line is that of the
	// file the setup wrote; QPot itself cannot read it (0640, like cowrie's).
	if f, err := os.Open(log); err == nil {
		f.Close()
		t.Fatal("the log is readable by this user: the helper would not need to read it")
	}
	fp, _ := vectorstate.Fingerprint(strings.NewReader("{\"e\":\"x\"}\n"))
	setCheckpoint(t, cfg, "cowrie", fp, logSize)

	// Without the helper: this user may change none of it.
	rep := Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true})
	if len(rep.Errors) == 0 || !strings.Contains(strings.Join(rep.Errors, "\n"), "permission denied") {
		t.Fatalf("without the helper the run should fail on permissions: %q", rep.Errors)
	}
	if !exists(oldSample) || !exists(rotated) || size(t, log) != logSize || !exists(oldBackup) {
		t.Fatal("without the helper something was changed: the files are not other users' after all")
	}

	// The helper leaves a log holding more than the collector delivered.
	if err := (&DockerHelper{Image: instance.CollectorImage}).Empty(context.Background(), filepath.Join(hp, "logs"),
		[]string{"cowrie.json"}, []int64{logSize - 1}); err != nil {
		t.Fatal(err)
	}
	if size(t, log) != logSize {
		t.Fatal("the helper emptied a log holding lines the collector had not delivered")
	}

	// With the real helper.
	rep = Run(context.Background(), cfg, limits(), Options{Now: now, CollectorRunning: true,
		Helper: &DockerHelper{Image: instance.CollectorImage}})
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %q", rep.Errors)
	}
	if exists(oldSample) || exists(rotated) || exists(oldBackup) {
		t.Error("the old capture, rotated log or backup day is still there")
	}
	if !exists(newSample) || !exists(todayBackup) {
		t.Error("a recent capture or today's backup was removed")
	}
	logAfter, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	if logAfter.Size() != 0 || !os.SameFile(logBefore, logAfter) {
		t.Errorf("the log was not emptied in place: %d bytes, same file %v", logAfter.Size(), os.SameFile(logBefore, logAfter))
	}
	if a := area(rep, "cowrie"); a.Removed != 2 || a.Emptied != 1 {
		t.Errorf("cowrie: removed %d emptied %d, want 2 and 1", a.Removed, a.Emptied)
	}
	if a := area(rep, "backup"); a.Removed != 1 {
		t.Errorf("backup: removed %d days, want 1", a.Removed)
	}
	for _, l := range []string{"rel-link", "rel-link2", "abs-link"} {
		if !exists(filepath.Join(dl, l)) {
			t.Errorf("the link %s was removed: cleanup lists no links", l)
		}
	}

	// Given the links themselves, the helper changes nothing outside the
	// volume it mounts.
	h := &DockerHelper{Image: instance.CollectorImage}
	ctx := context.Background()
	escapes := []string{"rel-link/keep", "abs-link/keep", "rel-link/", "abs-link/"}
	if err := h.Empty(ctx, dl, escapes[:2], []int64{1 << 40, 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(ctx, dl, escapes); err != nil {
		t.Fatal(err)
	}
	if size(t, keep) != 4096 {
		t.Error("the helper changed a file outside the volume through a link")
	}
	// Control: mounting the instance folder instead, the same link reaches
	// the file, so the check above can see an escape.
	if err := h.Remove(ctx, data, []string{"honeypots/cowrie/dl/rel-link2/keep"}); err != nil {
		t.Fatal(err)
	}
	if exists(keep2) {
		t.Error("control: through the instance folder the link should have reached the file")
	}
}

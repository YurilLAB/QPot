//go:build linux

package cleanup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/diskguard"
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

func TestDockerSSHInventoryPrivateEvidenceAndUnsupportedObjects(t *testing.T) {
	dockerTest(t)
	data := t.TempDir()
	root := filepath.Join(data, "logs", "cells")
	archive := filepath.Join(root, "opaque-cell", "archive-g1-123", "logs", "uid-1001")
	if err := os.MkdirAll(archive, 0o750); err != nil {
		t.Fatal(err)
	}
	name := "strange\nfilename.json"
	content := []byte("{\"event\":\"closed-private-capture\"}\nsecond line\n")
	if err := os.WriteFile(filepath.Join(archive, name), content, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { asContainerRoot(t, data, fmt.Sprintf("chown -R %d:%d /w", os.Getuid(), os.Getgid())) })
	asContainerRoot(t, data, `chown -R 2000:2000 /w/logs/cells/opaque-cell/archive-g1-123/logs
chmod 0700 /w/logs/cells/opaque-cell/archive-g1-123/logs/uid-1001`)
	helper := &DockerHelper{Image: instance.CollectorImage}
	files, err := helper.SSHInventory(context.Background(), root)
	if err != nil || len(files) != 1 {
		t.Fatalf("private evidence inventory failed: %v %+v", err, files)
	}
	want, _ := vectorstate.Fingerprint(strings.NewReader(string(content)))
	if files[0].rel != "logs/cells/opaque-cell/archive-g1-123/logs/uid-1001/"+name || !files[0].hasFP || files[0].fp != want || files[0].size != int64(len(content)) {
		t.Fatalf("NUL/hex framing changed evidence: %+v", files)
	}
	asContainerRoot(t, data, `mkfifo /w/logs/cells/opaque-cell/archive-g1-123/logs/unsupported`)
	if _, err := helper.SSHInventory(context.Background(), root); err == nil {
		t.Fatal("FIFO inventory was marked complete")
	}
	asContainerRoot(t, data, `rm /w/logs/cells/opaque-cell/archive-g1-123/logs/unsupported
ln /w/logs/cells/opaque-cell/archive-g1-123/logs/uid-1001/* /w/logs/cells/opaque-cell/archive-g1-123/logs/hard-link`)
	if _, err := helper.SSHInventory(context.Background(), root); err == nil {
		t.Fatal("multiply linked evidence inventory was marked complete")
	}
}

// TestDockerHelperMakesLogsWritable: a log the honeypot created as its own
// user is one QPot may not write, so the disk guard can keep no room beyond
// its end. The helper makes it writable, the log then gets its room, and
// nothing else changes: not the log's content, not a log that was not named,
// and nothing a planted link leads to outside the folder.
func TestDockerHelperMakesLogsWritable(t *testing.T) {
	dockerTest(t)
	cfg := testInstance(t)
	data := cfg.DataPath
	t.Cleanup(func() {
		asContainerRoot(t, data, fmt.Sprintf("chown -R %d:%d /w", os.Getuid(), os.Getgid()))
	})
	keep := put(t, cfg, "outside/keep", 4096, 0)
	if err := os.Chmod(keep, 0o600); err != nil {
		t.Fatal(err)
	}
	asContainerRoot(t, data, `
h=/w/honeypots/dionaea
mkdir -p "$h/logs/folder.log"
echo '{"e":1}' > "$h/logs/dionaea.json"
echo '{"e":2}' > "$h/logs/other.json"
ln -s "$OUTSIDE" "$h/logs/abs-link.log"
ln -s ../../../outside/keep "$h/logs/rel-link.log"
mkfifo "$h/logs/fifo.log"
chown -R 2000:2000 "$h"
chmod 0755 "$h" "$h/logs"
chmod 0640 "$h/logs/dionaea.json" "$h/logs/other.json"
`, "OUTSIDE="+keep)
	logs := filepath.Join(data, "honeypots", "dionaea", "logs")
	log := filepath.Join(logs, "dionaea.json")
	writable := func(p string) bool {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return false
		}
		_ = f.Close()
		return true
	}
	if writable(log) {
		t.Fatal("the honeypot's log is writable before the helper ran: the test shows nothing")
	}
	opt := diskguard.LogRoomOptions{Preferred: []string{"dionaea.json"}}
	res, err := diskguard.KeepLogRoom(logs, opt)
	if err != nil || !strings.Contains(strings.Join(res.Denied, " "), "dionaea.json") || len(res.Kept) != 0 {
		t.Fatalf("before the helper: denied %v, kept %v, %v; want dionaea.json denied", res.Denied, res.Kept, err)
	}
	h := &DockerHelper{Image: instance.CollectorImage}
	if err := h.MakeWritable(context.Background(), logs,
		[]string{"dionaea.json", "abs-link.log", "rel-link.log", "fifo.log", "folder.log", "missing.log"}); err != nil {
		t.Fatal(err)
	}
	if !writable(log) {
		t.Fatal("the helper left the honeypot's log unwritable")
	}
	if info, err := os.Stat(log); err != nil || info.Mode().Perm() != 0o662 {
		t.Errorf("the log's mode is %v (%v), want 0662: writable by all, readable by whom it was", info.Mode().Perm(), err)
	}
	if writable(filepath.Join(logs, "other.json")) {
		t.Error("a log that was not named became writable")
	}
	if info, err := os.Stat(keep); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("a planted link led the helper to a file outside the folder: %v, %v", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(filepath.Join(logs, "folder.log")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("a folder named like a log was changed: %v, %v", info.Mode().Perm(), err)
	}
	res, err = diskguard.KeepLogRoom(logs, opt)
	if err != nil || len(res.Kept) != 1 || res.Kept[0] != "dionaea.json" {
		t.Fatalf("after the helper: kept %v, denied %v, failed %v, %v; want dionaea.json kept", res.Kept, res.Denied, res.Failed, err)
	}
	// QPot may write the log now and still not read it; what it holds is
	// read as its owner would.
	asContainerRoot(t, data, `[ "$(cat /w/honeypots/dionaea/logs/dionaea.json)" = '{"e":1}' ]`)
	info, err := os.Stat(log)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != int64(len("{\"e\":1}\n")) {
		t.Errorf("the log's size changed: %d bytes", info.Size())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Blocks*512 < diskguard.LogRoom {
		t.Errorf("the log holds %d bytes of blocks, want its room of %d", st.Blocks*512, diskguard.LogRoom)
	}
}

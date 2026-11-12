package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// cowrieJSONLogHarness runs the patched output plugin in the Cowrie image,
// with the image's own Twisted, against a log folder on a filesystem of 256
// kB that it fills and frees. It prints one JSON object.
const cowrieJSONLogHarness = `
import json, os, sys
from twisted.internet import reactor
import cowrie.output.jsonlog as jsonlog

LOG = "/log/cowrie.json"
result = {}

# A spill file that fits the test's small filesystem.
jsonlog.QPOT_SPILL_BYTES = 16384

def new_output():
    out = jsonlog.Output.__new__(jsonlog.Output)
    out.start()
    return out

def event(n):
    return {"eventid": "cowrie.session.connect", "n": n, "pad": "x" * 100, "time": 1.0, "log_x": 1, "system": "s"}

def fill():
    # Take every byte the filesystem has left.
    with open("/log/filler", "wb", buffering=0) as f:
        for size in (4096, 1):
            try:
                while True:
                    f.write(b"\0" * size)
            except OSError:
                pass

out = new_output()
for n in range(50):
    out.write(event(n))
fill()
errors = 0
for n in range(50, 250):
    try:
        out.write(event(n))
    except Exception as e:  # the plugin must never raise into Cowrie
        errors += 1
result["raised_while_full"] = errors
result["waiting_while_full"] = len(getattr(out, "qpot_pending", ()))
with open(LOG, "rb") as f:
    held = f.read()
result["whole_lines_while_full"] = held.count(b"\n")

def freed():
    try:
        os.remove("/log/filler")
    except FileNotFoundError:
        pass

def finish():
    result["waiting_after_retry"] = len(getattr(out, "qpot_pending", ()))
    for n in range(250, 260):
        try:
            out.write(event(n))
        except Exception:
            pass
    out.stop()
    # A log left ending in part of a line, as after a kill on a full disk.
    with open(LOG, "ab") as f:
        f.write(b'{"eventid":"torn","n":"to')
    again = new_output()
    again.write(event(260))
    again.stop()
    reactor.stop()

# The plugin's own timer must write the backlog once there is room.
reactor.callLater(0.5, freed)
reactor.callLater(3.5, finish)
reactor.run()

# Stopped on a full disk. Room comes a second later (QPot's disk guard frees
# its reserve once the disk has stopped filling, which can be after it has
# told Cowrie to stop): stop() waits for it and writes what it holds.
import threading, time
late = new_output()
fill()
# More than the log's last page still has room for, which a full disk takes.
for n in range(261, 301):
    try:
        late.write(event(n))
    except Exception:
        pass
result["waiting_at_stop"] = len(getattr(late, "qpot_pending", ()))
room = threading.Timer(1.0, freed)
room.start()
began = time.monotonic()
try:
    late.stop()
except Exception:
    pass
result["stop_seconds"] = round(time.monotonic() - began, 2)
room.join()
result["waiting_after_stop"] = len(getattr(late, "qpot_pending", ()))
# On a disk that stays full it stops waiting and writes what it holds into
# the spill file, which needs no new block; the next start puts those lines
# into the log before anything new.
jsonlog.QPOT_STOP_WAIT_SECONDS = 0.5
stuck = new_output()
fill()
for _ in range(40):  # again more than the last page's room
    try:
        stuck.write(event(999))
    except Exception:
        pass
began = time.monotonic()
try:
    stuck.stop()
except Exception:
    pass
result["gave_up_seconds"] = round(time.monotonic() - began, 2)
result["waiting_when_gave_up"] = len(getattr(stuck, "qpot_pending", ()))
freed()
def spill_start():
    try:
        with open("/log/spill", "rb") as f:
            return f.read(1)
    except OSError:
        return None  # the image's own plugin has no such file
result["spill_holds_lines"] = spill_start() not in (None, b"\0")
# The next start: whatever part of a line the disk took is ended, as any torn
# line is, and the spilled lines follow.
last = new_output()
last.write(event(301))
last.stop()
result["spill_empty_again"] = spill_start() == b"\0"

lines = open(LOG, "rb").read().split(b"\n")
result["ends_in_newline"] = lines[-1] == b""
numbers, unreadable = [], []
for line in lines[:-1]:
    try:
        numbers.append(json.loads(line)["n"])
    except Exception:
        unreadable.append(line.decode("utf-8", "replace"))
# The 40 events written to a disk that stayed full: all there, once each,
# before the event of the start that followed.
result["stuck_kept"] = numbers.count(999)
result["stuck_before_next"] = numbers[-1:] == [301]
numbers = [n for n in numbers if n != 999]
result["numbers_in_order"] = numbers == list(range(302))
result["count"] = len(numbers)
result["unreadable"] = unreadable
result["legacy_keys_removed"] = b"log_x" not in b"".join(lines) and b'"system"' not in b"".join(lines)
print(json.dumps(result))
`

// TestCowrieJSONLogSurvivesAFullDiskLive: with the image's own output plugin a
// full disk cut lines short or lost them while Cowrie went on serving. The
// patched plugin must hold every event while the disk takes nothing, never
// raise, never leave part of a line between whole ones, and write the backlog
// in order by itself once there is room.
func TestCowrieJSONLogSurvivesAFullDiskLive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a Linux Docker engine with tmpfs mounts")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker not available")
	}
	image := GetHoneypotImage("cowrie")
	if exec.Command(docker, "image", "inspect", image).Run() != nil {
		t.Skip("cowrie image not present locally")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"jsonlog.py": cowrieJSONLogPy, "harness.py": []byte(cowrieJSONLogHarness)} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(plugin, logtype string) (map[string]any, string) {
		t.Helper()
		args := []string{"run", "--rm", "--network", "none", "--tmpfs", "/log:size=256k,mode=1777",
			"-e", "COWRIE_HONEYPOT_LOGTYPE=" + logtype, "-e", "COWRIE_OUTPUT_JSONLOG_LOGFILE=/log/cowrie.json",
			"-e", "COWRIE_OUTPUT_JSONLOG_QPOT_SPILL=/log/spill",
			"-v", filepath.Join(dir, "harness.py") + ":/harness.py:ro"}
		if plugin != "" {
			args = append(args, "-v", plugin+":"+cowrieSource+"/output/jsonlog.py:ro")
		}
		out, err := exec.Command(docker, append(args, "--entrypoint", "python3", image, "/harness.py")...).CombinedOutput()
		text := strings.TrimSpace(string(out))
		last := text[strings.LastIndexByte(text, '\n')+1:]
		var res map[string]any
		if err != nil || json.Unmarshal([]byte(last), &res) != nil {
			return nil, text
		}
		return res, text
	}
	// Both kinds of log file Cowrie has; it accepts no third. An instance
	// runs with the plain one. A patch that covers only the other protects
	// nothing, as the first version of this one did (found by the failure
	// soak).
	for _, logtype := range []string{"plain", "rotating"} {
		res, text := run(filepath.Join(dir, "jsonlog.py"), logtype)
		if res == nil {
			t.Fatalf("%s: the harness did not finish:\n%s", logtype, text)
		}
		t.Logf("%s, patched plugin: %v", logtype, res)
		want := map[string]any{"raised_while_full": 0.0, "waiting_after_retry": 0.0, "ends_in_newline": true,
			"numbers_in_order": true, "count": 302.0, "legacy_keys_removed": true, "waiting_after_stop": 0.0,
			"stuck_kept": 40.0, "stuck_before_next": true, "spill_holds_lines": true, "spill_empty_again": true}
		for k, v := range want {
			if res[k] != v {
				t.Errorf("%s: %s = %v, want %v", logtype, k, res[k], v)
			}
		}
		if waiting, _ := res["waiting_while_full"].(float64); waiting < 150 {
			t.Errorf("%s: only %v events waited in memory while the disk was full: the filesystem was not full, so this run proves nothing", logtype, res["waiting_while_full"])
		}
		// Stopped on a full disk: lines waited, stop() waited about the
		// second it took for room to come; on a disk that stayed full it
		// stopped waiting after the half second it was given and kept the
		// lines in its spill file (checked above: all 40 are in the log
		// after the next start).
		if waiting, _ := res["waiting_at_stop"].(float64); waiting < 10 {
			t.Errorf("%s: only %v events waited when Cowrie was stopped on a full disk", logtype, res["waiting_at_stop"])
		}
		if took, _ := res["stop_seconds"].(float64); took < 0.7 || took > 4 {
			t.Errorf("%s: stopping took %v s, want about the 1 s until there was room", logtype, res["stop_seconds"])
		}
		if took, _ := res["gave_up_seconds"].(float64); took < 0.4 || took > 3 {
			t.Errorf("%s: on a disk that stayed full stopping took %v s, want about the 0.5 s it was given", logtype, res["gave_up_seconds"])
		}
		if waiting, _ := res["waiting_when_gave_up"].(float64); waiting < 10 {
			t.Errorf("%s: %v events waited when it gave up on a disk that stayed full; the disk was not full", logtype, res["waiting_when_gave_up"])
		}
		// The unreadable lines are the torn one the harness planted and,
		// when the disk took part of it, the start of the event written to a
		// disk that stayed full: each ended by a newline, so that the next
		// event has a line of its own.
		lines, _ := res["unreadable"].([]any)
		planted := false
		for _, line := range lines {
			text, _ := line.(string)
			switch {
			case text == `{"eventid":"torn","n":"to` && !planted:
				planted = true
			case text != "" && strings.HasPrefix(`{"eventid":"cowrie.session.connect","n":999,"pad":"`+strings.Repeat("x", 100)+`"}`, text):
			default:
				t.Errorf("%s: unreadable line %q is neither the planted torn line nor the start of the event a full disk cut", logtype, text)
			}
		}
		if !planted || len(lines) > 2 {
			t.Errorf("%s: unreadable lines: %v, want the planted torn line and at most one cut event", logtype, lines)
		}

		// Negative control: the image's own plugin on the same full disk
		// loses events (it raises, cuts a line or drops them), so the
		// harness detects what the patch is for.
		stock, text := run("", logtype)
		if stock == nil {
			t.Fatalf("%s: the harness did not finish with the image's own plugin:\n%s", logtype, text)
		}
		t.Logf("%s, the image's own plugin on the same disk: %v", logtype, stock)
		if stock["numbers_in_order"] == true {
			t.Errorf("%s: the image's own plugin also kept every event in order: the harness does not fill the disk, so the run above proves nothing", logtype)
		}
	}
}

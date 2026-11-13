package instance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/diskguard"
)

// fullDiskTarget is one honeypot as the full-disk harness runs it: the
// profile QPot deploys, the port a visitor connects to, what the visitor
// sends, and the log the visitor's events go to.
type fullDiskTarget struct {
	name    string
	profile honeypotDeploy
	port    int
	payload string // hex
	logFile string // in the logs volume
	json    bool
	// connectEvent, when set, is the event type the honeypot logs once per
	// connection. Conpot keeps one session per source address and logs
	// the first connection's port with every later one, so its visitors
	// are counted by these events instead of by port.
	connectEvent string
}

// fullDiskTargets are the honeypots QPot enables by default (Cowrie, which
// holds lines itself, has its own test: cowrie_jsonlog_live_test.go) and the
// two industrial and malware honeypots most often added.
func fullDiskTargets() []fullDiskTarget {
	return []fullDiskTarget{
		{name: "endlessh", profile: deployProfile(nil, "endlessh"), port: 2222, logFile: "endlessh.log"},
		{name: "conpot", profile: deployProfile(conpotConfig("qp_fulldisktest", "IEC104"), "conpot"), port: 2404,
			payload: "680407000000", logFile: "conpot.json", json: true, connectEvent: "NEW_CONNECTION"},
		{name: "dionaea", profile: deployProfile(nil, "dionaea"), port: 21, payload: fmt.Sprintf("%x", "QUIT\r\n"),
			logFile: "dionaea.json", json: true},
	}
}

// fullDiskClient makes n connections from consecutive source ports, each
// sending the payload and reading the reply for a moment, as a visitor that
// connects, says one thing and leaves. It prints the source ports whose
// connection was accepted.
const fullDiskClient = `
import json, socket, sys, time
port, first, n, payload = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), bytes.fromhex(sys.argv[4])
ok = []
for i in range(n):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", first + i))
        s.settimeout(2)
        s.connect(("127.0.0.1", port))
        ok.append(first + i)
        if payload:
            s.sendall(payload)
        s.settimeout(0.3)
        try:
            s.recv(512)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        s.close()
    time.sleep(0.05)
print(json.dumps(ok))
`

// fullDiskLogPort finds the visitor's source port in a log line: endlessh
// writes port=N, Conpot and Dionaea a src_port field.
var fullDiskLogPort = regexp.MustCompile(`(?:"src_port"\s*:\s*"?|\bport=)(\d+)`)

// fullDiskResult is what one run left in the log.
type fullDiskResult struct {
	Scenario       string
	Room           bool
	Before         []int // connections accepted with room on the disk
	Full           []int // accepted while the disk was full
	After          []int // accepted after room came back
	KeptBefore     int   // of Before, with an event in the log at the end
	KeptFull       int
	KeptAfter      int
	Unreadable     []string // lines that are not one whole event
	PartialOnDisk  bool     // the log ended inside a line while the disk was full
	StateWhileFull string   // the container's state then
	Errors         int      // lines of the container's output that report a full disk
	Twice          int      // lines that are in the log more than once
	Counted        string   // how the visitors were counted, when not by port
}

func (r fullDiskResult) String() string {
	return fmt.Sprintf("%s, room %v: kept %d/%d before, %d/%d while full, %d/%d after; line cut on the full disk %v; container %s while full; full-disk errors in its output %d; unreadable lines %d %q; repeated lines %d %s",
		r.Scenario, r.Room, r.KeptBefore, len(r.Before), r.KeptFull, len(r.Full), r.KeptAfter, len(r.After),
		r.PartialOnDisk, r.StateWhileFull, r.Errors, len(r.Unreadable), r.Unreadable, r.Twice, r.Counted)
}

// fillDisk writes a file into dir until the filesystem takes no more byte.
func fillDisk(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, size := range []int{1 << 20, 4096, 1} {
		chunk := make([]byte, size)
		for {
			if _, err := f.Write(chunk); err != nil {
				break
			}
		}
	}
	_ = f.Sync()
}

// runFullDisk runs the honeypot with its logs on the small filesystem under
// fs, lets visitors connect, fills the filesystem, lets more connect, and then
// either frees the disk while the honeypot runs ("freed") or, as the disk
// guard does, stops it on the full disk, frees the disk and starts it again
// ("stopped"). With room, QPot's start creates the honeypot's logs and the
// guard keeps room beyond their end, as an instance does.
func runFullDisk(t *testing.T, fs string, target fullDiskTarget, scenario string, room bool) fullDiskResult {
	t.Helper()
	image := GetHoneypotImage(target.name)
	client := GetHoneypotImage("cowrie")
	name := fmt.Sprintf("qpot-fulldisk-%s-%d", target.name, time.Now().UnixNano())
	res := fullDiskResult{Scenario: scenario, Room: room}
	docker := func(timeout time.Duration, args ...string) string {
		t.Helper()
		out, err := conpotLiveDocker(timeout, args...)
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(args[:min(3, len(args))], " "), err, out)
		}
		return out
	}
	logs := filepath.Join(fs, name)
	filler := filepath.Join(fs, ".filler-"+name)
	if err := os.MkdirAll(logs, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(logs, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := conpotLiveDocker(10*time.Second, "logs", "--tail", "40", name)
			t.Logf("%s container output:\n%s", target.name, out)
		}
		_, _ = conpotLiveDocker(30*time.Second, "rm", "-f", name)
		_ = os.Remove(filler)
		_ = os.RemoveAll(logs)
	})
	if room {
		if err := ensureHoneypotLogs(logs, target.profile.Logs); err != nil {
			t.Fatal(err)
		}
	}
	keepRoom := func() {
		t.Helper()
		if !room {
			return
		}
		res, err := diskguard.KeepLogRoom(logs, diskguard.LogRoomOptions{Preferred: target.profile.Logs})
		if err != nil || len(res.Denied)+len(res.Failed) > 0 || !slices.Contains(res.Kept, target.logFile) {
			t.Fatalf("keep room beyond the logs: %+v, %v", res, err)
		}
	}

	root := t.TempDir()
	args := []string{"run", "-d", "--name", name, "--network", "none", "--read-only",
		"--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
		"--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:rw,mode=1777", "--tmpfs", "/run:rw,mode=1777",
		"--tmpfs", "/var/tmp:rw,mode=1777", "--memory", "512m"}
	if target.profile.NeedsNetBind() || target.name == "conpot" {
		args = append(args, "--cap-add", "NET_BIND_SERVICE")
	}
	for _, mount := range target.profile.Tmpfs {
		args = append(args, "--tmpfs", mount)
	}
	for _, mount := range target.profile.Volumes {
		if mount.ContainerPath == "" {
			continue
		}
		path := filepath.Join(root, mount.HostSubdir)
		if mount.HostSubdir == "logs" {
			path = logs
		} else if mount.File {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mount.Content, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		} else if err := os.MkdirAll(path, 0o777); err != nil {
			t.Fatal(err)
		}
		bind := "type=bind,src=" + path + ",dst=" + mount.ContainerPath
		if mount.ReadOnly {
			bind += ",readonly"
		}
		args = append(args, "--mount", bind)
	}
	for _, d := range target.profile.ContainerDirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	// Writable for the image's user, whatever host user made them.
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(path, 0o777)
		}
		return nil
	})
	for key, value := range target.profile.Env {
		args = append(args, "-e", key+"="+value)
	}
	args = append(args, image)
	if target.name == "conpot" {
		args = append(args, "/bin/sh", "-c", conpotStartScript())
	}

	probes := 0
	running := func() string {
		out, _ := conpotLiveDocker(10*time.Second, "inspect", name, "--format", "{{.State.Status}}")
		return strings.TrimSpace(out)
	}
	connect := func(first, n int) []int {
		t.Helper()
		out, err := conpotLiveDocker(2*time.Minute, "run", "--rm", "--network", "container:"+name, "--entrypoint", "python3", client,
			"-c", fullDiskClient, strconv.Itoa(target.port), strconv.Itoa(first), strconv.Itoa(n), target.payload)
		if err != nil {
			if running() != "running" {
				return nil // the honeypot stopped itself: nobody was let in
			}
			t.Fatalf("client: %v\n%s", err, out)
		}
		var ports []int
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ports); err != nil {
			t.Fatalf("client output: %v\n%s", err, out)
		}
		return ports
	}
	ready := func() {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for probe := 30000; time.Now().Before(deadline); probe++ {
			if len(connect(probe, 1)) == 1 {
				probes++
				// The listener is up; give the honeypot a moment to finish
				// starting the rest.
				time.Sleep(2 * time.Second)
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s did not start listening on %d", target.name, target.port)
	}

	docker(time.Minute, args...)
	ready()
	res.Before = connect(40000, 5)
	time.Sleep(2 * time.Second)
	keepRoom() // the guard's tick
	fillDisk(t, filler)
	// More than a log's last block has room for: a page of slack hides a
	// full disk from a few lines.
	res.Full = connect(41000, 100)
	time.Sleep(time.Second)
	res.StateWhileFull = running()
	if data, err := os.ReadFile(filepath.Join(logs, target.logFile)); err == nil && len(data) > 0 {
		res.PartialOnDisk = data[len(data)-1] != '\n'
	}
	switch scenario {
	case "freed":
		if err := os.Remove(filler); err != nil {
			t.Fatal(err)
		}
		time.Sleep(3 * time.Second)
		if running() != "running" {
			// It stopped itself on the full disk. Docker starts it again
			// (restart: on-failure in an instance's compose).
			docker(time.Minute, "start", name)
			ready()
		}
		res.After = connect(42000, 5)
	case "stopped":
		docker(time.Minute, "stop", "-t", "10", name)
		if err := os.Remove(filler); err != nil {
			t.Fatal(err)
		}
		docker(time.Minute, "start", name)
		ready()
		res.After = connect(42000, 5)
	default:
		t.Fatalf("unknown scenario %q", scenario)
	}
	// Endlessh logs a CLOSE only when it next tries to send, which is after
	// its delay of up to 14 seconds.
	time.Sleep(16 * time.Second)
	docker(time.Minute, "stop", "-t", "10", name)
	output, _ := conpotLiveDocker(30*time.Second, "logs", name)
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "No space left") || strings.Contains(line, "Errno 28") {
			res.Errors++
		}
	}
	data, err := os.ReadFile(filepath.Join(logs, target.logFile))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	lines := map[string]int{}
	connections := 0
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if bytes.IndexByte([]byte(line), 0) >= 0 {
			res.Unreadable = append(res.Unreadable, "(NUL bytes)")
			continue
		}
		if target.json {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) != nil {
				res.Unreadable = append(res.Unreadable, fullDiskShort(line))
				continue
			}
		} else if fields := strings.Fields(line); len(fields) < 2 || !strings.HasPrefix(fields[0], "20") {
			res.Unreadable = append(res.Unreadable, fullDiskShort(line))
			continue
		}
		lines[line]++
		if target.connectEvent != "" && strings.Contains(line, `"`+target.connectEvent+`"`) {
			connections++
		}
		if m := fullDiskLogPort.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			seen[port] = true
		}
	}
	kept := func(ports []int) int {
		n := 0
		for _, p := range ports {
			if seen[p] {
				n++
			}
		}
		return n
	}
	res.KeptBefore, res.KeptFull, res.KeptAfter = kept(res.Before), kept(res.Full), kept(res.After)
	if target.connectEvent != "" {
		// Counted, not matched: the connections logged beyond the ready
		// probes and the visitors before and after are the full disk's.
		res.KeptBefore, res.KeptAfter = len(res.Before), len(res.After)
		res.KeptFull = min(max(connections-probes-len(res.Before)-len(res.After), 0), len(res.Full))
		res.Counted = fmt.Sprintf("%d %s events for %d connections", connections, target.connectEvent, probes+len(res.Before)+len(res.Full)+len(res.After))
	}
	for _, count := range lines {
		if count > 1 {
			res.Twice++
		}
	}
	return res
}

func fullDiskShort(line string) string {
	if len(line) > 80 {
		return line[:80] + "..."
	}
	return line
}

// TestHoneypotLogRoomOnAFullDiskLive: the honeypots QPot runs on T-Pot's own
// images lose what they log on a disk that fills at once (endlessh drops
// lines, Dionaea keeps them in memory and loses them when it is stopped,
// Conpot stops itself), and cut a line in two, which gives the collector two
// identities for one event. With QPot's room beyond the end of each log
// (diskguard.KeepLogRoom), every event of a visitor on the full disk is in
// the log, whole, whether the disk is freed while the honeypot runs or the
// honeypot is stopped first as the disk guard does.
//
// The run without room is the negative control: it must show a loss, a cut
// line, a stop or a write the honeypot reports as failed, or the filesystem
// was not full and the run with room proves nothing.
//
// QPOT_FULLDISK_DIR is a folder on a small filesystem of its own (tens of
// MB, ext4), writable by the test's user; the test fills it.
func TestHoneypotLogRoomOnAFullDiskLive(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("QPOT_TEST_DOCKER") != "1" {
		t.Skip("set QPOT_TEST_DOCKER=1 on Linux with the honeypot images pulled")
	}
	fs := os.Getenv("QPOT_FULLDISK_DIR")
	if fs == "" {
		t.Skip("set QPOT_FULLDISK_DIR to a folder on a small filesystem of its own")
	}
	only := os.Getenv("QPOT_FULLDISK_ONLY")
	for _, target := range fullDiskTargets() {
		if only != "" && !slices.Contains(strings.Split(only, ","), target.name) {
			continue
		}
		t.Run(target.name, func(t *testing.T) {
			if out, err := conpotLiveDocker(15*time.Second, "image", "inspect", GetHoneypotImage(target.name)); err != nil {
				t.Fatalf("pull %s first: %v\n%s", GetHoneypotImage(target.name), err, out)
			}
			if !slices.Contains(target.profile.Logs, target.logFile) {
				t.Fatalf("%s: QPot does not create %s, so it gets no room", target.name, target.logFile)
			}
			for _, scenario := range []string{"freed", "stopped"} {
				stock := runFullDisk(t, fs, target, scenario, false)
				t.Logf("%s %v", target.name, stock)
				// Dionaea keeps what it could not write in memory and writes it
				// once there is room, if it runs that long: then it loses
				// nothing, but says that its writes failed.
				if stock.KeptFull == len(stock.Full) && len(stock.Full) > 0 && !stock.PartialOnDisk &&
					len(stock.Unreadable) == 0 && stock.StateWhileFull == "running" && stock.Errors == 0 {
					t.Errorf("%s, %s: without room no write failed: the filesystem was not full, so the run with room proves nothing", target.name, scenario)
				}
				kept := runFullDisk(t, fs, target, scenario, true)
				t.Logf("%s %v", target.name, kept)
				if kept.StateWhileFull != "running" {
					t.Errorf("%s, %s: the honeypot was %s on the full disk", target.name, scenario, kept.StateWhileFull)
				}
				if len(kept.Full) < 90 || kept.KeptFull != len(kept.Full) || kept.KeptBefore != len(kept.Before) ||
					kept.KeptAfter != len(kept.After) || len(kept.After) == 0 {
					t.Errorf("%s, %s: with room, events are missing", target.name, scenario)
				}
				if kept.PartialOnDisk || len(kept.Unreadable) > 0 || kept.Errors > 0 || kept.Twice > 0 {
					t.Errorf("%s, %s: with room, a line was cut, unreadable or written twice, or the honeypot reported a full disk", target.name, scenario)
				}
			}
		})
	}
}

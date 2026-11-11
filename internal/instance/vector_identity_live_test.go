package instance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
	"github.com/qpot/qpot/internal/vectorstate"
)

// runVectorUntil runs Vector on a config that reads files (so it never ends by
// itself), until done reports true or limit passes, and then stops it the way
// `docker stop` stops the collector: with a signal Vector shuts down on, so its
// checkpoints are written.
func runVectorUntil(t *testing.T, run []string, cfgPath string, limit time.Duration, done func() bool) {
	t.Helper()
	args := append([]string(nil), run[1:]...)
	name := ""
	if len(args) > 0 && args[0] == "run" {
		name = fmt.Sprintf("qpot-vectest-%d", time.Now().UnixNano())
		args = append([]string{"run", "--name", name}, args[1:]...)
	}
	cmd := exec.Command(run[0], append(args, "--quiet", "--config", cfgPath)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start vector: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	stop := func() {
		if name != "" {
			_ = exec.Command(run[0], "stop", "-t", "10", name).Run()
		} else if cmd.Process.Signal(os.Interrupt) != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-exited:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	deadline := time.Now().Add(limit)
	for !done() {
		select {
		case err := <-exited:
			t.Fatalf("vector ended by itself: %v\n%s", err, stderr.String())
		case <-time.After(200 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			stop()
			t.Fatalf("vector did not get there in %s\n%s", limit, stderr.String())
		}
	}
	stop()
}

// TestVectorEventIdentityLive reads real files with the generated file source
// and the generated remap, and checks what an event's ID stands for: one
// written line. Reviewed defect: the ID was a hash of the file path and the
// line's text, so two separate visits that wrote the same line into the same
// file were one event to everything keyed by ID.
//
// Cases: equal lines in one file; a restart that keeps its
// checkpoints (nothing is read again); a collector that lost its checkpoints
// (everything is read again and gets the SAME IDs, which is what lets the
// second copies be found and removed); a rotated log whose new file repeats an
// old line at another offset.
func TestVectorEventIdentityLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)

	cfg := config.Default("vec-ident")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	hp := cfg.Honeypots["cowrie"]
	hp.Enabled = true
	cfg.Honeypots["cowrie"] = hp
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	var vc struct {
		Sources    map[string]map[string]any `yaml:"sources"`
		Transforms map[string]struct {
			Source string `yaml:"source"`
		} `yaml:"transforms"`
	}
	if err := yaml.Unmarshal([]byte(out), &vc); err != nil {
		t.Fatal(err)
	}
	source := vc.Sources[vectorstate.HoneypotSource("cowrie")]
	remap := vc.Transforms["add_qpot_metadata"].Source
	if source == nil || remap == "" {
		t.Fatal("the generated config lacks the cowrie source or add_qpot_metadata")
	}
	if source["offset_key"] != "qpot_offset" {
		t.Fatalf("the cowrie source has offset_key %v", source["offset_key"])
	}
	// The generated source, reading the test's folder instead of /data.
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"include", "exclude"} {
		list, _ := source[key].([]any)
		for i, p := range list {
			list[i] = strings.Replace(fmt.Sprint(p), "/data/honeypots/cowrie/logs", logs, 1)
		}
	}
	writeConfig := func(tag string) (cfgPath, outPath string) {
		outPath = filepath.Join(dir, "out-"+tag+".json")
		harness := map[string]any{
			"data_dir":   filepath.Join(dir, "state-"+tag),
			"sources":    map[string]any{"in": source},
			"transforms": map[string]any{"t": map[string]any{"type": "remap", "inputs": []string{"in"}, "source": remap}},
			"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"t"},
				"path": outPath, "encoding": map[string]any{"codec": "json"}}},
		}
		hb, err := yaml.Marshal(harness)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "state-"+tag), 0o755); err != nil {
			t.Fatal(err)
		}
		cfgPath = filepath.Join(dir, "vector-"+tag+".yaml")
		if err := os.WriteFile(cfgPath, hb, 0o644); err != nil {
			t.Fatal(err)
		}
		return cfgPath, outPath
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, tag := range []string{"a", "b"} {
			b, _ := os.ReadFile(filepath.Join(dir, "out-"+tag+".json"))
			t.Logf("out-%s.json: %s", tag, b)
		}
	})
	type row struct {
		EventID string `json:"event_id"`
		Command string `json:"command"`
		Offset  any    `json:"qpot_offset"`
	}
	read := func(path string) []row {
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		var rows []row
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for sc.Scan() {
			var r row
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				return nil // a line still being written
			}
			rows = append(rows, r)
		}
		return rows
	}
	appendLines := func(name string, lines ...string) {
		f, err := os.OpenFile(filepath.Join(logs, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	// settled waits for n events and then a little longer, so one too many
	// shows.
	settled := func(path string, n int) func() bool {
		var since time.Time
		return func() bool {
			if len(read(path)) < n {
				return false
			}
			if since.IsZero() {
				since = time.Now()
			}
			return time.Since(since) > 2*time.Second
		}
	}
	ids := func(rows []row) map[string]int {
		m := map[string]int{}
		for _, r := range rows {
			m[r.EventID]++
		}
		return m
	}

	const (
		login = `{"eventid":"cowrie.login.failed","username":"root","password":"123456","src_ip":"203.0.113.9","session":"s1","timestamp":"2026-11-02T05:09:25.000000Z"}`
		cmdID = `{"eventid":"cowrie.command.input","input":"id","src_ip":"203.0.113.9","session":"s1","timestamp":"2026-11-02T05:09:26.000000Z"}`
	)
	// Two equal lines and one other.
	appendLines("cowrie.json", login, login, cmdID)

	cfgA, outA := writeConfig("a")
	runVectorUntil(t, run, cfgA, 90*time.Second, settled(outA, 3))
	first := read(outA)
	if len(first) != 3 {
		t.Fatalf("%d events came out of 3 lines: %+v", len(first), first)
	}
	for _, r := range first {
		if !eventUUID.MatchString(r.EventID) {
			t.Errorf("event ID %q is not a version 8 UUID", r.EventID)
		}
		if r.Offset != nil {
			t.Errorf("the offset field stayed on the event: %v", r.Offset)
		}
	}
	if got := ids(first); len(got) != 3 {
		t.Fatalf("3 written lines got %d different IDs (equal lines must not share one): %v", len(got), got)
	}

	// A restart with its checkpoints: only the new line is read.
	appendLines("cowrie.json", `{"eventid":"cowrie.command.input","input":"uname -a","src_ip":"203.0.113.9","session":"s1","timestamp":"2026-11-02T05:09:27.000000Z"}`)
	runVectorUntil(t, run, cfgA, 90*time.Second, settled(outA, 4))
	second := read(outA)
	if len(second) != 4 || len(ids(second)) != 4 {
		t.Fatalf("after a restart with checkpoints there are %d events with %d IDs, want 4 and 4", len(second), len(ids(second)))
	}

	// A collector without its checkpoints reads everything again: the same
	// four lines must get the same four IDs.
	cfgB, outB := writeConfig("b")
	runVectorUntil(t, run, cfgB, 90*time.Second, settled(outB, 4))
	again := read(outB)
	if len(again) != 4 {
		t.Fatalf("a collector without checkpoints read %d of 4 lines", len(again))
	}
	want := ids(second)
	for id := range ids(again) {
		if want[id] != 1 {
			t.Errorf("a line read again got ID %s, which its first reading did not have", id)
		}
	}

	// Rotation: the old file moves away, the new one starts with another line
	// and then repeats the old file's first line, at another offset.
	if err := os.Rename(filepath.Join(logs, "cowrie.json"), filepath.Join(logs, "cowrie.json.2026-11-02")); err != nil {
		t.Fatal(err)
	}
	appendLines("cowrie.json", `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.77","session":"s9","timestamp":"2026-11-03T00:00:01.000000Z"}`, login)
	runVectorUntil(t, run, cfgA, 90*time.Second, settled(outA, 6))
	rotated := read(outA)
	if len(rotated) != 6 || len(ids(rotated)) != 6 {
		t.Fatalf("after rotation there are %d events with %d IDs, want 6 and 6 (a repeated line in the new file is a new observation)", len(rotated), len(ids(rotated)))
	}
}

// TestVectorMarksSharedSourceLive: a source address inside one of the
// instance's own Docker networks is Docker's, not a visitor's, and the event
// must say so. Any other address, private ones included (a honeypot on an
// internal network sees real private sources), must not be marked, and a log
// line cannot set or clear the mark.
func TestVectorMarksSharedSourceLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)
	cfg := config.Default("vec-shared")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	hp := cfg.Honeypots["cowrie"]
	hp.Enabled = true
	cfg.Honeypots["cowrie"] = hp
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	gen := &ComposeGenerator{Config: cfg, Sandbox: sb}
	own := gen.OwnSubnets()
	if len(own) == 0 {
		t.Fatal("the instance has no Docker subnets of its own")
	}
	out, err := gen.GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, subnet := range own {
		if !strings.Contains(out, `ip_cidr_contains("`+subnet+`", sip)`) {
			t.Errorf("the collector does not check sources against the instance's subnet %s", subnet)
		}
	}
	var vc struct {
		Transforms map[string]struct {
			Source string `yaml:"source"`
		} `yaml:"transforms"`
	}
	if err := yaml.Unmarshal([]byte(out), &vc); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.json")
	harness := map[string]any{
		"data_dir": dir,
		"sources":  map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": map[string]any{
			"split": map[string]any{"type": "remap", "inputs": []string{"in"},
				"source": "parts = split(string!(.message), \"\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
			"t": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": vc.Transforms["add_qpot_metadata"].Source},
		},
		"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"t"},
			"path": outPath, "encoding": map[string]any{"codec": "json"}}},
	}
	hb, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(cfgPath, hb, 0o644); err != nil {
		t.Fatal(err)
	}
	// The gateway of the first own subnet: x.y.z.0/24 -> x.y.z.1.
	gateway := strings.TrimSuffix(strings.SplitN(own[0], "/", 2)[0], "0") + "1"
	const file = "/data/honeypots/cowrie/logs/cowrie.json\t"
	in := strings.Join([]string{
		file + `{"eventid":"cowrie.command.input","input":"one","src_ip":"` + gateway + `","session":"s1"}`,
		file + `{"eventid":"cowrie.command.input","input":"two","src_ip":"203.0.113.9","session":"s2"}`,
		file + `{"eventid":"cowrie.command.input","input":"three","src_ip":"192.168.1.5","session":"s3"}`,
		file + `{"eventid":"cowrie.command.input","input":"four","src_ip":"203.0.113.9","session":"s4","source_shared":"docker","metadata":{"source_shared":"docker"}}`,
		file + `{"eventid":"cowrie.command.input","input":"five","src_ip":"::ffff:` + gateway + `","session":"s5","source_shared":"","metadata":{"source_shared":""}}`,
	}, "\n") + "\n"
	cmd := exec.Command(run[0], append(run[1:], "--quiet", "--config", cfgPath)...)
	cmd.Stdin = strings.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("vector failed: %v\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("no output: %v\n%s", err, stderr.String())
	}
	want := map[string]string{"one": "docker", "two": "", "three": "", "four": "", "five": "docker"}
	seen := 0
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var r struct {
			Command  string            `json:"command"`
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad output line %q: %v", line, err)
		}
		seen++
		if got := r.Metadata["source_shared"]; got != want[r.Command] {
			t.Errorf("event %q: source_shared = %q, want %q", r.Command, got, want[r.Command])
		}
	}
	if seen != len(want) {
		t.Fatalf("%d of %d events came out:\n%s", seen, len(want), raw)
	}
}

// TestVectorCellRecordIDSurvivesArchiveLive: a HiFi cell's record file moves
// from current/ to an archive folder when the cell is reset. Found by the HiFi
// capture soak: one command in 1,356 was stored twice, with two IDs, because
// the collector was killed after delivering its line and read it again under
// the archive path. The ID must not depend on which of the two folders the
// file is in, and must still tell cells and other files apart.
func TestVectorCellRecordIDSurvivesArchiveLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cfg := config.Default("vec-cell")
	cfg.DataPath = filepath.Join(t.TempDir(), "instance")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	for _, name := range []string{"cowrie", sshProxyHoneypot} {
		hp := cfg.Honeypots[name]
		hp.Enabled = true
		cfg.Honeypots[name] = hp
	}
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&ComposeGenerator{Config: cfg, Sandbox: sb}).GenerateVectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	var vc struct {
		Transforms map[string]struct {
			Source string `yaml:"source"`
		} `yaml:"transforms"`
	}
	if err := yaml.Unmarshal([]byte(out), &vc); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.json")
	harness := map[string]any{
		"data_dir": dir,
		"sources":  map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": map[string]any{
			"split": map[string]any{"type": "remap", "inputs": []string{"in"},
				"source": "parts = split(string!(.message), \"\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
			"t": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": vc.Transforms["add_qpot_metadata"].Source},
		},
		"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"t"},
			"path": outPath, "encoding": map[string]any{"codec": "json"}}},
	}
	hb, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(cfgPath, hb, 0o644); err != nil {
		t.Fatal(err)
	}
	record := func(input string) string {
		return `{"timestamp":"2026-11-12T03:30:00Z","event_type":"ssh_backend_command_start","phase":"start","session":"abc","peer_ip":"203.0.113.9","src_ip":"203.0.113.9","src_port":40000,"username":"root","uid":0,"input":"` + input + `"}`
	}
	const cells = "/data/honeypots/ssh-proxy/logs/cells/"
	const cowrieLine = `{"eventid":"cowrie.command.input","input":"COMMAND","src_ip":"203.0.113.9","session":"s1"}`
	in := strings.Join([]string{
		cells + "ssh-backend-1/current/uid-0/20261112T033000Z-abc.json\t" + record("live"),
		cells + "ssh-backend-1/archive-g7-AbC_d-9/logs/uid-0/20261112T033000Z-abc.json\t" + record("live"),
		cells + "ssh-backend-2/current/uid-0/20261112T033000Z-abc.json\t" + record("live"),
		cells + "ssh-backend-1/current/uid-0/20261112T033000Z-def.json\t" + record("live"),
		// Outside the cells nothing is left out of the ID.
		"/data/honeypots/cowrie/logs/current/cowrie.json\t" + strings.Replace(cowrieLine, "COMMAND", "plain", 1),
		"/data/honeypots/cowrie/logs/archive-g7-a/logs/cowrie.json\t" + strings.Replace(cowrieLine, "COMMAND", "plain", 1),
	}, "\n") + "\n"
	cmd := exec.Command(run[0], append(run[1:], "--quiet", "--config", cfgPath)...)
	cmd.Stdin = strings.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("vector failed: %v\n%s", err, stderr.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("no output: %v\n%s", err, stderr.String())
	}
	var ids []string
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var r struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(line, &r); err != nil || !eventUUID.MatchString(r.EventID) {
			t.Fatalf("bad output line %q: %v", line, err)
		}
		ids = append(ids, r.EventID)
	}
	if len(ids) != 6 {
		t.Fatalf("%d of 6 events came out:\n%s", len(ids), raw)
	}
	if ids[0] != ids[1] {
		t.Errorf("the same record has ID %s in current/ and %s in its archive", ids[0], ids[1])
	}
	if ids[2] == ids[0] {
		t.Error("the same file name in another cell got the same ID")
	}
	if ids[3] == ids[0] {
		t.Error("another record file of the cell got the same ID")
	}
	if ids[4] == ids[5] {
		t.Error("outside the cells, a folder named like an archive was left out of the ID")
	}
}

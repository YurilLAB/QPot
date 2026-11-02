package instance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// vectorRunner returns a command prefix that runs Vector, or skips the test.
// It uses a local `vector` binary, else the collector image if it is already
// present (never pulls).
func vectorRunner(t *testing.T, dir string) []string {
	t.Helper()
	if p, err := exec.LookPath("vector"); err == nil {
		return []string{p}
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("neither vector nor docker available")
	}
	const img = "timberio/vector:latest-alpine"
	if exec.Command(docker, "image", "inspect", img).Run() != nil {
		t.Skip("vector image not present locally")
	}
	return []string{docker, "run", "--rm", "-i", "-v", dir + ":" + dir, img}
}

// TestVectorRemapLive runs the generated add_qpot_metadata remap through the
// real Vector binary with log lines in each honeypot's actual format and checks
// the normalised columns the intelligence worker classifies on.
func TestVectorRemapLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)

	cfg := config.Default("vec-live")
	cfg.QPotID = "qp_vectorvectorvectorvecto"
	for _, n := range []string{"cowrie", "endlessh", "dionaea", "conpot", "heralding", "adbhoney"} {
		hp := cfg.Honeypots[n]
		hp.Enabled = true
		cfg.Honeypots[n] = hp
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
		t.Fatalf("generated vector config is not YAML: %v", err)
	}
	src := vc.Transforms["add_qpot_metadata"].Source
	if src == "" {
		t.Fatal("add_qpot_metadata has no source")
	}

	// Harness: stdin lines are "<file path>\t<log line>"; split them back into
	// the .file/.message pair the file source would produce.
	harness := map[string]any{
		"data_dir": dir,
		"sources":  map[string]any{"in": map[string]any{"type": "stdin"}},
		"transforms": map[string]any{
			"split": map[string]any{"type": "remap", "inputs": []string{"in"},
				"source": "parts = split(string!(.message), \"\\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
			"t": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": src},
		},
		"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"t"},
			"path": filepath.Join(dir, "out.json"), "encoding": map[string]any{"codec": "json"}}},
	}
	hb, err := yaml.Marshal(harness)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(cfgPath, hb, 0o644); err != nil {
		t.Fatal(err)
	}

	in := strings.Join([]string{
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.session.connect","src_ip":"203.0.113.9","src_port":55632,"dst_ip":"172.20.0.2","dst_port":22,"session":"s1","protocol":"ssh"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.login.failed","username":"root","password":"123456","src_ip":"203.0.113.9","session":"s1","protocol":"ssh"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"uname -a","src_ip":"203.0.113.9","session":"s1","protocol":"ssh"}`,
		// Hostile/odd shapes: injected file/classification keys, wrong types,
		// out-of-range port, IPv4-mapped address.
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"id","src_ip":"::ffff:198.51.100.7","src_port":"70000","file":"/data/honeypots/evil/x","technique_id":"T9999","classified":1,"event_id":"not-a-uuid","metadata":[1],"username":{"a":1}}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.login.failed","src_ip":"not-an-ip"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t{broken",
		"/data/honeypots/cowrie/logs/cowrie.log\t2026-11-02 05:09:25 [-] Ready to accept SSH connections",
		"/data/honeypots/endlessh/logs/endlessh.log\t2026-11-02T05:28:07.311Z ACCEPT host=::ffff:203.0.113.10 port=44688 fd=4 n=1/4096",
		"/data/honeypots/endlessh/logs/endlessh.log\t2026-11-02T05:26:53.114Z Port 2222",
		"/data/honeypots/dionaea/logs/dionaea.json\t" + `{"connection":{"protocol":"smbd","transport":"tcp","type":"accept"},"dst_port":445,"src_ip":"203.0.113.11","src_port":39812}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"data_type":"http","src_ip":"203.0.113.12","src_port":1,"dst_port":80,"request":"GET /","event_type":null}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"data_type":"modbus","src_ip":"203.0.113.12","dst_port":502,"event_type":"NEW_CONNECTION"}`,
		"/data/honeypots/heralding/logs/log_session.json\t" + `{"source_ip":"203.0.113.13","source_port":43128,"destination_port":21,"protocol":"ftp","num_auth_attempts":1,"auth_attempts":[{"username":"admin","password":"hunter2"}]}`,
		"/data/honeypots/adbhoney/logs/adbhoney.json\t" + `{"eventid":"adbhoney.session.connect","src_ip":"203.0.113.14","src_port":34434,"dest_port":"5555"}`,
	}, "\n") + "\n"

	cmd := exec.Command(run[0], append(run[1:], "--quiet", "--config", cfgPath)...)
	cmd.Stdin = strings.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("vector failed: %v\n%s", err, stderr.String())
	}

	f, err := os.Open(filepath.Join(dir, "out.json"))
	if err != nil {
		t.Fatalf("no output: %v\n%s", err, stderr.String())
	}
	defer f.Close()
	type row struct {
		Honeypot   string            `json:"honeypot"`
		EventType  string            `json:"event_type"`
		SourceIP   string            `json:"source_ip"`
		SourcePort int               `json:"source_port"`
		DestPort   int               `json:"dest_port"`
		Protocol   string            `json:"protocol"`
		Username   string            `json:"username"`
		Password   string            `json:"password"`
		Command    string            `json:"command"`
		Payload    string            `json:"payload"`
		Metadata   map[string]string `json:"metadata"`
		Technique  *string           `json:"technique_id"`
		Classified any               `json:"classified"`
		EventID    any               `json:"event_id"`
		QPotID     string            `json:"qpot_id"`
	}
	var rows []row
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad output line %q: %v", sc.Text(), err)
		}
		rows = append(rows, r)
	}
	// 14 input lines: broken JSON, cowrie.log chatter and endlessh's banner
	// line must be dropped.
	if len(rows) != 11 {
		t.Fatalf("got %d events, want 11: %+v", len(rows), rows)
	}

	r := rows[0]
	if r.Honeypot != "cowrie" || r.EventType != "cowrie.session.connect" || r.SourceIP != "203.0.113.9" ||
		r.SourcePort != 55632 || r.DestPort != 22 || r.Protocol != "ssh" || r.Metadata["session"] != "s1" || r.QPotID != cfg.QPotID {
		t.Errorf("cowrie connect: %+v", r)
	}
	if r := rows[1]; r.Username != "root" || r.Password != "123456" || r.EventType != "cowrie.login.failed" {
		t.Errorf("cowrie login: %+v", r)
	}
	if r := rows[2]; r.Command != "uname -a" {
		t.Errorf("cowrie command input not mapped to command: %+v", r)
	}
	if r := rows[3]; r.Honeypot != "cowrie" || r.SourceIP != "198.51.100.7" || r.SourcePort != 0 ||
		r.Technique != nil || r.Classified != nil || r.EventID != nil || r.Username != "" || r.Command != "id" {
		t.Errorf("hostile cowrie line not sanitised: %+v", r)
	}
	if r := rows[4]; r.SourceIP != "0.0.0.0" {
		t.Errorf("invalid src_ip not replaced: %+v", r)
	}
	if r := rows[5]; r.Honeypot != "endlessh" || r.EventType != "endlessh.connection.accept" || r.SourceIP != "203.0.113.10" || r.SourcePort != 44688 {
		t.Errorf("endlessh: %+v", r)
	}
	if r := rows[6]; r.EventType != "dionaea.connection.accept" || r.Protocol != "smbd" || r.DestPort != 445 {
		t.Errorf("dionaea: %+v", r)
	}
	if r := rows[7]; r.EventType != "conpot.http.probe" || r.Payload != "GET /" || r.Protocol != "http" {
		t.Errorf("conpot http: %+v", r)
	}
	if r := rows[8]; r.EventType != "conpot.modbus.new_connection" {
		t.Errorf("conpot modbus: %+v", r)
	}
	if r := rows[9]; r.EventType != "heralding.login.failed" || r.Username != "admin" || r.Password != "hunter2" ||
		r.SourceIP != "203.0.113.13" || r.DestPort != 21 {
		t.Errorf("heralding: %+v", r)
	}
	if r := rows[10]; r.DestPort != 5555 || r.SourcePort != 34434 {
		t.Errorf("adbhoney: %+v", r)
	}
}

// TestVectorConfigValidatesLive runs `vector validate` over the full generated
// collector config for each backend, with and without the NSM sensors, so an
// option the real sink/transform does not accept fails here instead of
// crash-looping the collector container.
func TestVectorConfigValidatesLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)
	for _, db := range []string{"clickhouse", "timescaledb"} {
		for _, sensors := range []bool{false, true} {
			out := genVectorCfg(t, func(c *config.Config) {
				c.Database.Type = db
				for _, n := range []string{"endlessh", "dionaea", "conpot", "heralding", "adbhoney"} {
					hp := c.Honeypots[n]
					hp.Enabled = true
					c.Honeypots[n] = hp
				}
				c.Collector.IngestSuricata = sensors
				c.Collector.IngestP0f = sensors
				c.Collector.IngestFatt = sensors
			})
			out = strings.Replace(out, `data_dir: "/var/lib/vector"`, `data_dir: "`+dir+`"`, 1)
			path := filepath.Join(dir, db+".yaml")
			if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(run[0], append(run[1:], "validate", "--no-environment", path)...)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s (sensors=%v): vector validate failed: %v\n%s", db, sensors, err, b)
			}
		}
	}
}

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
	for _, n := range []string{"cowrie", "endlessh", "dionaea", "conpot", "heralding", "adbhoney",
		"tanner", "dicompot", "ddospot", "hellpot", "log4pot", "citrixhoneypot", "galah", "mailoney",
		"redishoneypot", "go-pot", "beelzebub", "ciscoasa", "sentrypeer", "wordpot", "medpot"} {
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
		// Honeypots with their own field names (T-Pot 24.04.2 formats).
		"/data/honeypots/tanner/logs/tanner_report.json\t" + `{"method":"GET","path":"/wp-login.php","peer":{"ip":"203.0.113.20","port":40112},"status":200,"uuid":"u1"}`,
		"/data/honeypots/dicompot/logs/dicompot.log\t" + `{"ID":"1","IP":"203.0.113.21","Port":"52800","level":"warning","msg":"Connection from","time":"2026-11-02 08:46:24"}`,
		"/data/honeypots/dicompot/logs/dicompot.log\t" + `{"ID":"1","Status":"Finished","level":"warning","msg":"Connection","time":"2026-11-02 08:46:34"}`,
		"/data/honeypots/ddospot/logs/targets.log\t" + `{"dest_port":53,"dns_name":"example.com.","event":"attack_start","pot":"dns","proto":"udp","target_ip":"203.0.113.22","target_port":52840}`,
		"/data/honeypots/hellpot/logs/hellpot.log\t" + `{"level":"info","USERAGENT":"x","REMOTE_ADDR":"203.0.113.23","URL":"/.env","time":"2026-11-02T08:47:50Z","message":"NEW"}`,
		"/data/honeypots/hellpot/logs/hellpot.log\t" + `{"level":"info","caller":"0.0.0.0:8080","message":"Listening and serving HTTP..."}`,
		"/data/honeypots/log4pot/logs/log4pot.log\t" + `{"reason": "request", "server_port": 8080, "client": "203.0.113.24", "port": 42458, "request": "GET /?x=${jndi:ldap://a/b} HTTP/1.1"}`,
		"/data/honeypots/log4pot/logs/log4pot.log\t" + `{"reason": "start", "timestamp": "2026-11-02T08:15:14.894487"}`,
		"/data/honeypots/citrixhoneypot/logs/server.log\t" + `{"asctime": "2026-11-02 08:15:24,516", "levelname": "INFO", "message": "(203.0.113.25:51234): GET /vpn/../vpns/cfg/smb.conf"}`,
		"/data/honeypots/galah/logs/galah.json\t" + `{"dest_port":"8080","msg":"successfulResponse","request.method":"GET","request.requestURI":"/admin","src_ip":"203.0.113.26","src_port":"39202"}`,
		"/data/honeypots/mailoney/logs/log.json\t" + `{"dest_port":25,"event.type":"session","smtp_input":"HELO x\nAUTH LOGIN","src_ip":"203.0.113.27","src_port":34714}`,
		"/data/honeypots/redishoneypot/logs/redishoneypot.log\t" + `{"message":"command","event":"command","protocol":"redis","src_ip":"203.0.113.28","src_port":37198,"dest_port":6379,"command":"CONFIG","args_text":"SET dir /tmp"}`,
		"/data/honeypots/go-pot/logs/go-pot.json\t" + `{"msg":"","status":"200","src_ip":"203.0.113.29","method":"GET","path":"/admin/login.php","qs":"user=root","dest_port":"80"}`,
		"/data/honeypots/beelzebub/logs/beelzebub.json\t" + `{"command":"uname -a","dest_port":"22","msg":"New SSH Session","protocol":"SSH","src_ip":"203.0.113.30","src_port":"55688"}`,
		"/data/honeypots/ciscoasa/logs/ciscoasa.json\t" + `{"event_type":"error","src_ip":"203.0.113.31","src_port":40596,"dest_port":8443,"protocol":"tcp","payload":""}`,
		"/data/honeypots/sentrypeer/logs/sentrypeer.json\t" + `{"source_ip":"203.0.113.32:5061","transport_type":"UDP","sip_method":"OPTIONS"}`,
		"/data/honeypots/wordpot/logs/profile-state.json\t" + `{"pid": 1, "profile_count": 4, "profile_id": "maintenance-lag"}`,
		"/data/honeypots/medpot/logs/medpot.log\t" + `{"level":"info","message":"Connection found","src_port":"44462","src_ip":"203.0.113.33","data":"TVNIfA=="}`,
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
	// 32 input lines: broken JSON, cowrie.log chatter, endlessh's banner line
	// and the lines without an attacker address (dicompot's finished line,
	// hellpot's/log4pot's startup lines, wordpot's profile state) must be
	// dropped.
	if len(rows) != 25 {
		t.Fatalf("got %d events, want 25: %+v", len(rows), rows)
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

	want := []struct {
		hp, ip   string
		sp, dp   int
		et       string
		proto    string
		cmd, pay string
	}{
		{"tanner", "203.0.113.20", 40112, 80, "tanner.http.get", "http", "", "/wp-login.php"},
		{"dicompot", "203.0.113.21", 52800, 11112, "dicompot.connection_from", "", "", ""},
		{"ddospot", "203.0.113.22", 52840, 53, "ddospot.dns.attack_start", "udp", "", "example.com."},
		{"hellpot", "203.0.113.23", 0, 80, "hellpot.new", "http", "", "/.env"},
		{"log4pot", "203.0.113.24", 42458, 8080, "log4pot.request", "http", "", "GET /?x=${jndi:ldap://a/b} HTTP/1.1"},
		{"citrixhoneypot", "203.0.113.25", 51234, 443, "citrixhoneypot.http.request", "https", "", "GET /vpn/../vpns/cfg/smb.conf"},
		{"galah", "203.0.113.26", 39202, 8080, "galah.successfulresponse", "http", "", "/admin"},
		{"mailoney", "203.0.113.27", 34714, 25, "mailoney.session", "smtp", "HELO x\nAUTH LOGIN", ""},
		{"redishoneypot", "203.0.113.28", 37198, 6379, "redishoneypot.command", "redis", "CONFIG SET dir /tmp", ""},
		{"go-pot", "203.0.113.29", 0, 80, "go-pot.http.get", "http", "", "/admin/login.php?user=root"},
		{"beelzebub", "203.0.113.30", 55688, 22, "beelzebub.new_ssh_session", "ssh", "uname -a", ""},
		{"ciscoasa", "203.0.113.31", 40596, 8443, "ciscoasa.error", "tcp", "", ""},
		{"sentrypeer", "203.0.113.32", 5061, 5060, "sentrypeer.sip.options", "sip", "", ""},
		{"medpot", "203.0.113.33", 44462, 2575, "medpot.connection_found", "", "", ""},
	}
	for i, w := range want {
		r := rows[11+i]
		if r.Honeypot != w.hp || r.SourceIP != w.ip || r.SourcePort != w.sp || r.DestPort != w.dp ||
			r.EventType != w.et || r.Protocol != w.proto || r.Command != w.cmd || r.Payload != w.pay {
			t.Errorf("%s:\n got %+v\nwant %+v", w.hp, r, w)
		}
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

// Edge configurations that used to render a config Vector rejects (so the
// collector crash-looped and nothing was collected): no honeypot enabled
// (with and without sensors), and probe blocking on with an empty probe list.
func TestVectorEdgeConfigsValidateLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)
	cases := map[string]func(c *config.Config){
		"no-honeypots-with-sensors": func(c *config.Config) {
			for name, hp := range c.Honeypots {
				hp.Enabled = false
				c.Honeypots[name] = hp
			}
			c.Collector.IngestSuricata = true
		},
		"nothing-to-collect": func(c *config.Config) {
			for name, hp := range c.Honeypots {
				hp.Enabled = false
				c.Honeypots[name] = hp
			}
			c.Collector.IngestSuricata, c.Collector.IngestP0f, c.Collector.IngestFatt = false, false, false
		},
		"empty-probe-list": func(c *config.Config) {
			c.Stealth.BlockCommonProbes = true
			c.Stealth.BlockedProbes = nil
		},
	}
	for name, mut := range cases {
		out := genVectorCfg(t, mut)
		if strings.Contains(out, "!()") {
			t.Errorf("%s: empty VRL expression rendered", name)
		}
		out = strings.Replace(out, `data_dir: "/var/lib/vector"`, `data_dir: "`+dir+`"`, 1)
		path := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		if b, err := exec.Command(run[0], append(run[1:], "validate", "--no-environment", path)...).CombinedOutput(); err != nil {
			t.Errorf("%s: vector validate failed: %v\n%s", name, err, b)
		}
	}
}

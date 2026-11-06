package instance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qpot/qpot/internal/canary"
)

// sshHarness runs the patch layer's ssh.py outside Cowrie: Cowrie's command
// base class, its filesystem and event log are stubbed with a fake tree of the
// files the test passes (path -> base64), qpot_bait.py is the real module.
// For each case (args, home, cwd) it prints the events ssh dispatched and the
// paths it read. Mode "fuzz" instead feeds public_key() mutated key files.
const sshHarness = `
import base64, json, posixpath, random, sys, time, types, importlib.util
bait_path, ssh_path, mode, spec_path = sys.argv[1:5]
class Logger:
    def info(self, *a, **k): pass
    def warn(self, *a, **k): pass
    def failure(self, *a, **k): pass
for name in ("twisted", "twisted.logger", "cowrie", "cowrie.core", "cowrie.core.config", "cowrie.shell",
             "cowrie.shell.command", "cowrie.shell.fs"):
    sys.modules[name] = types.ModuleType(name)
sys.modules["twisted.logger"].Logger = Logger
class CowrieConfig:
    @staticmethod
    def get(section, key, fallback=None):
        return fallback
sys.modules["cowrie.core.config"].CowrieConfig = CowrieConfig
class HoneyPotCommand:
    pass
sys.modules["cowrie.shell.command"].HoneyPotCommand = HoneyPotCommand
sys.modules["cowrie.shell.fs"].A_SIZE = 4
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
bait = load("cowrie.core.qpot_bait", bait_path)
sys.modules["cowrie.core"].qpot_bait = bait
spec = json.load(open(spec_path))
if mode == "fuzz":
    rnd = random.Random(spec["seed"])
    seeds = [base64.b64decode(s) for s in spec["files"]]
    worst, found = 0.0, 0
    for i in range(spec["n"]):
        data = bytearray(rnd.choice(seeds))
        for _ in range(rnd.randint(1, 8)):
            op = rnd.randint(0, 4)
            pos = rnd.randrange(len(data) + 1)
            if op == 0 and data:
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            elif op == 1:
                data[pos:pos] = bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 16)))
            elif op == 2:
                del data[pos:pos + rnd.randint(1, 64)]
            elif op == 3:
                data[pos:pos] = rnd.choice([b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----END OPENSSH PRIVATE KEY-----",
                                            b"ssh-ed25519 ", b"\xff\xff\xff\xff", b"=" * 50, b"A" * 70000])
            else:
                data = data * rnd.randint(1, 40)
            del data[200000:]
        data = bytes(data)
        t0 = time.perf_counter()
        blob = bait.public_key(data)
        worst = max(worst, time.perf_counter() - t0)
        if blob is not None:
            assert isinstance(blob, bytes) and bait.key_type(blob), blob
            found += 1
    print(json.dumps({"worst": worst, "found": found}))
    sys.exit(0)
ssh = load("ssh_cmd", ssh_path)
files = {p: base64.b64decode(v) for p, v in spec["files"].items()}
reads = []
class FS:
    def resolve_path(self, path, cwd):
        return posixpath.normpath(posixpath.join(cwd, path))
    def exists(self, path):
        return path in files or any(p.startswith(path.rstrip("/") + "/") for p in files)
    def isdir(self, path):
        return path not in files and self.exists(path)
    def getfile(self, path):
        return [posixpath.basename(path), 2, 0, 0, len(files[path]), 0o100600, 0, None, None, None] if path in files else None
    def file_contents(self, path):
        reads.append(path)
        return files[path]
events = []
class Events:
    def dispatch(self, eventid, fmt, **fields):
        events.append(dict(fields, eventid=eventid))
out = []
for case in spec["cases"]:
    events.clear(); reads.clear()
    cmd = ssh.Command_ssh.__new__(ssh.Command_ssh)
    cmd.args = case["args"]
    cmd.environ = {"HOME": case.get("home", "/root")}
    cmd.cwd = case.get("cwd", "/root")
    cmd.fs = FS()
    cmd.protocol = types.SimpleNamespace(events=Events(), user=types.SimpleNamespace(username="root"))
    import getopt
    optlist, args = getopt.getopt(case["args"], "-1246AaCfgKkMNnqsTtVvXxYb:c:D:e:F:i:L:l:m:O:o:p:R:S:w:")
    user, host = "root", args[0]
    for opt in optlist:
        if opt[0] == "-l":
            user = opt[1]
    if "@" in args[0]:
        user, host = args[0].split("@", 1)
    cmd.qpot_log_identities(optlist, user, host)
    out.append({"events": list(events), "reads": list(reads)})
print(json.dumps(out))
`

type sshEvent struct {
	EventID     string `json:"eventid"`
	Realm       string `json:"realm"`
	Username    string `json:"username"`
	Host        string `json:"host"`
	Identity    string `json:"identity"`
	Fingerprint string `json:"fingerprint"`
	Key         string `json:"key"`
	Input       string `json:"input"`
}

type sshCase struct {
	Args []string `json:"args"`
	Home string   `json:"home,omitempty"`
	Cwd  string   `json:"cwd,omitempty"`
}

func runSSHHarness(t *testing.T, py, mode string, spec any) []byte {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(py, write("harness.py", []byte(sshHarness)), write("qpot_bait.py", cowrieQPotBaitPy),
		write("ssh.py", cowrieSSHPy), mode, write("spec.json", specJSON))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	return out
}

// sshString is an SSH wire string.
func sshString(b []byte, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// TestSSHLogsTheKeysItWouldOffer: ssh on the honeypot logs the public key of
// every identity file it would offer (-i, -o IdentityFile, the IdentityFile of
// the matching Host of ~/.ssh/config or -F, else the default files), so the
// planted key used from the box (ssh -i ~/.ssh/id_ed25519 backup@db01, the
// way SSH-Snake and Kinsing's spre.sh use the keys they find) trips its
// canary: the event carries its MD5 fingerprint and blob. Anything that is no
// key, a key file too large and identity files past the cap are not read.
func TestSSHLogsTheKeysItWouldOffer(t *testing.T) {
	py := python(t)
	key := canary.NewDeriver("ssh-harness").Ed25519Key("root-key")
	blob := canary.Ed25519PublicBlob(key.Public().(ed25519.PublicKey))
	priv := canary.MarshalEd25519PrivateKey(key, "backup@corp", 7)
	pub := canary.AuthorizedKey(blob, "backup@corp") + "\n"
	fp := canary.MD5Fingerprint(blob)
	other := canary.NewDeriver("ssh-harness").Ed25519Key("other")
	otherBlob := canary.Ed25519PublicBlob(other.Public().(ed25519.PublicKey))
	// an encrypted OpenSSH key: its public half is still in the clear
	enc := []byte("openssh-key-v1\x00")
	enc = sshString(enc, []byte("aes256-ctr"))
	enc = sshString(enc, []byte("bcrypt"))
	enc = sshString(enc, sshString(binary.BigEndian.AppendUint32(nil, 16), make([]byte, 16)))
	enc = binary.BigEndian.AppendUint32(enc, 1)
	enc = sshString(enc, otherBlob)
	enc = sshString(enc, make([]byte, 160))
	encFile := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.StdEncoding.EncodeToString(enc) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	config := "Host db01\n    HostName 10.9.8.7\n    User backup\n    IdentityFile ~/.ssh/id_ed25519\n\n" +
		"Host bk*\n  IdentityFile=/srv/keys/%r_%h\n\nHost *\n    ConnectTimeout 10\n"
	files := map[string]string{
		"/root/.ssh/id_ed25519":     b64(string(priv)),
		"/root/.ssh/id_ed25519.pub": b64(pub),
		"/root/.ssh/config":         b64(config),
		"/srv/keys/dumps_bk1":       b64(encFile),
		"/tmp/pem":                  b64("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"),
		"/tmp/pem2":                 b64("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"),
		"/tmp/pem2.pub":             b64(pub),
		"/tmp/huge":                 b64(string(priv) + strings.Repeat("#", 70000)),
		"/tmp/garbage":              b64("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA////\n-----END OPENSSH PRIVATE KEY-----\n"),
		"/home/u/.ssh/id_rsa.pub":   b64("ssh-rsa AAAA not-base64!\n"),
	}
	many := []string{}
	for i := 0; i < 40; i++ {
		many = append(many, "-i", "/tmp/k"+strings.Repeat("x", i))
	}
	cases := []sshCase{
		{Args: []string{"-o", "BatchMode=yes", "-i", "/root/.ssh/id_ed25519", "backup@10.9.8.7", "id"}},
		{Args: []string{"db01", "hostname"}},
		{Args: []string{"-p", "2222", "web7"}},               // no IdentityFile: the default files
		{Args: []string{"-i", ".ssh/id_ed25519.pub", "x@y"}}, // relative to the cwd, a .pub given
		{Args: []string{"dumps@bk1"}},                        // %r and %h of the config; an encrypted key
		{Args: []string{"-o", "IdentityFile=/tmp/pem", "a@b"}},
		{Args: []string{"-oIdentityFile /tmp/pem2", "a@b"}},
		{Args: []string{"-i", "/tmp/huge", "-i", "/tmp/garbage", "-i", "/nope", "a@b"}},
		{Args: append(many, "a@b")},
		{Args: []string{"-F", "/root/.ssh/config", "-i", "/root/.ssh/id_ed25519", "db01"}, Home: "/home/u"},
		{Args: []string{"web7"}, Home: "/home/u"}, // the user has no key
	}
	raw := runSSHHarness(t, py, "cases", map[string]any{"files": files, "cases": cases})
	var got []struct {
		Events []sshEvent `json:"events"`
		Reads  []string   `json:"reads"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	want := []struct {
		fps      []string
		user     string
		identity string
	}{
		{[]string{fp}, "backup", "/root/.ssh/id_ed25519"},
		{[]string{fp}, "root", "/root/.ssh/id_ed25519"},
		{[]string{fp}, "root", "/root/.ssh/id_ed25519"},
		{[]string{fp}, "x", "/root/.ssh/id_ed25519.pub"},
		{[]string{canary.MD5Fingerprint(otherBlob)}, "dumps", "/srv/keys/dumps_bk1"},
		{nil, "", ""},
		{[]string{fp}, "a", "/tmp/pem2"},
		{nil, "", ""},
		{nil, "", ""},
		{[]string{fp}, "root", "/root/.ssh/id_ed25519"},
		{nil, "", ""},
	}
	for i, w := range want {
		ev := got[i].Events
		var fps []string
		for _, e := range ev {
			fps = append(fps, e.Fingerprint)
			if e.EventID != "cowrie.credentials.use" || e.Realm != "ssh" || e.Username != w.user || e.Identity != w.identity ||
				!strings.HasPrefix(e.Input, "ssh ") {
				t.Errorf("case %d %v: event %+v", i, cases[i].Args, e)
			}
			if e.Fingerprint == fp && e.Key != "ssh-ed25519 "+base64.StdEncoding.EncodeToString(blob) {
				t.Errorf("case %d: key %q", i, e.Key)
			}
		}
		if strings.Join(fps, ",") != strings.Join(w.fps, ",") {
			t.Errorf("case %d %v: fingerprints %v, want %v", i, cases[i].Args, fps, w.fps)
		}
	}
	for _, p := range got[7].Reads {
		if p == "/tmp/huge" {
			t.Error("a key file larger than the cap was read")
		}
	}
	if n := len(got[8].Reads); n > 2*8 {
		t.Errorf("40 identity files given: %d reads", n)
	}
}

// TestPublicKeyOfMutatedFiles: public_key() on thousands of mutated key files
// (bytes flipped, inserted, cut; armor lines and huge runs spliced in) never
// raises, returns only well-formed blobs and stays fast in Cowrie's reactor.
func TestPublicKeyOfMutatedFiles(t *testing.T) {
	py := python(t)
	key := canary.NewDeriver("ssh-fuzz").Ed25519Key("k")
	blob := canary.Ed25519PublicBlob(key.Public().(ed25519.PublicKey))
	seeds := []string{
		base64.StdEncoding.EncodeToString(canary.MarshalEd25519PrivateKey(key, "c", 1)),
		base64.StdEncoding.EncodeToString([]byte(canary.AuthorizedKey(blob, "c") + "\n")),
		base64.StdEncoding.EncodeToString([]byte("from=\"10.0.0.1\" " + canary.AuthorizedKey(blob, "x") + "\n")),
	}
	raw := runSSHHarness(t, py, "fuzz", map[string]any{"files": seeds, "seed": 7, "n": 3000})
	var res struct {
		Worst float64 `json:"worst"`
		Found int     `json:"found"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if res.Worst > 0.05 {
		t.Errorf("public_key took %.3f s on one input", res.Worst)
	}
	if res.Found == 0 {
		t.Error("no mutated file still read as a key: the mutations or the parser are off")
	}
	t.Logf("worst %.4f s, %d of 3000 still a key", res.Worst, res.Found)
}

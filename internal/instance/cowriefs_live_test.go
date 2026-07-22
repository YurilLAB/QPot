package instance

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCowrieFsPatchServesContentLive is the end-to-end proof that the generated
// fs-patch script actually makes content SERVEABLE the way Cowrie serves it. It
// runs the REAL generated Python against a base pickle shaped like Cowrie's
// (root -> /home/phil+dotfiles, /etc/{passwd,shadow}, /proc/sys/kernel/* as
// empty size-0 nodes, /var/lib) and then applies a faithful reimplementation of
// Cowrie's file_contents() (verified against the pinned shell/fs.py: content is
// served from the node's realfile, NEVER from inline node content) to assert:
//   - ~/.bash_history / ~/.bashrc / ~/.ssh return their real bytes (the bug that
//     made inline-content histories a silent no-op is fixed),
//   - the per-instance system files (machine-id, shadow, /proc/sys/kernel/*) are
//     served with the expected content,
//   - the stock /home/phil (no /etc/passwd account) is removed while the persona
//     users remain,
//   - /etc/shadow's hash for a user actually verifies against that user's login
//     password (crack-back consistency).
//
// If QPOT_TEST_FS_PICKLE points at a real Cowrie fs.pickle the test uses it;
// otherwise it builds a faithful synthetic base. Skipped when python3 is absent.
func TestCowrieFsPatchServesContentLive(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.pickle")

	if real := os.Getenv("QPOT_TEST_FS_PICKLE"); real != "" {
		b, err := os.ReadFile(real)
		if err != nil {
			t.Fatalf("QPOT_TEST_FS_PICKLE unreadable: %v", err)
		}
		if err := os.WriteFile(basePath, b, 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		runPy(t, py, dir, "build.py", buildBasePy, basePath)
	}

	seed := "livetest"
	// jump-bastion: 4 human users (admin/ansible/jumpuser/bastion) AND a root login.
	persona, ok := credentialTemplateByName("jump-bastion")
	if !ok {
		t.Fatal("jump-bastion persona missing")
	}
	hostname := hostnameForPersona(persona, seed)
	profile := profileForSeed(seed)
	files := append(cowrieHomeFiles(persona, seed),
		embeddedSystemFiles(persona, profile, hostname, seed)...)
	script := cowrieFsPatchScript(files, personaHomeNames(persona, seed))

	// Repoint the hardcoded container paths at this test's temp dirs.
	outPath := filepath.Join(dir, "out.pickle")
	realDir := filepath.Join(dir, "qpotfs")
	script = strings.ReplaceAll(script, `BASE = "/home/cowrie/cowrie/src/cowrie/data/fs.pickle"`, "BASE = "+strconv.Quote(basePath))
	script = strings.ReplaceAll(script, `OUT = "/tmp/cowrie/fs.pickle"`, "OUT = "+strconv.Quote(outPath))
	script = strings.ReplaceAll(script, `REALDIR = "/tmp/cowrie/qpotfs"`, "REALDIR = "+strconv.Quote(realDir))

	if out := runPy(t, py, dir, "patch.py", script); strings.Contains(out, "qpot fs patch failed") {
		t.Fatalf("patch script hit its error fallback:\n%s", out)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("patch produced no output pickle: %v", err)
	}

	// Serve the paths through Cowrie's real file_contents semantics.
	served := serve(t, py, dir, outPath,
		"/home/admin/.bash_history",
		"/home/admin/.bashrc",
		"/home/admin/.ssh/authorized_keys",
		"/home/admin/.ssh/config",
		"/root/.bash_history",
		"/etc/machine-id",
		"/etc/shadow",
		"/proc/sys/kernel/hostname",
		"/proc/sys/kernel/osrelease",
		"/proc/loadavg",
		"LS:/home",
	)

	// ~/.bash_history is served with real content (the fixed no-op bug).
	wantHist := bashHistoryFor("admin", seed)
	if got := served["/home/admin/.bash_history"]; got != wantHist {
		t.Errorf("~/.bash_history not served correctly.\n got: %q\nwant: %q", got, wantHist)
	}
	if served["/home/admin/.bash_history"] == "" {
		t.Error("~/.bash_history served EMPTY - the inline-content no-op bug is back")
	}
	// Dotfiles present with real content.
	if !strings.Contains(served["/home/admin/.bashrc"], "HISTCONTROL") {
		t.Errorf("~/.bashrc not served with real content: %q", served["/home/admin/.bashrc"])
	}
	// ~/.ssh bait served.
	if !strings.Contains(served["/home/admin/.ssh/authorized_keys"], "ssh-ed25519 ") {
		t.Errorf("~/.ssh/authorized_keys not served: %q", served["/home/admin/.ssh/authorized_keys"])
	}
	if !strings.Contains(served["/home/admin/.ssh/config"], "Host deploy") {
		t.Errorf("~/.ssh/config not served: %q", served["/home/admin/.ssh/config"])
	}
	// root got a home too (root is an accepted login for this persona).
	if strings.TrimSpace(served["/root/.bash_history"]) == "" {
		t.Error("/root/.bash_history not served (root is an accepted login for this persona)")
	}
	// machine-id: 32 hex + newline, per-seed.
	wantMID := machineIDForSeed(seed) + "\n"
	if served["/etc/machine-id"] != wantMID {
		t.Errorf("/etc/machine-id = %q, want %q", served["/etc/machine-id"], wantMID)
	}
	// /proc/sys/kernel/* mirror the advertised identity.
	if served["/proc/sys/kernel/hostname"] != hostname+"\n" {
		t.Errorf("/proc/sys/kernel/hostname = %q, want %q", served["/proc/sys/kernel/hostname"], hostname+"\n")
	}
	if served["/proc/sys/kernel/osrelease"] != profile.KernelVersion+"\n" {
		t.Errorf("/proc/sys/kernel/osrelease = %q, want %q", served["/proc/sys/kernel/osrelease"], profile.KernelVersion+"\n")
	}
	// /proc/loadavg served (was an empty size-0 node) and consistent with w (0.00).
	if !strings.HasPrefix(served["/proc/loadavg"], "0.00 0.00 0.00 ") {
		t.Errorf("/proc/loadavg = %q, want 0.00 0.00 0.00 ...", served["/proc/loadavg"])
	}
	// /home no longer contains the orphan stock user; the persona users are there.
	homeLS := served["LS:/home"]
	if strings.Contains(","+homeLS+",", ",phil,") {
		t.Errorf("/home still contains stock 'phil' (no /etc/passwd account): %q", homeLS)
	}
	for _, u := range []string{"admin", "ansible", "jumpuser", "bastion"} {
		if !strings.Contains(","+homeLS+",", ","+u+",") {
			t.Errorf("/home missing persona user %q: %q", u, homeLS)
		}
	}
	// /etc/shadow matches passwd (persona users, not phil) AND the hash cracks
	// back to the user's actual login password (crack-back consistency).
	shadow := served["/etc/shadow"]
	if strings.Contains(shadow, "phil:") {
		t.Errorf("/etc/shadow still references stock 'phil'")
	}
	verifyShadowCrack(t, shadow, "admin", firstPassword(persona, "admin"), seed)
	verifyShadowCrack(t, shadow, "root", firstPassword(persona, "root"), seed)
}

// firstPassword returns the primary (first) password the persona accepts for a
// username - the value etcShadow hashes into that account's $6$ entry.
func firstPassword(t credentialTemplate, user string) string {
	for _, u := range t.Users {
		if u.Username == user && len(u.Passwords) > 0 {
			return u.Passwords[0]
		}
	}
	return ""
}

// verifyShadowCrack confirms the /etc/shadow $6$ line for user is a valid
// sha512-crypt of password (i.e. an attacker cracking it recovers a working
// password).
func verifyShadowCrack(t *testing.T, shadow, user, password, seed string) {
	t.Helper()
	var line string
	for _, ln := range strings.Split(shadow, "\n") {
		if strings.HasPrefix(ln, user+":") {
			line = ln
		}
	}
	if line == "" {
		t.Errorf("/etc/shadow has no line for %q", user)
		return
	}
	parts := strings.Split(line, ":")
	if len(parts) < 2 || !strings.HasPrefix(parts[1], "$6$") {
		t.Errorf("%s shadow field is not a $6$ hash: %q", user, line)
		return
	}
	hash := parts[1]
	seg := strings.Split(hash, "$") // ["", "6", salt, digest]
	if len(seg) < 4 {
		t.Errorf("%s hash malformed: %q", user, hash)
		return
	}
	if got := sha512Crypt(password, seg[2]); got != hash {
		t.Errorf("%s shadow hash does not crack to login password %q\n got: %s\nwant: %s", user, password, got, hash)
	}
}

// runPy writes src to dir/name, runs it with python3 (extra args appended), and
// returns combined output. Fails the test on a non-zero exit.
func runPy(t *testing.T, py, dir, name, src string, args ...string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, append([]string{p}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("python3 %s failed: %v\n%s", name, err, out)
	}
	return string(out)
}

// serve loads the patched pickle and returns each requested path's served bytes
// (as a string) via Cowrie's real file_contents rules. "LS:<dir>" returns a
// comma-joined child listing instead.
func serve(t *testing.T, py, dir, pickle string, paths ...string) map[string]string {
	t.Helper()
	out := runPy(t, py, dir, "serve.py", servePy, append([]string{pickle}, paths...)...)
	res := map[string]string{}
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		tab := strings.IndexByte(ln, '\t')
		if tab < 0 {
			continue
		}
		key, val := ln[:tab], ln[tab+1:]
		if strings.HasPrefix(key, "LS:") {
			res[key] = val
			continue
		}
		if val == "NONE" {
			res[key] = "\x00NONE"
			continue
		}
		b, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			t.Fatalf("bad base64 for %s: %v", key, err)
		}
		res[key] = string(b)
	}
	return res
}

const buildBasePy = `import sys, pickle
T_DIR, T_FILE = 1, 2
NOW = 1365163363
def d(name, uid=0, gid=0, kids=None):
    return [name, T_DIR, uid, gid, 4096, 0o40755, NOW, kids if kids is not None else [], None, None]
def f(name, uid=0, gid=0, size=0, mode=0o100644):
    return [name, T_FILE, uid, gid, size, mode, NOW, [], None, None]
home = d("home", kids=[d("phil", 1000, 1000, kids=[f(".bashrc",1000,1000,3392), f(".profile",1000,1000,807), f(".bash_logout",1000,1000,220)])])
etc = d("etc", kids=[f("passwd",0,0,872), f("shadow",0,42,753,0o100640), d("ssh")])
kernel = d("kernel", kids=[f("hostname",0,0,0), f("osrelease",0,0,0), f("ostype",0,0,0), f("version",0,0,0)])
proc = d("proc", kids=[f("loadavg",0,0,0), f("uptime",0,0,0), d("sys", kids=[kernel])])
var = d("var", kids=[d("lib")])
root = ["/", T_DIR, 0, 0, 4096, 0o40755, NOW, [home, etc, proc, var, d("root")], None]
pickle.dump(root, open(sys.argv[1], "wb"), protocol=2)
`

const servePy = `import sys, pickle, base64
N, T, U, G, SZ, M, C, CONT, TGT, RF = range(10)
T_DIR, T_FILE = 1, 2
fs = pickle.load(open(sys.argv[1], "rb"))
def children(n):
    return n[CONT] if len(n) > CONT and isinstance(n[CONT], list) else []
def getfile(path):
    cur = fs
    for p in [x for x in path.split("/") if x]:
        cur = next((c for c in children(cur) if c[N] == p), None)
        if cur is None:
            return None
    return cur
def contents(path):
    n = getfile(path)
    if n is None:
        return None
    if n[T] == T_DIR:
        return b""
    # Faithful to Cowrie shell/fs.py file_contents: realfile first, then size==0.
    if n[T] == T_FILE and n[RF]:
        return open(n[RF], "rb").read()
    if n[T] == T_FILE and n[SZ] == 0:
        return b""
    return b""
for path in sys.argv[2:]:
    if path.startswith("LS:"):
        n = getfile(path[3:])
        names = ",".join(c[N] for c in (children(n) if n else []))
        print("%s\t%s" % (path, names))
    else:
        c = contents(path)
        print("%s\t%s" % (path, "NONE" if c is None else base64.b64encode(c).decode("ascii")))
`

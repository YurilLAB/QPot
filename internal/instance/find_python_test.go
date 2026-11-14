package instance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// findHarness runs the patch layer's find.py outside Cowrie on a tree of
// Cowrie's nodes with the links a real persona has (/usr/bin/X11 -> .,
// /proc/self/root -> /, /bin -> usr/bin, a broken one) and many plain entries,
// behind a stub of Cowrie's filesystem (getfile follows links as Cowrie's
// does) and of the part of its protocol that starts a command, and prints,
// per command, what it wrote, its status and how long it took. The programs
// -exec may start: echo, cat, pwd, true, false, has WORD FILE (status 0 where
// the file holds the word), slow, an echo that ends after find has returned
// to the reactor, as a download does, and spin, which holds the thread for a
// quarter of a second before it ends.
const findHarness = `
import json, posixpath, sys, time, types, importlib.util
find_path, cases_path, wide = sys.argv[1], sys.argv[2], int(sys.argv[3])
for name in ("cowrie", "cowrie.shell", "cowrie.shell.command", "cowrie.shell.fs", "cowrie.shell.pipe"):
    sys.modules[name] = types.ModuleType(name)
class HoneyPotCommand:
    exited = False
sys.modules["cowrie.shell.command"].HoneyPotCommand = HoneyPotCommand
fsmod = sys.modules["cowrie.shell.fs"]
sys.modules["cowrie.shell"].fs = fsmod
(fsmod.A_NAME, fsmod.A_TYPE, fsmod.A_UID, fsmod.A_GID, fsmod.A_SIZE, fsmod.A_MODE, fsmod.A_CTIME, fsmod.A_CONTENTS,
 fsmod.A_TARGET, fsmod.A_REALFILE) = range(10)
fsmod.T_LINK, fsmod.T_DIR, fsmod.T_FILE, fsmod.T_BLK, fsmod.T_CHR, fsmod.T_SOCK, fsmod.T_FIFO = range(7)
class PipeProtocol:
    def __init__(self, protocol, cmdclass, args, data, targets, cwd=None, user=None):
        self.cwd, self.user = cwd, user
sys.modules["cowrie.shell.pipe"].PipeProtocol = PipeProtocol
spec = importlib.util.spec_from_file_location("find_cmd", find_path)
find = importlib.util.module_from_spec(spec)
spec.loader.exec_module(find)
D, F, L = 1, 2, 0
NOW = time.time()
DAY = 86400
def build():
    paths = {"/root": D, "/root/.ssh": D, "/root/.ssh/id_ed25519": F, "/root/.ssh/config": F,
             "/home": D, "/home/u": D, "/home/u/.ssh": D, "/home/u/.ssh/id_rsa": F,
             "/usr": D, "/usr/bin": D, "/usr/bin/ls": F, "/usr/bin/sudo": F, "/usr/bin/X11": (L, "."), "/bin": (L, "usr/bin"),
             "/proc": D, "/proc/self": D, "/proc/self/root": (L, "/"), "/proc/self/cwd": (L, "/root"),
             "/tmp": D, "/tmp/dead": (L, "/nowhere"), "/etc": D, "/etc/passwd": F, "/etc/group": F, "/srv": D}
    for i in range(wide):
        paths[f"/srv/d{i}"] = D
        for j in range(wide):
            paths[f"/srv/d{i}/f{j}"] = F
    body = {"/root/.ssh/id_ed25519": b"KEY\n" + b"k" * 396, "/root/.ssh/config": b"Host db\n" + b"#" * 12,
            "/home/u/.ssh/id_rsa": b"RSAKEY\n", "/usr/bin/ls": b"\x7fELF" + b"\0" * 4996, "/usr/bin/sudo": b"\x7fELF" + b"\0" * 2996,
            "/etc/passwd": b"root:x:0:0::/root:/bin/bash\nu:x:1000:1000::/home/u:/bin/bash\n",
            "/etc/group": b"root:x:0:\nu:x:1000:\n"}
    modes = {"/usr/bin/sudo": 0o104755, "/usr/bin/ls": 0o100755, "/root/.ssh/id_ed25519": 0o100600, "/root": 0o40700}
    when = {"/root/.ssh/config": NOW - 400 * DAY, "/home/u/.ssh/id_rsa": NOW - 3600}
    root = ["", D, 0, 0, 4096, 0o40755, NOW - 10 * DAY, [], None, None]
    nodes = {"/": root}
    for p, v in paths.items():
        kind, target = v if isinstance(v, tuple) else (v, None)
        mode = modes.get(p, 0o40755 if kind == D else 0o120777 if kind == L else 0o100644)
        owner = 1000 if p.startswith("/home/u") else 0
        data = [] if kind == D else body.get(p, b"x\n") if kind == F else None
        size = 4096 if kind == D else len(data) if kind == F else len(target)
        node = [posixpath.basename(p), kind, owner, owner, size, mode, when.get(p, NOW - 10 * DAY), data, target, None]
        nodes[posixpath.dirname(p)][7].append(node)
        nodes[p] = node
    return root
class FS:
    def __init__(self, root, uid):
        self.root, self.uid = root, uid
    def resolve_path(self, path, cwd):
        return posixpath.normpath(posixpath.join(cwd, path))
    def getfile(self, path, follow_symlinks=True, depth=0):
        root = self.root
        if depth > 16:
            return None
        if path == "/":
            return root
        node, done = root, ""
        pieces = [p for p in path.split("/") if p]
        for i, piece in enumerate(pieces):
            if not isinstance(node[7], list):
                return None
            node = next((c for c in node[7] if c[0] == piece), None)
            if node is None:
                return None
            if node[1] == L and (follow_symlinks or i < len(pieces) - 1):
                node = self.getfile(posixpath.normpath(posixpath.join(done or "/", node[8])), True, depth + 1)
                if node is None:
                    return None
            done += "/" + piece
        return node
    def get_path(self, path):
        if self.uid != 0 and (path == "/root" or path.startswith("/root/")):
            raise PermissionError(13, "Permission denied", path)
        return self.getfile(path)[7]
    def file_contents(self, path):
        node = self.getfile(path)
        if node is None or not isinstance(node[7], bytes):
            raise FileNotFoundError(path)
        return node[7]
    def exists(self, path):
        return self.getfile(path, False) is not None
    def isdir(self, path):
        node = self.getfile(path)
        return node is not None and node[1] == D
    def remove(self, path):
        parent = self.getfile(posixpath.dirname(path))
        parent[7].remove(self.getfile(path, False))
    rmdir = remove
    def mkfile(self, path, uid, gid, size, mode, ctime=None):
        self.getfile(posixpath.dirname(path))[7].append([posixpath.basename(path), F, uid, gid, size, mode, ctime, b"", None, None])
class Proto:
    """Starts a command as Cowrie's protocol does: on the stack above find, which is resumed when it ends."""
    def __init__(self, cmd):
        self.cmd, self.cmdstack, self.later, self.started = cmd, [cmd], [], []
        self.events = types.SimpleNamespace(dispatch=lambda *a, **k: None)
    def getCommand(self, name, paths, cwd):
        return name if name in ("echo", "cat", "pwd", "true", "false", "has", "slow", "spin") else None
    def call_command(self, pp, name, *args):
        cmd = self.cmd
        self.started.append([name, *args])
        child = types.SimpleNamespace(handle_CTRL_C=lambda: None)
        self.cmdstack.append(child)
        def end(code):
            self.cmdstack.remove(child)
            cmd.last_exit_code = code
            cmd.resume()
        if name == "slow":
            self.later.append(lambda: (cmd.write(" ".join(args) + "\n"), end(0)))
            return
        code = 0
        if name == "spin":
            time.sleep(0.25)
        if name == "echo":
            cmd.write(" ".join(args) + "\n")
        elif name == "pwd":
            cmd.write(pp.cwd + "\n")
        elif name == "cat":
            for arg in args:
                cmd.write(cmd.fs.file_contents(arg).decode("latin-1"))
        elif name == "false":
            code = 1
        elif name == "has":
            code = 0 if args[0].encode() in cmd.fs.file_contents(args[1]) else 1
        end(code)
shared = build()
out = []
for case in json.load(open(cases_path)):
    args, uid = case["args"], case.get("uid", 0)
    lines, errs, codes = [], [], []
    cmd = find.Command_find.__new__(find.Command_find)
    cmd.args, cmd.cwd = args, "/root"
    cmd.fs = FS(build() if "-delete" in args or "-fprint" in args else shared, uid)
    cmd.user, cmd.environ = {"uid": uid, "gid": uid}, {"PATH": "/usr/bin"}
    cmd.pp = types.SimpleNamespace(targets=None, stdin_from_pipe=False)
    cmd.protocol = Proto(cmd)
    cmd.write = lambda s: lines.append(s)
    cmd.errorWrite = lambda s: errs.append(s)
    def leave(code=None, cmd=cmd, codes=codes):
        cmd.exited = True
        codes.append(code)
    cmd.exit = leave
    t0 = time.perf_counter()
    cmd.start()
    while cmd.protocol.later:
        cmd.protocol.later.pop(0)()
    raw = "".join(lines)
    saved = cmd.fs.getfile("/tmp/out")
    out.append({"lines": raw.splitlines(), "raw": raw, "errors": errs, "codes": codes,
                "seconds": time.perf_counter() - t0, "tmp": [c[0] for c in cmd.fs.getfile("/tmp")[7]],
                "saved": saved[7].decode() if saved else "", "started": len(cmd.protocol.started)})
print(json.dumps(out))
`

type findCase struct {
	Args []string `json:"args"`
	UID  int      `json:"uid,omitempty"`
}

type findResult struct {
	Lines   []string `json:"lines"`
	Raw     string   `json:"raw"`
	Errors  []string `json:"errors"`
	Codes   []*int   `json:"codes"`
	Seconds float64  `json:"seconds"`
	Tmp     []string `json:"tmp"`
	Saved   string   `json:"saved"`
	Started int      `json:"started"`
}

// status is the exit status find ended with; -1 where it did not end exactly once.
func (r findResult) status() int {
	if len(r.Codes) != 1 {
		return -1
	}
	if r.Codes[0] == nil {
		return 0
	}
	return *r.Codes[0]
}

func runFindCases(t *testing.T, py string, cases []findCase, wide string) []findResult {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cb, _ := json.Marshal(cases)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, py, write("h.py", []byte(findHarness)), write("find.py", cowrieFindPy),
		write("cases.json", cb), wide).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, b)
	}
	var got []findResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	if len(got) != len(cases) {
		t.Fatalf("%d results for %d cases", len(got), len(cases))
	}
	return got
}

func runFindHarness(t *testing.T, py string, args [][]string, wide string) []findResult {
	t.Helper()
	cases := make([]findCase, len(args))
	for i, a := range args {
		cases[i] = findCase{Args: a}
	}
	return runFindCases(t, py, cases, wide)
}

// TestFindWalksLikeGNUFind: find on the honeypot does not enter links to
// directories (GNU find's default, -P), so `find / -name 'id_*'`, the first
// command of a credential harvest, ends at once with the keys it finds; the
// image's find followed every link down to depth 20 and held Cowrie's reactor
// (every session) for minutes. Several starting points, -iname and -type l
// work as in GNU find; a huge tree stops at the walk's bound.
func TestFindWalksLikeGNUFind(t *testing.T) {
	py := python(t)
	cases := []struct {
		args []string
		want string // the lines, space-joined; /srv/ lines left out where marked
		srv  bool
	}{
		{[]string{"/", "-name", "id_*", "-type", "f"}, "/root/.ssh/id_ed25519 /home/u/.ssh/id_rsa", false},
		{[]string{"/", "-type", "d"}, "/ /root /root/.ssh /home /home/u /home/u/.ssh /usr /usr/bin /proc /proc/self /tmp /etc /srv", true},
		{[]string{"/usr", "-name", "X11"}, "/usr/bin/X11", false},
		{[]string{"/bin"}, "/bin", false},
		{[]string{"/tmp"}, "/tmp /tmp/dead", false},
		{[]string{"/root", "/home", "-name", "id_*"}, "/root/.ssh/id_ed25519 /home/u/.ssh/id_rsa", false},
		{[]string{"/", "-iname", "ID_RSA", "-print"}, "/home/u/.ssh/id_rsa", false},
		{[]string{"/", "-name", "*", "-type", "l"}, "/usr/bin/X11 /bin /proc/self/root /proc/self/cwd /tmp/dead", false},
		{[]string{".", "-name", "config"}, "./.ssh/config", false},
		{[]string{"/root/", "-maxdepth", "1"}, "/root/ /root/.ssh", false},
		{[]string{"/srv", "-name", "f1", "-maxdepth", "2"}, "", true},
		{[]string{"/", "-perm", "-4000", "-type", "f"}, "/usr/bin/sudo", false},
		{[]string{"/usr", "-perm", "/u=s,g=s"}, "/usr/bin/sudo", false},
		{[]string{"/usr/bin", "-perm", "-0755", "-type", "f"}, "/usr/bin/ls /usr/bin/sudo", false},
	}
	var args [][]string
	for _, c := range cases {
		args = append(args, c.args)
	}
	got := runFindHarness(t, py, args, "30")
	for i, c := range cases {
		lines := got[i].Lines
		if c.srv {
			var kept []string
			for _, l := range lines {
				if !strings.HasPrefix(l, "/srv/") {
					kept = append(kept, l)
				}
			}
			lines = kept
		}
		if strings.Join(lines, " ") != c.want || len(got[i].Errors) != 0 || got[i].status() != 0 {
			t.Errorf("find %v: %q (errors %q, status %d), want %q", c.args, lines, got[i].Errors, got[i].status(), c.want)
		}
		if got[i].Seconds > 1 {
			t.Errorf("find %v took %.2f s", c.args, got[i].Seconds)
		}
	}
	if n := len(got[10].Lines); n != 30 {
		t.Errorf("find /srv -name f1: %d lines, want 30", n)
	}
	// 640 000 entries under /srv: the walk stops at its bound, inside the time it may take
	big := runFindHarness(t, py, [][]string{{"/", "-name", "f1"}, {"/srv"}}, "800")
	for i, c := range big {
		if c.Seconds > 3 || len(c.Lines) == 0 {
			t.Errorf("huge tree, case %d: %.2f s, %d lines", i, c.Seconds, len(c.Lines))
		}
	}
	if n := len(big[1].Lines); n > 200000 {
		t.Errorf("find /srv in a huge tree printed %d lines, more than the walk's bound", n)
	}
}

// TestFindExpression: the expressions someone hunting for credentials writes
// are GNU find's, where the image's find answered "unknown predicate": several
// names joined with -o, parentheses, !, -path, -size, -mtime, -newer, -user,
// -regex, -prune, -depth, -mindepth, -printf, -ls, -print0, -fprint, -delete
// and -quit. Expected lines are what findutils 4.10.0 prints for the same tree.
func TestFindExpression(t *testing.T) {
	py := python(t)
	keys := "/root/.ssh/id_ed25519 /home/u/.ssh/id_rsa"
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/", "-name", "id_rsa", "-o", "-name", "id_ed25519*"}, keys},
		{[]string{"/", "(", "-name", "id_rsa", "-o", "-name", "config", ")", "-type", "f"}, "/root/.ssh/config /home/u/.ssh/id_rsa"},
		// -a binds tighter than -o: the second name alone is printed with its action, the first has none
		{[]string{"/", "-name", "id_rsa", "-o", "-name", "config", "-print"}, "/root/.ssh/config"},
		{[]string{"/root", "/home", "-path", "*/.ssh/*", "!", "-name", "config"}, keys},
		{[]string{"/root", "/home", "-wholename", "*/.ssh/*", "-not", "-name", "id_*"}, "/root/.ssh/config"},
		{[]string{"/root", "-type", "f", "-size", "-2k"}, "/root/.ssh/id_ed25519 /root/.ssh/config"},
		{[]string{"/usr", "-type", "f", "-size", "+4k"}, "/usr/bin/ls"},
		{[]string{"/root", "-type", "f", "-size", "-100c"}, "/root/.ssh/config"},
		{[]string{"/root", "/home", "-type", "f", "-mtime", "-1"}, "/home/u/.ssh/id_rsa"},
		{[]string{"/root", "/home", "-type", "f", "-mtime", "+30"}, "/root/.ssh/config"},
		{[]string{"/root", "/home", "-type", "f", "-mmin", "-120"}, "/home/u/.ssh/id_rsa"},
		{[]string{"/root", "/home", "-newer", "/root/.ssh/config", "-type", "f"}, keys},
		{[]string{"/root", "/home", "-type", "f", "-newermt", "30 days ago"}, keys},
		{[]string{"/home", "-user", "u"}, "/home/u /home/u/.ssh /home/u/.ssh/id_rsa"},
		{[]string{"/home", "-uid", "+999", "-type", "f"}, "/home/u/.ssh/id_rsa"},
		{[]string{"/home", "/root", "-maxdepth", "1", "-group", "root"}, "/home /root /root/.ssh"},
		{[]string{"/home", "-nouser"}, ""},
		{[]string{"/root", "-regex", ".*/id_[a-z0-9]*"}, "/root/.ssh/id_ed25519"},
		{[]string{"/root", "/home", "-regextype", "posix-extended", "-regex", ".*/(config|id_rsa)"}, "/root/.ssh/config /home/u/.ssh/id_rsa"},
		{[]string{"/root", "-depth"}, "/root/.ssh/id_ed25519 /root/.ssh/config /root/.ssh /root"},
		{[]string{"/", "-mindepth", "1", "-maxdepth", "1", "-type", "d"}, "/root /home /usr /proc /tmp /etc /srv"},
		{[]string{"/", "-name", "srv", "-prune", "-o", "-name", "id_*", "-print"}, keys},
		{[]string{"/", "-type", "l", "-lname", "/*"}, "/proc/self/root /proc/self/cwd /tmp/dead"},
		{[]string{"/", "-xtype", "d", "-type", "l"}, "/usr/bin/X11 /bin /proc/self/root /proc/self/cwd"},
		{[]string{"/tmp", "/proc/self", "-type", "d", "-empty"}, ""},
		{[]string{"/root", "-type", "d", "-links", "3"}, "/root"},
		{[]string{"/usr", "-executable", "-type", "f"}, "/usr/bin/ls /usr/bin/sudo"},
		{[]string{"/root", "-type", "f", "-printf", "%f %s %u %m\\n"}, "id_ed25519 400 root 600 config 20 root 644"},
		{[]string{"/home/u", "-printf", "%d:%y:%P:%h|"}, "0:d::/home|1:d:.ssh:/home/u|2:f:.ssh/id_rsa:/home/u/.ssh|"},
		{[]string{"/", "-name", "id_rsa", "-print", "-quit"}, "/home/u/.ssh/id_rsa"},
		{[]string{"/", "-name", "id_*", "-print", "-quit"}, "/root/.ssh/id_ed25519"},
		{[]string{"/root", "-false", "-o", "-name", "config"}, "/root/.ssh/config"},
		{[]string{"/root/.ssh", "-name", "config", ",", "-name", "id_*"}, "/root/.ssh/id_ed25519"},
		{[]string{"-H", "/root", "-name", "config"}, "/root/.ssh/config"},
	}
	var args [][]string
	for _, c := range cases {
		args = append(args, c.args)
	}
	got := runFindHarness(t, py, args, "3")
	for i, c := range cases {
		if strings.Join(got[i].Lines, " ") != c.want || len(got[i].Errors) != 0 || got[i].status() != 0 {
			t.Errorf("find %v: %q (errors %q, status %d), want %q", c.args, got[i].Lines, got[i].Errors, got[i].status(), c.want)
		}
	}

	more := runFindHarness(t, py, [][]string{
		{"/root/.ssh", "-type", "f", "-print0"},
		{"/root/.ssh", "-name", "config", "-ls"},
		{"/tmp", "-name", "dead", "-delete"},
		{"/root", "-delete"},
		{"/root", "-type", "f", "-fprint", "/tmp/out"},
		{"--version"},
		{"/", "-help"},
		{"/nope", "/root/.ssh", "-name", "config"},
	}, "1")
	if more[0].Raw != "/root/.ssh/id_ed25519\x00/root/.ssh/config\x00" {
		t.Errorf("-print0: %q", more[0].Raw)
	}
	// the columns of find -ls (inode, 1K blocks, mode, links, owner, group, size, date, name); a file
	// older than half a year shows its year
	if ok, _ := regexp.MatchString(`^ {0,8}\d+      4 -rw-r--r--   1 root     root           20 [A-Z][a-z]{2} [ \d]\d  \d{4} /root/\.ssh/config\n$`, more[1].Raw); !ok {
		t.Errorf("-ls: %q", more[1].Raw)
	}
	if len(more[2].Tmp) != 0 || more[2].status() != 0 || more[2].Raw != "" {
		t.Errorf("-delete left %q (status %d, output %q)", more[2].Tmp, more[2].status(), more[2].Raw)
	}
	// -delete is depth first, so a folder goes after what it held
	if strings.Join(more[3].Errors, "") != "" || more[3].status() != 0 {
		t.Errorf("-delete of a tree: %q, status %d", more[3].Errors, more[3].status())
	}
	if more[4].Saved != "/root/.ssh/id_ed25519\n/root/.ssh/config\n" || more[4].Raw != "" {
		t.Errorf("-fprint wrote %q and printed %q", more[4].Saved, more[4].Raw)
	}
	if !strings.HasPrefix(more[5].Raw, "find (GNU findutils) 4.10.0\nCopyright (C) 2024 ") || more[5].status() != 0 {
		t.Errorf("--version: %q", more[5].Raw)
	}
	if !strings.HasPrefix(more[6].Raw, "Usage: find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]\n") || more[6].status() != 0 {
		t.Errorf("-help: %q", more[6].Raw)
	}
	if strings.Join(more[7].Errors, "") != "find: ‘/nope’: No such file or directory\n" || more[7].Raw != "/root/.ssh/config\n" || more[7].status() != 1 {
		t.Errorf("a missing starting point: %q, %q, status %d", more[7].Errors, more[7].Raw, more[7].status())
	}

	// an account that may not list a folder is told so, and the rest is searched
	denied := runFindCases(t, py, []findCase{{Args: []string{"/root", "/home", "-name", "id_*"}, UID: 1000}}, "1")
	if strings.Join(denied[0].Errors, "") != "find: ‘/root’: Permission denied\n" || denied[0].Raw != "/home/u/.ssh/id_rsa\n" || denied[0].status() != 1 {
		t.Errorf("without permission: %q, %q, status %d", denied[0].Errors, denied[0].Raw, denied[0].status())
	}
}

// TestFindExec: -exec starts the honeypot's own commands, one per file (;) or
// one for all (+), in the order find reaches the files, and the command's
// status is the test's: `-exec grep -q KEY {} \; -print` prints the files that
// hold the word. A command that ends later (a download) is waited for.
func TestFindExec(t *testing.T) {
	py := python(t)
	cases := []struct {
		args    []string
		want    string
		started int
		status  int
	}{
		{[]string{"/root", "-type", "f", "-exec", "cat", "{}", ";"}, "KEY\n" + strings.Repeat("k", 396) + "Host db\n############", 2, 0},
		{[]string{"/root", "/home", "-type", "f", "-exec", "has", "KEY", "{}", ";", "-print"}, "/root/.ssh/id_ed25519\n/home/u/.ssh/id_rsa\n", 3, 0},
		{[]string{"/root", "-type", "f", "-exec", "false", ";", "-print"}, "", 2, 0},
		{[]string{"/root", "-type", "f", "!", "-exec", "false", ";", "-print"}, "/root/.ssh/id_ed25519\n/root/.ssh/config\n", 2, 0},
		{[]string{"/root", "-type", "f", "-exec", "echo", "{}", "+"}, "/root/.ssh/id_ed25519 /root/.ssh/config\n", 1, 0},
		{[]string{"/root", "-type", "f", "-exec", "echo", "a", "{}", "b{}c", ";"}, "a /root/.ssh/id_ed25519 b/root/.ssh/id_ed25519c\na /root/.ssh/config b/root/.ssh/configc\n", 2, 0},
		// the output of -print and of the commands, in the order of the walk
		{[]string{"/root", "-type", "f", "-print", "-exec", "slow", "got", "{}", ";"}, "/root/.ssh/id_ed25519\ngot /root/.ssh/id_ed25519\n/root/.ssh/config\ngot /root/.ssh/config\n", 2, 0},
		{[]string{"/root", "-name", "config", "-execdir", "pwd", ";"}, "/root/.ssh\n", 1, 0},
		{[]string{"/root", "-name", "config", "-execdir", "echo", "{}", ";"}, "./config\n", 1, 0},
		{[]string{"/root", "-type", "f", "-exec", "false", "{}", "+"}, "", 1, 1},
		{[]string{"/root", "-type", "f", "-exec", "nosuch", "{}", ";"}, "", 0, 0},
		{[]string{"/root", "-type", "f", "-ok", "cat", "{}", ";"}, "", 0, 0},
	}
	var args [][]string
	for _, c := range cases {
		args = append(args, c.args)
	}
	got := runFindHarness(t, py, args, "1")
	for i, c := range cases {
		if got[i].Raw != c.want || got[i].Started != c.started || got[i].status() != c.status {
			t.Errorf("find %v: %q, %d commands, status %d (errors %q); want %q, %d, %d",
				c.args, got[i].Raw, got[i].Started, got[i].status(), got[i].Errors, c.want, c.started, c.status)
		}
	}
	if e := strings.Join(got[10].Errors, ""); e != strings.Repeat("find: ‘nosuch’: No such file or directory\n", 2) {
		t.Errorf("a command that is not there: %q", e)
	}
	if e := strings.Join(got[11].Errors, ""); e != "< cat ... /root/.ssh/id_ed25519 > ? < cat ... /root/.ssh/config > ? " {
		t.Errorf("-ok: %q", e)
	}
	// every file of a wide tree: the commands find may start in one call are bounded
	many := runFindHarness(t, py, [][]string{{"/srv", "-type", "f", "-exec", "true", ";"}}, "40")
	if many[0].Started != 1000 || many[0].status() != 0 || many[0].Seconds > 5 {
		t.Errorf("-exec on 1600 files started %d commands in %.2f s, status %d", many[0].Started, many[0].Seconds, many[0].status())
	}
	// the call has one budget of time, the commands that run at once included: commands that each
	// hold the thread do not add up to minutes (1000 of these would take four)
	held := runFindHarness(t, py, [][]string{{"/srv", "-type", "f", "-exec", "spin", ";"}, {"/srv", "-type", "f", "-exec", "spin", "{}", "+"}}, "40")
	if held[0].Started < 2 || held[0].Started > 12 || held[0].Seconds > 4 || held[0].status() != 0 {
		t.Errorf("-exec of a command that holds the thread: %d started in %.2f s, status %d", held[0].Started, held[0].Seconds, held[0].status())
	}
	if held[1].Started != 1 || held[1].Seconds > 4 {
		t.Errorf("-exec ... + of the same: %d started in %.2f s", held[1].Started, held[1].Seconds)
	}
}

// TestFindMessages: what find says of an expression it cannot read is GNU
// find's text and status 1 (recorded from findutils 4.10.0).
func TestFindMessages(t *testing.T) {
	py := python(t)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"/nope", "-name", "x"}, "find: ‘/nope’: No such file or directory\n"},
		{[]string{"/", "-perm", "-9999"}, "find: invalid mode ‘-9999’\n"},
		{[]string{"/", "-bogus"}, "find: unknown predicate `-bogus'\n"},
		{[]string{"/", "-name"}, "find: missing argument to `-name'\n"},
		{[]string{"/", "-exec"}, "find: missing argument to `-exec'\n"},
		{[]string{"/", "-exec", "echo", "{}"}, "find: missing argument to `-exec'\n"},
		{[]string{"/", "-exec", "echo", "{}", "{}", "+"}, "find: Only one instance of {} is supported with -exec ... +\n"},
		{[]string{"/", "-type", "q"}, "find: Unknown argument to -type: q\n"},
		{[]string{"/", "-type", "fq"}, "find: Must separate multiple arguments to -type using: ','\n"},
		{[]string{"/", "-type", "f,"}, "find: Last file type in list argument to -type is missing, i.e., list is ending on: ','\n"},
		{[]string{"/", "-type", ""}, "find: Arguments to -type should contain at least one letter\n"},
		{[]string{"/", "-maxdepth", "x"}, "find: Expected a positive decimal integer argument to -maxdepth, but got ‘x’\n"},
		{[]string{"/", "-size", "1x"}, "find: invalid -size type `x'\n"},
		{[]string{"/", "-mtime", "z"}, "find: invalid argument `z' to `-mtime'\n"},
		{[]string{"/", "-o", "-name", "x"}, "find: invalid expression; you have used a binary operator '-o' with nothing before it.\n"},
		{[]string{"/", "-name", "x", "-o"}, "find: expected an expression after '-o'\n"},
		{[]string{"/", "(", "-name", "x"}, "find: invalid expression; I was expecting to find a ')' somewhere but did not see one.\n"},
		{[]string{"/", "(", ")"}, "find: invalid expression; empty parentheses are not allowed.\n"},
		{[]string{"/", "-name", "x", ")"}, "find: you have too many ')'\n"},
		{[]string{"/", "!"}, "find: expected an expression after '!'\n"},
		{[]string{"/", "-name", "f1", "extra"}, "find: paths must precede expression: `extra'\n"},
		{[]string{"/", "-name", "a.sh", "b.sh", "-print"}, "find: paths must precede expression: `b.sh'\n"},
		{[]string{"/", "-user", "nosuchuser"}, "find: invalid user name or UID argument to -user: ‘nosuchuser’\n"},
		{[]string{"/", "-group", "nosuchgroup"}, "find: invalid group name or GID argument to -group: ‘nosuchgroup’\n"},
		{[]string{"/", "-newer", "nosuchfile"}, "find: ‘nosuchfile’: No such file or directory\n"},
		{[]string{"/", "-newermt", "garbage"}, "find: I cannot figure out how to interpret ‘garbage’ as a date or time\n"},
		{[]string{"/", "-newermx", "x"}, "find: invalid predicate `-newermx'\n"},
		{[]string{"/", "-regextype", "bogus", "-regex", "x"}, "find: Unknown regular expression type ‘bogus’; valid types are ‘findutils-default’, ‘ed’, ‘emacs’, ‘gnu-awk’, ‘grep’, ‘posix-awk’, ‘awk’, ‘posix-basic’, ‘posix-egrep’, ‘egrep’, ‘posix-extended’, ‘posix-minimal-basic’, ‘sed’.\n"},
		{[]string{"/tmp", ",", "-name", "b"}, "find: ‘,’: No such file or directory\n"},
	}
	var args [][]string
	for _, c := range cases {
		args = append(args, c.args)
	}
	got := runFindHarness(t, py, args, "1")
	for i, c := range cases {
		if strings.Join(got[i].Errors, "") != c.want || got[i].status() != 1 {
			t.Errorf("find %v: %q, status %d; want %q, status 1", c.args, got[i].Errors, got[i].status(), c.want)
		}
	}
	// a pattern that could hold the one thread every session shares matches nothing, at once: not
	// even the paths it would match were it tried (the second one names every f1)
	slow := runFindHarness(t, py, [][]string{
		{"/", "-regextype", "posix-extended", "-regex", "(a*)*b"},
		{"/", "-regex", ".*.*.*.*.*.*f1"},
		{"/", "-regextype", "posix-extended", "-regex", "(.*)\\1"},
	}, "30")
	for i, c := range slow {
		if len(c.Lines) != 0 || c.Seconds > 1 || c.status() != 0 {
			t.Errorf("costly -regex %d: %d lines in %.2f s, status %d", i, len(c.Lines), c.Seconds, c.status())
		}
	}
}

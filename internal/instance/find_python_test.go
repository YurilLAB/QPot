package instance

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findHarness runs the patch layer's find.py outside Cowrie on a tree of
// Cowrie's nodes with the links a real persona has (/usr/bin/X11 -> .,
// /proc/self/root -> /, /bin -> usr/bin, a broken one) and many plain entries,
// behind a stub of Cowrie's filesystem (getfile follows links as Cowrie's
// does), and prints, per command, what it wrote and how long it took.
const findHarness = `
import json, posixpath, sys, time, types, importlib.util
find_path, cases_path, wide = sys.argv[1], sys.argv[2], int(sys.argv[3])
for name in ("cowrie", "cowrie.shell", "cowrie.shell.command", "cowrie.shell.fs"):
    sys.modules[name] = types.ModuleType(name)
class HoneyPotCommand:
    pass
sys.modules["cowrie.shell.command"].HoneyPotCommand = HoneyPotCommand
fsmod = sys.modules["cowrie.shell.fs"]
fsmod.A_NAME, fsmod.A_TYPE, fsmod.A_MODE, fsmod.A_CONTENTS, fsmod.A_TARGET = 0, 1, 5, 7, 8
fsmod.T_LINK, fsmod.T_DIR, fsmod.T_FILE = 0, 1, 2
spec = importlib.util.spec_from_file_location("find_cmd", find_path)
find = importlib.util.module_from_spec(spec)
spec.loader.exec_module(find)
D, F, L = 1, 2, 0
paths = {"/root": D, "/root/.ssh": D, "/root/.ssh/id_ed25519": F, "/root/.ssh/config": F,
         "/home": D, "/home/u": D, "/home/u/.ssh": D, "/home/u/.ssh/id_rsa": F,
         "/usr": D, "/usr/bin": D, "/usr/bin/ls": F, "/usr/bin/sudo": F, "/usr/bin/X11": (L, "."), "/bin": (L, "usr/bin"),
         "/proc": D, "/proc/self": D, "/proc/self/root": (L, "/"), "/proc/self/cwd": (L, "/root"),
         "/tmp": D, "/tmp/dead": (L, "/nowhere"), "/srv": D}
for i in range(wide):
    paths[f"/srv/d{i}"] = D
    for j in range(wide):
        paths[f"/srv/d{i}/f{j}"] = F
root = ["", D, 0, 0, 4096, 0o40755, 0, [], None, None]
nodes = {"/": root}
for p, v in paths.items():
    kind, target = v if isinstance(v, tuple) else (v, None)
    mode = {"/usr/bin/sudo": 0o104755, "/usr/bin/ls": 0o100755}.get(p, 0o40755 if kind == D else 0o100644)
    node = [posixpath.basename(p), kind, 0, 0, 4096, mode, 0, [] if kind == D else None, target, None]
    nodes[posixpath.dirname(p)][7].append(node)
    nodes[p] = node
class FS:
    def resolve_path(self, path, cwd):
        return posixpath.normpath(posixpath.join(cwd, path))
    def getfile(self, path, follow_symlinks=True, depth=0):
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
out = []
for args in json.load(open(cases_path)):
    lines, errs = [], []
    cmd = find.Command_find.__new__(find.Command_find)
    cmd.args, cmd.cwd, cmd.fs = args, "/root", FS()
    cmd.write = lambda s: lines.append(s)
    cmd.errorWrite = lambda s: errs.append(s)
    cmd.exit = lambda *a: None
    t0 = time.perf_counter()
    cmd.start()
    out.append({"lines": "".join(lines).splitlines(), "errors": errs, "seconds": time.perf_counter() - t0})
print(json.dumps(out))
`

type findResult struct {
	Lines   []string `json:"lines"`
	Errors  []string `json:"errors"`
	Seconds float64  `json:"seconds"`
}

func runFindHarness(t *testing.T, py string, cases [][]string, wide string) []findResult {
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
	return got
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
		{[]string{"/", "-type", "d"}, "/ /root /root/.ssh /home /home/u /home/u/.ssh /usr /usr/bin /proc /proc/self /tmp /srv", true},
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
		if strings.Join(lines, " ") != c.want || len(got[i].Errors) != 0 {
			t.Errorf("find %v: %q (errors %q), want %q", c.args, lines, got[i].Errors, c.want)
		}
		if got[i].Seconds > 1 {
			t.Errorf("find %v took %.2f s", c.args, got[i].Seconds)
		}
	}
	if n := len(got[10].Lines); n != 30 {
		t.Errorf("find /srv -name f1: %d lines, want 30", n)
	}
	// GNU find's messages in a UTF-8 locale
	errs := runFindHarness(t, py, [][]string{{"/nope", "-name", "x"}, {"/", "-perm", "-9999"}, {"/", "-exec", "id"}}, "1")
	if strings.Join(errs[0].Errors, "") != "find: ‘/nope’: No such file or directory\n" ||
		strings.Join(errs[1].Errors, "") != "find: invalid mode ‘-9999’\n" ||
		strings.Join(errs[2].Errors, "") != "find: unknown predicate `-exec'\n" {
		t.Errorf("errors: %q / %q / %q", errs[0].Errors, errs[1].Errors, errs[2].Errors)
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

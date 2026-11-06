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

// globHarness takes the pathname expansion out of the patch layer's
// bashparse.py (its qpot_ methods and bounds, by their source, so lark need
// not be installed) into a stub parser whose shell has a tree of Cowrie's
// nodes behind a stub of Cowrie's filesystem (getfile follows links as
// Cowrie's does, a link loop raises), and prints what each word expands to.
// A word's mask marks its quoted characters ("0"): `\*` and '*' are literal,
// as in bash.
const globHarness = `
import ast, json, posixpath, re, sys, time, types
src, cases_path = sys.argv[1], sys.argv[2]
for name in ("cowrie", "cowrie.shell", "cowrie.shell.fs", "cowrie.commands", "cowrie.commands.coreutils"):
    sys.modules[name] = types.ModuleType(name)
fsmod = sys.modules["cowrie.shell.fs"]
fsmod.A_NAME, fsmod.A_TYPE, fsmod.A_CONTENTS, fsmod.A_TARGET = 0, 1, 7, 8
fsmod.T_LINK, fsmod.T_DIR, fsmod.T_FILE = 0, 1, 2
tree = ast.parse(open(src, encoding="utf-8").read())
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "BashParser")
keep = [n for n in cls.body if (isinstance(n, ast.FunctionDef) and n.name in ("qpot_split_masked", "qpot_pathnames",
                                                                            "qpot_glob_dots", "qpot_glob_pattern"))
        or (isinstance(n, ast.Assign) and any(getattr(t, "id", "").startswith("QPOT_GLOB") for t in n.targets))]
stub = ast.parse("class Stub:" + chr(10) + "    pass" + chr(10))
stub.body[0].body = keep
shell_cfg = json.loads(sys.argv[4])
# what the patch layer's coreutils derives for bash --version from the persona's os-release
sys.modules["cowrie.commands.coreutils"].qpot_bash_version = lambda fs: shell_cfg.get("os_bash")
class CowrieConfig:
    @staticmethod
    def get(section, key, fallback=""):
        return shell_cfg.get(key, fallback)
ns = {"_IFS_WHITESPACE": " \t\n", "re": re, "CowrieConfig": CowrieConfig}
exec(compile(ast.fix_missing_locations(stub), src, "exec"), ns)
D, F, L = 1, 2, 0
paths = {"/etc": D, "/etc/cron.d": D, "/etc/cron.d/db-backup": F, "/etc/cron.d/e2scrub_all": F, "/etc/cron.d/.placeholder": F,
         "/home": D, "/home/ubuntu": D, "/home/ubuntu/.bash_history": F, "/home/ubuntu/.ssh": D,
         "/home/ubuntu/.ssh/authorized_keys": F, "/home/debian": D, "/home/debian/.bash_history": F,
         "/root": D, "/root/.ssh": D, "/root/.ssh/id_ed25519": F, "/root/.ssh/id_ed25519.pub": F,
         "/root/.ssh/config": F, "/root/.bash_history": F, "/root/notes.txt": F,
         "/var": D, "/var/backups": D, "/var/backups/crm-pre-release-20250101.sql.gz": F,
         "/srv": D, "/srv/a[1].txt": F, "/srv/b*c": F, "/usr": D, "/usr/bin": D, "/usr/bin/ls": F,
         "/bin": (L, "usr/bin"), "/tmp": D, "/tmp/dead": (L, "nowhere-xyz"),
         "/loop": D, "/loop/a": (L, "b"), "/loop/b": (L, "a"), "/data": D, "/data/big": D, "/mid": D}
for i in range(int(sys.argv[3])):
    paths[f"/data/big/f{i:06d}"] = F
for i in range(30000):
    paths[f"/mid/m{i:06d}"] = F
root = ["", D, 0, 0, 4096, 0o40755, 0, [], None, None]
nodes = {"/": root}
for path, v in paths.items():
    kind, target = v if isinstance(v, tuple) else (v, None)
    node = [posixpath.basename(path), kind, 0, 0, 4096, 0o40755 if kind == D else 0o100644, 0,
            [] if kind == D else None, target, None]
    nodes[posixpath.dirname(path)][7].append(node)
    nodes[path] = node
class FS:
    def getfile(self, path, follow_symlinks=True):
        if path == "/":
            return root
        node, done = root, ""
        for piece in [x for x in path.strip("/").split("/") if x]:
            if not isinstance(node, list) or not isinstance(node[7], list):
                return None
            node = next((c for c in node[7] if c[0] == piece), None)
            if node is None:
                return None
            if node[1] == L:
                node = self.getfile(posixpath.normpath("/".join((done, node[8]))))
                if node is None:
                    return None
            done = "/".join((done, piece))
        return node
class Shell:
    cwd = "/root"
    protocol = types.SimpleNamespace(fs=FS())
    def get_variable(self, name): return {"HOME": "/root"}.get(name)
p = ns["Stub"]()
p.context = Shell()
out = []
for text, mask in json.load(open(cases_path)):
    t0 = time.perf_counter()
    out.append({"names": p.qpot_pathnames(text, mask), "seconds": time.perf_counter() - t0})
out.append({"split": p.qpot_split_masked([("/etc/cron.d/", False), ("*", False), None, ("a b*", True)],
                                         [True, False, False, True])})
# one command's words share the bounds: the second 30 000-entry scan is past the first, alone it is
# not; 5000 names of 13 bytes fit the second once, not twice, and 30 000 of them never
shared = [p.QPOT_GLOB_SCAN, p.QPOT_GLOB_BYTES]
plenty = [10**9, p.QPOT_GLOB_BYTES]
# the module's cap on fnmatch's cache of compiled patterns
cap = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "qpot_cap_fnmatch_cache")
exec(compile(ast.fix_missing_locations(ast.Module(body=[cap], type_ignores=[])), src, "exec"), ns)
ns["qpot_cap_fnmatch_cache"]()
import fnmatch
matched = fnmatch.fnmatchcase("id_ed25519.pub", "id_*.pub") and not fnmatch.fnmatchcase("config", "id_*")
out.append({"shared": [p.qpot_pathnames("/mid/m00001?", "1" * 12, shared) for _ in range(2)],
            "alone": p.qpot_pathnames("/mid/m00001?", "1" * 12),
            "bytes": [len(p.qpot_pathnames("/mid/m00[0-4]*", "1" * 14, plenty)) for _ in range(2)]
                     + [len(p.qpot_pathnames("/mid/m0*", "1" * 8, [10**9, p.QPOT_GLOB_BYTES]))],
            "cache": [fnmatch._compile_pattern.cache_info().maxsize, int(matched),
                      fnmatch._compile_pattern.cache_info().currsize]})
print(json.dumps(out))
`

// globResult is what globHarness prints for one word, or for its last checks.
type globResult struct {
	Names   []string    `json:"names"`
	Seconds float64     `json:"seconds"`
	Split   [][2]string `json:"split"`
	Shared  [][]string  `json:"shared"`
	Alone   []string    `json:"alone"`
	Bytes   []int       `json:"bytes"`
	Cache   [3]int      `json:"cache"`
}

// runGlobHarness expands each [text, mask] with the patch layer's code, for a
// shell configured as shellCfg: [shell] not_found_style and bash_version, and
// os_bash, what the patch layer's coreutils derives for `bash --version`.
func runGlobHarness(t *testing.T, words [][2]string, shellCfg map[string]string) []globResult {
	t.Helper()
	py := python(t)
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cb, _ := json.Marshal(words)
	sc, _ := json.Marshal(shellCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, py, write("h.py", []byte(globHarness)), write("bashparse.py", cowrieBashparsePy),
		write("cases.json", cb), "60000", string(sc)).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, b)
	}
	var got []globResult
	if err := json.Unmarshal(b, &got); err != nil || len(got) != len(words)+2 {
		t.Fatalf("%v (%d results for %d words)\n%s", err, len(got), len(words), b)
	}
	return got
}

// globCase is a word, its mask ("" for all unquoted) and the names bash gives.
type globCase struct {
	text, mask string
	want       []string
}

func globWords(cases []globCase) [][2]string {
	var in [][2]string
	for _, c := range cases {
		m := c.mask
		if m == "" {
			m = strings.Repeat("1", len(c.text))
		}
		in = append(in, [2]string{c.text, m})
	}
	return in
}

func checkGlobCases(t *testing.T, label string, cases []globCase, got []globResult, in [][2]string) {
	t.Helper()
	for i, c := range cases {
		if strings.Join(got[i].Names, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s: %q (mask %s): %q, want %q", label, c.text, in[i][1], got[i].Names, c.want)
		}
	}
}

// TestPathnameExpansionLikeBash: the patch layer's bashparse.py expands an
// unquoted pattern to the sorted names it matches, as bash does without
// nullglob or dotglob: dotfiles only for a pattern starting with a dot, a
// pattern that matches nothing stays as typed, quoted pattern characters are
// literal, a trailing slash keeps directories, ~ is the home, [^...] negates
// and POSIX classes work in brackets; the attacker's `cat /etc/cron.d/*`, `cat
// /home/*/.bash_history` and `cat ~/.ssh/id_*` read the bait files. The
// expected names were checked against bash 5.2.37 (and, for . and .., against
// bash with globskipdots off, as before 5.2, and BusyBox 1.37 ash).
func TestPathnameExpansionLikeBash(t *testing.T) {
	cases := []globCase{
		{"/etc/cron.d/*", "", []string{"/etc/cron.d/db-backup", "/etc/cron.d/e2scrub_all"}},
		{"/home/*/.bash_history", "", []string{"/home/debian/.bash_history", "/home/ubuntu/.bash_history"}},
		{"/root/.ssh/id_*", "", []string{"/root/.ssh/id_ed25519", "/root/.ssh/id_ed25519.pub"}},
		{"~/.ssh/id_*", "", []string{"/root/.ssh/id_ed25519", "/root/.ssh/id_ed25519.pub"}},
		{"*", "", []string{"notes.txt"}},
		{".*", "", []string{".bash_history", ".ssh"}},
		{"/etc/cron.d/*", "0000000000000", []string{"/etc/cron.d/*"}}, // '/etc/cron.d/*'
		{"/nope/*", "", []string{"/nope/*"}},
		{"/home/*/", "", []string{"/home/debian/", "/home/ubuntu/"}},
		{"/home/*/.ssh/", "", []string{"/home/ubuntu/.ssh/"}},
		{"/var/backups/crm-*.sql.gz", "", []string{"/var/backups/crm-pre-release-20250101.sql.gz"}},
		{"/srv/b*?", "11111101", []string{"/srv/b*c"}}, // b\*? matches b*c only
		{"/srv/a[1].txt", "", []string{"/srv/a[1].txt"}},
		{"/srv/a?1?.txt", "", []string{"/srv/a[1].txt"}},
		{"/bin/*", "", []string{"/bin/ls"}},
		{"../root/.ssh/*.pub", "", []string{"../root/.ssh/id_ed25519.pub"}},
		{"./*.txt", "", []string{"./notes.txt"}},
		{"/root/.ssh/[ck]*", "", []string{"/root/.ssh/config"}},
		{"/root/.ssh/[!i]*", "", []string{"/root/.ssh/config"}},
		{"/etc/cron.d/[", "", []string{"/etc/cron.d/["}},
		{"/*/cron.d", "", []string{"/etc/cron.d"}},
		{"/root/.ssh/[^i]*", "", []string{"/root/.ssh/config"}},
		{"/usr/bin/[[:alpha:]]?", "", []string{"/usr/bin/ls"}},
		{"/root/.ssh/id_[[:alpha:]]*[[:digit:]]", "", []string{"/root/.ssh/id_ed25519"}},
		{"/root/.ssh/*[[:digit:]].pub", "", []string{"/root/.ssh/id_ed25519.pub"}},
		{"/srv/a?[[:digit:]]?.txt", "", []string{"/srv/a[1].txt"}},
		{"/srv/[[:upper:]]*", "", []string{"/srv/[[:upper:]]*"}},
		{"/root/.ssh/[!", "", []string{"/root/.ssh/[!"}},
		{".?", "", []string{".?"}},
		{"/root/.*", "", []string{"/root/.bash_history", "/root/.ssh"}},
		{"/srv/a[1]*", "1111110111", []string{"/srv/a[1].txt"}}, // a\[1]*: the [ is a plain character
		{"/srv/a[1]*", "1111100111", []string{"/srv/a[1].txt"}}, // "a["1]*
		// links: a broken one is a name but leads nowhere, a loop leads nowhere, a link to a directory is one
		{"/tmp/*", "", []string{"/tmp/dead"}},
		{"/tmp/dead/*", "", []string{"/tmp/dead/*"}},
		{"/loop/*", "", []string{"/loop/a", "/loop/b"}},
		{"/loop/*/x", "", []string{"/loop/*/x"}},
		{"/b*/", "", []string{"/bin/"}},
		{"/bin/l?", "", []string{"/bin/ls"}},
		{"/*/ls", "", []string{"/bin/ls"}},
		{"/usr/bin/../bin/l*", "", []string{"/usr/bin/../bin/ls"}},
		{"/root/./.ssh/c*", "", []string{"/root/./.ssh/config"}},
	}
	in := globWords(cases)
	// a directory of 60 000 entries: past the scan bound the word stays as typed
	in = append(in, [2]string{"/data/big/f*", strings.Repeat("1", len("/data/big/f*"))})
	// a long pattern matches as bash matches it (1100 stars are one)
	long := "/etc/" + strings.Repeat("*", 1100)
	in = append(in, [2]string{long, strings.Repeat("1", len(long))})
	got := runGlobHarness(t, in, map[string]string{"not_found_style": "bash",
		"os_bash": "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n"})
	checkGlobCases(t, "bash 5.2", cases, got, in)
	big := got[len(cases)]
	if strings.Join(big.Names, " ") != "/data/big/f*" || big.Seconds > 2 {
		t.Errorf("huge directory: %d names in %.2f s", len(big.Names), big.Seconds)
	}
	if names := got[len(cases)+1].Names; strings.Join(names, " ") != "/etc/cron.d" {
		t.Errorf("long pattern: %d names", len(names))
	}
	// fnmatch keeps 256 compiled patterns, not 32768, and still matches
	if c := got[len(in)+1].Cache; c[0] != 256 || c[1] != 1 || c[2] < 1 {
		t.Errorf("fnmatch cache after the patch: maxsize, matched, size = %v", c)
	}
	// the masked split keeps quoted text literal and splits an unquoted expansion as _split_fields does
	split := got[len(in)].Split
	if len(split) != 3 || split[0] != [2]string{"/etc/cron.d/*", "1111111111110"} || split[1] != [2]string{"a", "1"} ||
		split[2] != [2]string{"b*", "11"} {
		t.Errorf("masked split: %q", split)
	}
	// the words of one command share the scan bound
	last := got[len(in)+1]
	if len(last.Shared) != 2 || len(last.Shared[0]) != 10 || strings.Join(last.Shared[1], " ") != "/mid/m00001?" ||
		len(last.Alone) != 10 {
		t.Errorf("shared bound: %q, alone %d names", last.Shared, len(last.Alone))
	}
	if len(last.Bytes) != 3 || last.Bytes[0] != 5000 || last.Bytes[1] != 1 || last.Bytes[2] != 1 {
		t.Errorf("bytes bound: %v", last.Bytes)
	}

	// bash before 5.2 (the jammy, rhel-9 and centos-7 personas; from their
	// os-release, else as configured) and BusyBox ash give . and .. to a
	// pattern that starts with a dot
	dots := []globCase{
		{".*", "", []string{".", "..", ".bash_history", ".ssh"}},
		{".?", "", []string{".."}},
		{"/root/.*", "", []string{"/root/.", "/root/..", "/root/.bash_history", "/root/.ssh"}},
		{"/etc/cron.d/*", "", []string{"/etc/cron.d/db-backup", "/etc/cron.d/e2scrub_all"}},
		{"/root/.ssh/[^i]*", "", []string{"/root/.ssh/config"}},
	}
	in = globWords(dots)
	for label, cfg := range map[string]map[string]string{
		"bash 5.1":        {"not_found_style": "bash", "os_bash": "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"},
		"bash 4.2 config": {"not_found_style": "bash", "bash_version": `"GNU bash, version 4.2.46(2)-release (x86_64-redhat-linux-gnu)"`},
		"ash":             {"not_found_style": "ash"},
		"no version":      {},
		"os over config": {"os_bash": "GNU bash, version 5.2.15(1)-release (aarch64-unknown-linux-gnu)\n",
			"bash_version": `"GNU bash, version 4.2.46(2)-release (x86_64-redhat-linux-gnu)"`},
	} {
		got := runGlobHarness(t, in, cfg)
		if label == "no version" || label == "os over config" {
			// a shell that names no version, or 5.2 itself, globs as current bash does
			if strings.Join(got[0].Names, " ") != ".bash_history .ssh" {
				t.Errorf("%s: .* gives %q", label, got[0].Names)
			}
			continue
		}
		checkGlobCases(t, label, dots, got, in)
	}
}

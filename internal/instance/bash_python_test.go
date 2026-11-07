package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelpLikeBash: help prints the banner and builtins of the persona's
// bash laid out for the terminal's width, as bash 5.2.37 printed them at
// 80, 120 and 512 columns (testdata/bash-5.2.37-help-*.txt); bash 4.2 its
// own list; BusyBox ash its builtins (recorded from 1.37).
func TestHelpLikeBash(t *testing.T) {
	mk := func(persona string, env map[string]string) stubCase {
		return stubCase{"argv": []string{"help"}, "persona": persona, "env": env}
	}
	ash := func(version string) stubCase {
		c := mk("openwrt", nil)
		c["config"] = map[string]any{"shell.not_found_style": "ash", "shell.text_version": version}
		return c
	}
	// the terminal's width without COLUMNS; a pipe gets 80 columns whatever COLUMNS says (5.2.37: help |
	// sed and COLUMNS=120 help | sed gave the 80-column lines on a terminal of 160)
	wide := mk("debian-13", nil)
	wide["columns"] = 512
	piped := mk("debian-13", map[string]string{"COLUMNS": "120"})
	piped["terminal"] = false
	got := runCowrieStub(t, []stubCase{
		mk("debian-13", map[string]string{"COLUMNS": "80"}), mk("debian-13", map[string]string{"COLUMNS": "120"}),
		mk("debian-13", map[string]string{"COLUMNS": "512"}), mk("debian-13", nil),
		mk("ubuntu-24.04", map[string]string{"COLUMNS": "80"}), mk("centos-7", map[string]string{"COLUMNS": "190"}),
		ash("1.37.0"), ash("1.19.4"), wide, piped,
	})
	for i, cols := range map[int]string{0: "80", 1: "120", 2: "512", 3: "80", 8: "512", 9: "80"} {
		want, err := os.ReadFile(filepath.Join("testdata", "bash-5.2.37-help-"+cols+".txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got[i].Stdout != string(want) {
			t.Errorf("help at %s columns (case %d):\n%s\nwant\n%s", cols, i, got[i].Stdout, want)
		}
	}
	if !strings.HasPrefix(got[4].Stdout, "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)\n") ||
		strings.TrimPrefix(got[4].Stdout, "GNU bash, version 5.2.21") != strings.TrimPrefix(got[0].Stdout, "GNU bash, version 5.2.37") {
		t.Errorf("help on Ubuntu 24.04: %q", got[4].Stdout[:80])
	}
	old := got[5].Stdout
	if !strings.HasPrefix(old, "GNU bash, version 4.2.46(2)-release (x86_64-redhat-linux-gnu)\n") ||
		!strings.Contains(old, "\n job_spec [&]                                                                                   "+
			"history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]\n") ||
		!strings.Contains(old, " cd [-L|[-P [-e]]] [dir]") || strings.Contains(old, "[-@]") {
		t.Errorf("help on CentOS 7 (bash 4.2's list): %q", old)
	}
	newAsh := "Built-in commands:\n------------------\n\t. : [ [[ alias bg break cd chdir command continue echo eval exec\n" +
		"\texit export false fg getopts hash help history jobs kill let\n" +
		"\tlocal printf pwd read readonly return set shift source test times\n\ttrap true type ulimit umask unalias unset wait\n"
	if got[6].Stdout != newAsh {
		t.Errorf("ash 1.37 help:\n%q\nwant\n%q", got[6].Stdout, newAsh)
	}
	if !strings.HasPrefix(got[7].Stdout, "Built-in commands:\n------------------\n\t. : [ [[ alias bg break cd chdir command") ||
		strings.Contains(got[7].Stdout, "history") || !strings.HasSuffix(got[7].Stdout, "wait\n\n") {
		t.Errorf("ash 1.19 help: %q", got[7].Stdout)
	}
}

// TestBashVariables: the login shell has the variables bash sets (not
// exported) for the persona's bash: what `echo "$BASH_VERSION|..."` showed on
// bash 5.2.37, for each persona's release and machine; none on ash.
func TestBashVariables(t *testing.T) {
	probe := func(persona, machine string, config map[string]any) stubCase {
		c := stubCase{"probe": "bash_variables", "argv": []string{"-"}, "persona": persona, "machine": machine}
		if config != nil {
			c["config"] = config
		}
		return c
	}
	raspios := probe("debian-12", "armv7l", nil)
	raspios["files"] = map[string]any{"/etc/os-release": "ID=raspbian\nVERSION_ID=\"12\"\n"}
	cases := []struct {
		c    stubCase
		want map[string]string
	}{
		{probe("debian-13", "x86_64", nil), map[string]string{"BASH_VERSION": "5.2.37(1)-release", "BASH_VERSINFO": "5",
			"MACHTYPE": "x86_64-pc-linux-gnu", "HOSTTYPE": "x86_64", "OSTYPE": "linux-gnu", "BASH": "/bin/bash"}},
		{probe("ubuntu-24.04", "x86_64", nil), map[string]string{"BASH_VERSION": "5.2.21(1)-release", "BASH_VERSINFO": "5",
			"MACHTYPE": "x86_64-pc-linux-gnu", "HOSTTYPE": "x86_64", "OSTYPE": "linux-gnu", "BASH": "/bin/bash"}},
		{probe("ubuntu-22.04", "x86_64", nil), map[string]string{"BASH_VERSION": "5.1.16(1)-release", "BASH_VERSINFO": "5",
			"MACHTYPE": "x86_64-pc-linux-gnu", "HOSTTYPE": "x86_64", "OSTYPE": "linux-gnu", "BASH": "/bin/bash"}},
		{probe("rhel-9", "x86_64", nil), map[string]string{"BASH_VERSION": "5.1.8(1)-release", "BASH_VERSINFO": "5",
			"MACHTYPE": "x86_64-redhat-linux-gnu", "HOSTTYPE": "x86_64", "OSTYPE": "linux-gnu", "BASH": "/bin/bash"}},
		{probe("centos-7", "x86_64", map[string]any{"shell.login_shell": "/usr/bin/bash"}), map[string]string{
			"BASH_VERSION": "4.2.46(2)-release", "BASH_VERSINFO": "4", "MACHTYPE": "x86_64-redhat-linux-gnu",
			"HOSTTYPE": "x86_64", "OSTYPE": "linux-gnu", "BASH": "/usr/bin/bash"}},
		{raspios, map[string]string{"BASH_VERSION": "5.2.15(1)-release", "BASH_VERSINFO": "5",
			"MACHTYPE": "arm-unknown-linux-gnueabihf", "HOSTTYPE": "arm", "OSTYPE": "linux-gnueabihf", "BASH": "/bin/bash"}},
		{probe("openwrt", "mips", map[string]any{"shell.not_found_style": "ash"}), map[string]string{}},
		// a Debian tree whose login shell is ash: no bash, none of its variables
		{probe("debian-12", "x86_64", map[string]any{"shell.not_found_style": "ash"}), map[string]string{}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		var env map[string]string
		if err := json.Unmarshal([]byte(got[i].Stdout), &env); err != nil {
			t.Fatalf("case %d: %v %q", i, err, got[i].Stdout)
		}
		for _, name := range []string{"BASH_VERSION", "BASH_VERSINFO", "MACHTYPE", "HOSTTYPE", "OSTYPE", "BASH"} {
			if env[name] != c.want[name] {
				t.Errorf("%s on %s: %q, want %q", name, c.c["persona"], env[name], c.want[name])
			}
		}
		if env["HOME"] != "/root" {
			t.Errorf("case %d: HOME %q", i, env["HOME"])
		}
	}
}

// subscriptHarness runs bashparse.py's qpot_subscript (taken out by its
// source) and its grammar's BRACE_NAME on the cases: ${NAME[INDEX]} of a
// shell that keeps no arrays.
const subscriptHarness = `
import ast, json, re, sys, time
src = open(sys.argv[1], encoding="utf-8").read()
fn = next(n for n in ast.parse(src).body if isinstance(n, ast.FunctionDef) and n.name == "qpot_subscript")
ns = {"re": re}
exec(compile(ast.Module([fn], []), "bashparse.py", "exec"), ns)
brace = re.compile(re.search(r"^BRACE_NAME: /(.*)/$", src, re.M).group(1))
class Context:
    def __init__(self, env): self.env = env
    def get_variable(self, name): return self.env.get(name)
out = []
for case in json.load(open(sys.argv[2])):
    m = brace.fullmatch(case["name"])
    t0 = time.process_time()
    long = brace.match("A[" + "9" * 200000 + "]")
    took = time.process_time() - t0
    value = ns["qpot_subscript"](Context(case["env"]), case["name"]) if m and case["name"].endswith("]") else None
    out.append({"match": bool(m), "value": value, "took": took})
print(json.dumps(out))
`

// TestBashSubscripts: ${BASH_VERSINFO[n]}, ${BASH_VERSINFO[@]} and
// ${VAR[0]} expand as in bash ("5 2 37 1 release x86_64-pc-linux-gnu" on
// 5.2.37); an index past the end is empty; an index longer than nine digits
// is no subscript the grammar takes, and a long one is refused in linear
// time.
func TestBashSubscripts(t *testing.T) {
	py := python(t)
	dir := t.TempDir()
	env := map[string]string{"BASH_VERSION": "5.2.37(1)-release", "MACHTYPE": "x86_64-pc-linux-gnu", "HOME": "/root"}
	type sc struct {
		Name  string            `json:"name"`
		Env   map[string]string `json:"env"`
		match bool
		value string
	}
	cases := []sc{
		{"BASH_VERSINFO[0]", env, true, "5"}, {"BASH_VERSINFO[1]", env, true, "2"}, {"BASH_VERSINFO[2]", env, true, "37"},
		{"BASH_VERSINFO[3]", env, true, "1"}, {"BASH_VERSINFO[4]", env, true, "release"},
		{"BASH_VERSINFO[5]", env, true, "x86_64-pc-linux-gnu"}, {"BASH_VERSINFO[6]", env, true, ""},
		{"BASH_VERSINFO[@]", env, true, "5 2 37 1 release x86_64-pc-linux-gnu"},
		{"BASH_VERSINFO[*]", env, true, "5 2 37 1 release x86_64-pc-linux-gnu"},
		{"HOME[0]", env, true, "/root"}, {"HOME[1]", env, true, ""}, {"HOME[@]", env, true, "/root"},
		{"NOPE[0]", env, true, ""}, {"BASH_VERSINFO[0]", map[string]string{}, true, ""},
		{"HOME[1234567890]", env, false, ""}, {"HOME[-1]", env, false, ""}, {"HOME[x]", env, false, ""},
		{"0A[0]", env, false, ""}, {"HOME", env, true, ""},
	}
	spec, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	out, err := exec.Command(py, write("h.py", []byte(subscriptHarness)), write("bashparse.py", cowrieBashparsePy),
		write("cases.json", spec)).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var got []struct {
		Match bool    `json:"match"`
		Value *string `json:"value"`
		Took  float64 `json:"took"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("%v: %s", err, out)
	}
	for i, c := range cases {
		value := ""
		if got[i].Value != nil {
			value = *got[i].Value
		}
		if got[i].Match != c.match || value != c.value {
			t.Errorf("${%s}: match %v value %q, want %v %q", c.Name, got[i].Match, value, c.match, c.value)
		}
		if got[i].Took > 0.05 {
			t.Errorf("a 200000-digit index took %.3f s", got[i].Took)
		}
	}
}

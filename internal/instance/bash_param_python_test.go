package instance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// paramHarness runs bashparse.py's parameter expansion (its qpot_param_
// functions and constants, taken out by their source so lark need not be
// installed) and its grammar's BRACE_EXPR on the cases. Command substitution
// answers <its source>, $(( )) the sum of the integers in it.
const paramHarness = `
import ast, asyncio, fnmatch, json, re, sys, time
src = open(sys.argv[1], encoding="utf-8").read()
keep = []
for node in ast.parse(src).body:
    name = getattr(node, "name", "")
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            name.startswith("qpot_param_") or name in ("qpot_subscript", "tpot_arith_close")):
        keep.append(node)
    elif isinstance(node, ast.ClassDef) and name == "TpotArithError":
        keep.append(node)
    elif isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "").startswith("QPOT_PARAM_"):
        keep.append(node)
style = ["bash"]
async def tpot_arith_value(context, body, level=0):
    total = 0
    for piece in re.findall(r"[-+]?\s*[A-Za-z_0-9]+", body):
        sign = -1 if piece.strip().startswith("-") else 1
        word = piece.strip().lstrip("+-").strip()
        total += sign * int(word if word.isdigit() else context.get_variable(word) or 0)
    return str(total)
ns = {"re": re, "fnmatch": fnmatch, "tpot_arith_style": lambda: style[0], "tpot_arith_value": tpot_arith_value,
      "tpot_shell_pid": lambda context: "4242"}
exec(compile(ast.Module(keep, []), "bashparse.py", "exec"), ns)
brace = re.compile(re.search(r"^BRACE_EXPR: /(.*)/s$", src, re.M).group(1), re.S)
name_only = re.compile(re.search(r"^BRACE_NAME: /(.*)/$", src, re.M).group(1))
class Context:
    def __init__(self, env, interactive):
        self.environ, self.interactive = dict(env), interactive
    def get_variable(self, name): return self.environ.get(name)
    def get_status(self): return "3"
    async def command_substitution(self, source): return "<" + source + ">"
out = []
for case in json.load(open(sys.argv[2])):
    style[0] = case.get("style") or "bash"
    context = Context(case["env"], case.get("interactive", False))
    text = case["text"]
    row = {"match": bool(brace.fullmatch(text)), "both": bool(brace.fullmatch(text)) and bool(name_only.fullmatch(text))}
    t0 = time.process_time()
    try:
        row["value"] = asyncio.run(ns["qpot_param_value"](context, text, 0, case.get("quoted", False)))
    except ns["TpotArithError"] as err:
        row["error"], row["status"], row["ash"] = err.message, err.status, err.ash
    row["took"] = time.process_time() - t0
    row["after"] = context.environ.get(case.get("then") or "", "")
    out.append(row)
print(json.dumps(out))
`

type paramCase struct {
	Text        string            `json:"text"`
	Env         map[string]string `json:"env"`
	Style       string            `json:"style,omitempty"`
	Quoted      bool              `json:"quoted,omitempty"`
	Interactive bool              `json:"interactive,omitempty"`
	Then        string            `json:"then,omitempty"`
}

type paramResult struct {
	Match  bool    `json:"match"`
	Both   bool    `json:"both"`
	Value  *string `json:"value"`
	Error  string  `json:"error"`
	Status int     `json:"status"`
	Ash    bool    `json:"ash"`
	Took   float64 `json:"took"`
	After  string  `json:"after"`
}

func runParamHarness(t *testing.T, cases []paramCase) []paramResult {
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
	spec, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, write("h.py", []byte(paramHarness)), write("bashparse.py", cowrieBashparsePy),
		write("cases.json", spec)).CombinedOutput()
	if err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	var got []paramResult
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("%v: %s", err, out)
	}
	return got
}

// TestBashParameterExpansion: ${NAME} with an operator expands as bash 5.2
// expands it (each value below is what bash printed for the same variables),
// where the image's shell answered "syntax error: unexpected end of file" to
// every one of them, so a line like ARCH=${1:-$(uname -m)} never ran.
func TestBashParameterExpansion(t *testing.T) {
	env := map[string]string{"HOME": "/root", "FILE": "/var/log/app/error.log.gz", "EMPTY": "", "X": "hello world",
		"N": "5", "U": "Abc", "P": "HOME", "1": "one", "2": "two", "#": "2", "@": "one two", "*": "one two"}
	cases := []struct {
		text, want string
		quoted     bool
	}{
		{"NOPE:-x", "x", false}, {"NOPE-x", "x", false}, {"EMPTY:-x", "x", false}, {"EMPTY-x", "", false},
		{"HOME:-x", "/root", false}, {"NOPE:-$HOME", "/root", false}, {"NOPE:-${HOME}/bin", "/root/bin", false},
		{`NOPE:-"a b"`, "a b", true}, {`NOPE:-"a b"`, "a b", false},
		// single quotes and a tilde are themselves inside double quotes, and are read outside them
		{"NOPE:-'$HOME'", "'/root'", true}, {"NOPE:-'$HOME'", "$HOME", false},
		{"NOPE:-~/x", "~/x", true}, {"NOPE:-~/x", "/root/x", false},
		{`NOPE:-\$5`, "$5", true}, {"NOPE:-${NOPE2:-deep}", "deep", true},
		{"NOPE:-$(uname -m)", "<uname -m>", false}, {"NOPE:-`id -u`", "<id -u>", false}, {"NOPE:-$((1+2))", "3", false},
		{"NOPE:-$? $$ $#", "3 4242 2", false},
		{"1:-def", "one", false}, {"3:-def", "def", false}, {"@:-none", "one two", false},
		{"HOME:=z", "/root", false}, {"EMPTY?", "", false}, {"HOME:?x", "/root", false},
		{"HOME:+set", "set", false}, {"NOPE:+set", "", false}, {"EMPTY:+set", "", false}, {"EMPTY+set", "set", false},
		{"#HOME", "5", false}, {"#NOPE", "0", false}, {"#X", "11", false}, {"#@", "2", false}, {"#1", "3", false},
		{"!P", "/root", false},
		{"FILE##*/", "error.log.gz", false}, {"FILE#*/", "var/log/app/error.log.gz", false},
		{"FILE%.*", "/var/log/app/error.log", false}, {"FILE%%.*", "/var/log/app/error", false},
		{"FILE%/*", "/var/log/app", false}, {"FILE#/var", "/log/app/error.log.gz", false},
		{"FILE%.gz", "/var/log/app/error.log", false}, {"FILE#nomatch", "/var/log/app/error.log.gz", false},
		{"FILE##*.", "gz", false}, {"X%% *", "hello", false}, {"X#*", "hello world", false}, {"X##*", "", false},
		{"X/o/0", "hell0 world", false}, {"X//o/0", "hell0 w0rld", false}, {"X/#hello/bye", "bye world", false},
		{"X/%world/all", "hello all", false}, {"X//l", "heo word", false}, {"X/l*o/L", "heLrld", false},
		{"X/ /_", "hello_world", false}, {`FILE//\//_`, "_var_log_app_error.log.gz", false},
		{"X/?/Q", "Qello world", false}, {"X//[lo]/_", "he___ w_r_d", false}, {"X/#h*o/J", "Jrld", false},
		{"X/%o*/J", "hellJ", false}, {"FILE/log/LOG", "/var/LOG/app/error.log.gz", false},
		{"X:0:5", "hello", false}, {"X:6", "world", false}, {"X: -5", "world", false}, {"X:0:-6", "hello", false},
		{"X:20", "", false}, {"X:N", " world", false}, {"X:1+1:3", "llo", false},
		{"U^^", "ABC", false}, {"U,,", "abc", false}, {"X^", "Hello world", false}, {"U,", "abc", false},
		{"X^^[aeiou]", "hEllO wOrld", false},
	}
	var spec []paramCase
	for _, c := range cases {
		spec = append(spec, paramCase{Text: c.text, Env: env, Quoted: c.quoted})
	}
	got := runParamHarness(t, spec)
	for i, c := range cases {
		if got[i].Value == nil || *got[i].Value != c.want || !got[i].Match || got[i].Both {
			value := "an error: " + got[i].Error
			if got[i].Value != nil {
				value = *got[i].Value
			}
			t.Errorf("${%s} (quoted %v): %q, want %q (the grammar takes it: %v, as a plain name too: %v)",
				c.text, c.quoted, value, c.want, got[i].Match, got[i].Both)
		}
	}

	// := sets the variable; what the shell says where it cannot expand, and the status it ends with
	// (bash 5.2: 1 at a prompt, 127 for the shell of a script; BusyBox ash 1.37: 2)
	errs := []struct {
		c      paramCase
		value  string
		err    string
		status int
		after  string
	}{
		{paramCase{Text: "NOPE:=made", Env: env, Then: "NOPE"}, "made", "", 0, "made"},
		{paramCase{Text: "3:=x", Env: env}, "", "$3: cannot assign in this way", 1, ""},
		{paramCase{Text: "NOPE:?gone", Env: env}, "", "NOPE: gone", 127, ""},
		{paramCase{Text: "NOPE:?gone", Env: env, Interactive: true}, "", "NOPE: gone", 1, ""},
		{paramCase{Text: "NOPE:?", Env: env, Interactive: true}, "", "NOPE: parameter null or not set", 1, ""},
		{paramCase{Text: "NOPE?", Env: env, Interactive: true}, "", "NOPE: parameter not set", 1, ""},
		{paramCase{Text: "X:", Env: env}, "", "${X:}: bad substitution", 1, ""},
		{paramCase{Text: "X:0:-20", Env: env}, "", "-20: substring expression < 0", 1, ""},
		{paramCase{Text: "NOPE:?gone", Env: env, Style: "ash"}, "", "NOPE: gone", 2, ""},
		{paramCase{Text: "NOPE:?", Env: env, Style: "ash"}, "", "NOPE: parameter not set or null", 2, ""},
		{paramCase{Text: "X^^", Env: env, Style: "ash"}, "", "syntax error: bad substitution", 2, ""},
		{paramCase{Text: "!P", Env: env, Style: "ash"}, "", "syntax error: bad substitution", 2, ""},
		{paramCase{Text: "X:0:5", Env: env, Style: "ash"}, "hello", "", 0, ""},
		{paramCase{Text: "X//o/0", Env: env, Style: "ash"}, "hell0 w0rld", "", 0, ""},
		{paramCase{Text: "NOPE:-x", Env: env, Style: "ash"}, "x", "", 0, ""},
	}
	spec = spec[:0]
	for _, e := range errs {
		spec = append(spec, e.c)
	}
	got = runParamHarness(t, spec)
	for i, e := range errs {
		value := ""
		if got[i].Value != nil {
			value = *got[i].Value
		}
		if value != e.value || got[i].Error != e.err || got[i].Status != e.status || got[i].After != e.after ||
			got[i].Ash != (e.c.Style == "ash" && e.err != "") {
			t.Errorf("${%s} (%s): %q, error %q status %d, variable %q; want %q, %q %d, %q",
				e.c.Text, e.c.Style, value, got[i].Error, got[i].Status, got[i].After, e.value, e.err, e.status, e.after)
		}
	}

	// what the grammar leaves to its other rules or refuses, as before: a plain name, a special
	// parameter, a subscript, an operator bash does not have here, braces in the word, two levels of ${
	for _, text := range []string{"HOME", "#", "?", "X[0]", "X@Q", "X:-{a}", "X:-${Y:-${Z}}", "", "-x", "X:-a}b", "9x:-y"} {
		if r := runParamHarness(t, []paramCase{{Text: text, Env: env}}); r[0].Match {
			t.Errorf("the grammar takes ${%s} as a parameter with an operator", text)
		}
	}

	// a long value and a pattern full of wildcards: every cut of the value is tried, so both are
	// bounded; beyond the bound the value comes back as it is, at once
	long := map[string]string{"L": strings.Repeat("a", 200000), "S": strings.Repeat("a", 2000)}
	slow := runParamHarness(t, []paramCase{
		{Text: "L%%*a*a*a*b", Env: long}, {Text: "L//a*a*a*b/x", Env: long}, {Text: "S##*a*a*a*a*a*b", Env: long},
		{Text: "S//a*a*b/x", Env: long}, {Text: "L^^", Env: long}, {Text: "#L", Env: long},
	})
	for i, r := range slow {
		if r.Value == nil || r.Took > 2 {
			t.Errorf("costly expansion %d: %.2f s, error %q", i, r.Took, r.Error)
		}
	}
	if *slow[5].Value != "200000" || len(*slow[0].Value) != 200000 || len(*slow[2].Value) != 2000 {
		t.Errorf("costly expansions changed the value: %q, %d, %d", *slow[5].Value, len(*slow[0].Value), len(*slow[2].Value))
	}
}

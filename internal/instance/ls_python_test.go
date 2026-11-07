package instance

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The output these tests compare with was recorded from GNU coreutils 9.7
// (Debian 13) in the C locale and UTC, on files made as the cases make them.

// TestLsLikeGNULs: ls -l's link counts, dates and total line, several
// operands under their names, -h, and the columns of a terminal, as GNU ls
// 9.7 gave them for the same files.
func TestLsLikeGNULs(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 59, 0, 0, time.UTC).Unix()
	at := func(s string) int64 {
		v, err := time.Parse("2006-01-02 15:04", s)
		if err != nil {
			t.Fatal(err)
		}
		return v.Unix()
	}
	recent := at("2026-11-07 12:58")
	files := map[string]any{
		"/a/big.sql.gz": map[string]any{"text": strings.Repeat("z", 33437), "mtime": recent},
		"/a/empty":      map[string]any{"text": "", "mtime": recent},
		"/a/future":     map[string]any{"text": "", "mtime": at("2026-11-10 05:20")},
		"/a/h10239":     map[string]any{"text": strings.Repeat("z", 10239), "mtime": recent},
		"/a/h1048575":   map[string]any{"text": "", "size": 1048575, "mtime": recent},
		"/a/h4097":      map[string]any{"text": strings.Repeat("z", 4097), "mtime": recent},
		"/a/longlink":   map[string]any{"link": strings.Repeat("x", 70), "mtime": recent},
		"/a/old":        map[string]any{"text": "", "mtime": at("2025-10-17 19:04")},
		"/a/recent":     map[string]any{"text": "", "mtime": at("2026-11-05 05:20")},
		"/a/short":      map[string]any{"link": "big.sql.gz", "mtime": recent},
		"/a/sub1":       map[string]any{"dir": true, "mtime": recent},
		"/a/sub2":       map[string]any{"dir": true, "mtime": recent},
		"/c/empty":      map[string]any{"dir": true, "mtime": recent},
	}
	for _, n := range strings.Fields("alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi rho sigma " +
		"tau upsilon phi chi psi omega") {
		files["/b/"+n] = map[string]any{"text": "", "mtime": recent}
	}
	mk := func(columns int, terminal bool, argv ...string) stubCase {
		return stubCase{"argv": argv, "persona": "debian-13", "files": files, "now": now, "cwd": "/", "terminal": terminal,
			"columns": columns, "mtime": recent}
	}
	long := "total 1092\n" +
		"-rw-r--r-- 1 root root   33437 Nov  7 12:58 big.sql.gz\n" +
		"-rw-r--r-- 1 root root       0 Nov  7 12:58 empty\n" +
		"-rw-r--r-- 1 root root       0 Nov 10  2026 future\n" +
		"-rw-r--r-- 1 root root   10239 Nov  7 12:58 h10239\n" +
		"-rw-r--r-- 1 root root 1048575 Nov  7 12:58 h1048575\n" +
		"-rw-r--r-- 1 root root    4097 Nov  7 12:58 h4097\n" +
		"lrwxrwxrwx 1 root root      70 Nov  7 12:58 longlink -> " + strings.Repeat("x", 70) + "\n" +
		"-rw-r--r-- 1 root root       0 Oct 17  2025 old\n" +
		"-rw-r--r-- 1 root root       0 Nov  5 05:20 recent\n" +
		"lrwxrwxrwx 1 root root      10 Nov  7 12:58 short -> big.sql.gz\n" +
		"drwxr-xr-x 2 root root    4096 Nov  7 12:58 sub1\n" +
		"drwxr-xr-x 2 root root    4096 Nov  7 12:58 sub2\n"
	human := "total 1.1M\n" +
		"-rw-r--r-- 1 root root  33K Nov  7 12:58 big.sql.gz\n" +
		"-rw-r--r-- 1 root root    0 Nov  7 12:58 empty\n" +
		"-rw-r--r-- 1 root root    0 Nov 10  2026 future\n" +
		"-rw-r--r-- 1 root root  10K Nov  7 12:58 h10239\n" +
		"-rw-r--r-- 1 root root 1.0M Nov  7 12:58 h1048575\n" +
		"-rw-r--r-- 1 root root 4.1K Nov  7 12:58 h4097\n" +
		"lrwxrwxrwx 1 root root   70 Nov  7 12:58 longlink -> " + strings.Repeat("x", 70) + "\n" +
		"-rw-r--r-- 1 root root    0 Oct 17  2025 old\n" +
		"-rw-r--r-- 1 root root    0 Nov  5 05:20 recent\n" +
		"lrwxrwxrwx 1 root root   10 Nov  7 12:58 short -> big.sql.gz\n" +
		"drwxr-xr-x 2 root root 4.0K Nov  7 12:58 sub1\n" +
		"drwxr-xr-x 2 root root 4.0K Nov  7 12:58 sub2\n"
	bOne := strings.Join([]string{"alpha", "beta", "chi", "delta", "epsilon", "eta", "gamma", "iota", "kappa", "lambda", "mu",
		"nu", "omega", "omicron", "phi", "pi", "psi", "rho", "sigma", "tau", "theta", "upsilon", "xi", "zeta"}, "\n") + "\n"
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{mk(80, false, "ls", "-l", "a"), stubWant{long, "", 0, -1}},
		{mk(80, false, "ls", "-lh", "a"), stubWant{human, "", 0, -1}},
		{mk(80, false, "ls", "a/empty", "b", "nope", "c", "a/old"), stubWant{"a/empty\na/old\n\nb:\n" + bOne + "\nc:\nempty\n",
			"ls: cannot access 'nope': No such file or directory\n", 2, -1}},
		{mk(80, false, "ls", "-l", "c", "a/old", "nope"), stubWant{"-rw-r--r-- 1 root root 0 Oct 17  2025 a/old\n\nc:\ntotal 4\n" +
			"drwxr-xr-x 2 root root 4096 Nov  7 12:58 empty\n", "ls: cannot access 'nope': No such file or directory\n", 2, -1}},
		{mk(80, false, "ls", "nope", "c"), stubWant{"c:\nempty\n", "ls: cannot access 'nope': No such file or directory\n", 2, -1}},
		{mk(80, false, "ls", "-ld", "a", "b", "c"), stubWant{"drwxr-xr-x 4 root root 4096 Nov  7 12:58 a\n" +
			"drwxr-xr-x 2 root root 4096 Nov  7 12:58 b\ndrwxr-xr-x 3 root root 4096 Nov  7 12:58 c\n", "", 0, -1}},
		{mk(80, false, "ls", "-l", "c/empty"), stubWant{"total 0\n", "", 0, -1}},
		{mk(80, true, "ls", "b"), stubWant{"alpha  delta\tgamma  lambda  omega\tpi   sigma  upsilon\n" +
			"beta   epsilon\tiota   mu      omicron\tpsi  tau    xi\n" +
			"chi    eta\tkappa  nu      phi\trho  theta  zeta\n", "", 0, -1}},
		{mk(40, true, "ls", "b"), stubWant{"alpha\t gamma\t omega\t  sigma\nbeta\t iota\t omicron  tau\n" +
			"chi\t kappa\t phi\t  theta\ndelta\t lambda  pi\t  upsilon\nepsilon  mu\t psi\t  xi\neta\t nu\t rho\t  zeta\n", "", 0, -1}},
		{mk(80, true, "ls", "a"), stubWant{"big.sql.gz  future  h1048575  longlink\trecent\tsub1\n" +
			"empty\t    h10239  h4097     old\tshort\tsub2\n", "", 0, -1}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, argvLabel(c.c), got[i], c.want)
	}
	// -la: . and .. counted in the total; / (with a, b, c, etc, root, tmp) has its block
	la := runCowrieStub(t, []stubCase{mk(80, false, "ls", "-la", "a"), mk(80, false, "ls", "-ld", "/")})
	if !strings.HasPrefix(la[0].Stdout, "total 1100\ndrwxr-xr-x 4 root root    4096 Nov  7 12:58 .\n"+
		"drwxr-xr-x 8 root root    4096 ") {
		t.Errorf("ls -la: %q", la[0].Stdout)
	}
	if !strings.HasPrefix(la[1].Stdout, "drwxr-xr-x 8 root root 4096 ") {
		t.Errorf("ls -ld /: %q", la[1].Stdout)
	}
}

// TestStatAgreesWithLs: for every node of a random tree, stat's size, mode,
// links and blocks are the ones ls -l shows and counts in its total.
func TestStatAgreesWithLs(t *testing.T) {
	files := map[string]any{"/proc/mounts": "/dev/vda1 / ext4 rw 0 0\n"}
	for i := 0; i < 40; i++ {
		files[fmt.Sprintf("/w/f%02d", i)] = map[string]any{"text": strings.Repeat("x", i*i*37), "mode": 0o600 + i%3*0o44}
		if i%5 == 0 {
			files[fmt.Sprintf("/w/d%02d/sub", i)] = map[string]any{"dir": true}
			files[fmt.Sprintf("/w/d%02d/x", i)] = "y"
		}
		if i%7 == 0 && i > 0 {
			files[fmt.Sprintf("/w/l%02d", i)] = map[string]any{"link": strings.Repeat("t", i*3)}
		}
	}
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC).Unix()
	ls := stubCase{"argv": []string{"ls", "-la", "/w"}, "persona": "debian-13", "files": files, "now": now}
	st := stubCase{"argv": []string{"stat", "-c", "%n %s %A %h %b", "/w", "/w/.."}, "persona": "debian-13", "files": files}
	var names []string
	for p := range files {
		if strings.HasPrefix(p, "/w/") && strings.Count(p, "/") == 2 {
			names = append(names, p)
		}
	}
	names = append(names, "/w/d00", "/w/d05", "/w/d10", "/w/d15", "/w/d20", "/w/d25", "/w/d30", "/w/d35")
	st["argv"] = append(st["argv"].([]string), names...)
	got := runCowrieStub(t, []stubCase{ls, st})
	byName := map[string][]string{}
	total := 0
	for _, line := range strings.Split(strings.TrimSpace(got[1].Stdout), "\n") {
		f := strings.Fields(line)
		byName[f[0]] = f[1:]
	}
	lines := strings.Split(strings.TrimSpace(got[0].Stdout), "\n")
	if !strings.HasPrefix(lines[0], "total ") {
		t.Fatalf("ls -la: %q", got[0].Stdout)
	}
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		name := f[len(f)-1]
		if strings.Contains(line, " -> ") {
			name = f[len(f)-3]
		}
		path := "/w/" + name
		if name == "." {
			path = "/w"
		} else if name == ".." {
			path = "/w/.."
		}
		s, ok := byName[path]
		if !ok {
			t.Errorf("stat lacks %s", path)
			continue
		}
		// ls: mode links user group size; stat: size mode links blocks
		if f[0] != s[1] || f[1] != s[2] || f[4] != s[0] {
			t.Errorf("%s: ls %v, stat %v", path, f[:5], s)
		}
		var blocks int
		fmt.Sscan(s[3], &blocks)
		total += blocks / 2
	}
	if lines[0] != fmt.Sprintf("total %d", total) {
		t.Errorf("ls says %q, stat's blocks sum to %d", lines[0], total)
	}
}

// TestLsFormatsLikeGNULs: the format the last of -l, -1, -C and -x asks
// for (-1 not after -l), the width of -w (0 or one too large: no limit, and
// blanks only) or of the terminal (an exported COLUMNS only for a pipe), the
// tab size of -T, and getopt's messages, as GNU ls 9.7 gave them.
func TestLsFormatsLikeGNULs(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 59, 0, 0, time.UTC).Unix()
	recent := time.Date(2026, 11, 7, 12, 58, 0, 0, time.UTC).Unix()
	files := map[string]any{}
	names := strings.Fields("alpha beta chi delta epsilon eta gamma iota kappa lambda mu nu omega omicron phi pi psi rho " +
		"sigma tau theta upsilon xi zeta")
	for _, n := range names {
		files["/b/"+n] = map[string]any{"text": "", "mtime": recent}
	}
	mk := func(columns int, terminal bool, env map[string]any, argv ...string) stubCase {
		c := stubCase{"argv": argv, "persona": "debian-13", "files": files, "now": now, "cwd": "/b", "terminal": terminal,
			"columns": columns, "mtime": recent}
		if env != nil {
			c["env"] = env
		}
		return c
	}
	pipe := func(argv ...string) stubCase { return mk(80, false, nil, argv...) }
	with := func(c stubCase, key string, value any) stubCase { c[key] = value; return c }
	one := strings.Join(names, "\n") + "\n"
	// one line of all the names: blanks only, or with the tab that "pi" reaches (column 96)
	row := func(sep string) string {
		return strings.Join(names[:15], "  ") + sep + strings.Join(names[15:], "  ") + "\n"
	}
	c80 := "alpha  delta\tgamma  lambda  omega\tpi   sigma  upsilon\nbeta   epsilon\tiota   mu      omicron\tpsi  tau    xi\n" +
		"chi    eta\tkappa  nu      phi\trho  theta  zeta\n"
	c40 := "alpha\t gamma\t omega\t  sigma\nbeta\t iota\t omicron  tau\nchi\t kappa\t phi\t  theta\ndelta\t lambda  pi\t  upsilon\n" +
		"epsilon  mu\t psi\t  xi\neta\t nu\t rho\t  zeta\n"
	w30 := "alpha\t kappa\t  psi\nbeta\t lambda   rho\nchi\t mu\t  sigma\ndelta\t nu\t  tau\nepsilon  omega\t  theta\n" +
		"eta\t omicron  upsilon\ngamma\t phi\t  xi\niota\t pi\t  zeta\n"
	x40 := "alpha  beta\tchi    delta\tepsilon\neta    gamma\tiota   kappa\tlambda\nmu     nu\tomega  omicron\tphi\n" +
		"pi     psi\trho    sigma\ttau\ntheta  upsilon\txi     zeta\n"
	x30 := "alpha\t beta\t  chi\ndelta\t epsilon  eta\ngamma\t iota\t  kappa\nlambda\t mu\t  nu\nomega\t omicron  phi\n" +
		"pi\t psi\t  rho\nsigma\t tau\t  theta\nupsilon  xi\t  zeta\n"
	long := "-rw-r--r-- 1 root root 0 Nov  7 12:58 alpha\n-rw-r--r-- 1 root root 0 Nov  7 12:58 beta\n"
	hint := "Try 'ls --help' for more information.\n"
	warn := func(value string) string {
		return "ls: ignoring invalid width in environment variable COLUMNS: ‘" + value + "’\n"
	}
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{pipe("ls", "-C"), stubWant{c80, "", 0, -1}},
		{pipe("ls", "-C", "-w", "40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-w", "40", "-C"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-Cw40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "--width", "30", "-C"), stubWant{w30, "", 0, -1}},
		{pipe("ls", "--wid=30", "-C"), stubWant{w30, "", 0, -1}},
		{pipe("ls", "--width=40", "-x"), stubWant{x40, "", 0, -1}},
		{pipe("ls", "-x", "-w", "30"), stubWant{x30, "", 0, -1}},
		{pipe("ls", "-C", "-w", "0"), stubWant{row("  "), "", 0, -1}},
		{pipe("ls", "-x", "-w", "0"), stubWant{row("  "), "", 0, -1}},
		{pipe("ls", "-C", "-w", "99999999999999999999"), stubWant{row("  "), "", 0, -1}},
		{pipe("ls", "-C", "-w", "1000"), stubWant{row("\t"), "", 0, -1}},
		{pipe("ls", "-C", "-w", "1"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-1C"), stubWant{c80, "", 0, -1}},
		{pipe("ls", "-C1"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-l", "-1", "alpha", "beta"), stubWant{long, "", 0, -1}},
		{pipe("ls", "-1", "-l", "alpha", "beta"), stubWant{long, "", 0, -1}},
		{pipe("ls", "-l", "-C", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{pipe("ls", "-lC", "-w", "30", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{pipe("ls", "-Cl", "alpha", "beta"), stubWant{long, "", 0, -1}},
		{pipe("ls", "-T", "0", "-C", "-w", "50"), stubWant{"alpha  epsilon  kappa   omega    psi    theta\n" +
			"beta   eta      lambda  omicron  rho    upsilon\nchi    gamma    mu      phi      sigma  xi\n" +
			"delta  iota     nu      pi       tau    zeta\n", "", 0, -1}},
		{pipe("ls", "--tabsize=4", "-x", "-w", "50"), stubWant{"alpha  beta\t\tchi    delta\tepsilon  eta\n" +
			"gamma  iota\t\tkappa  lambda\tmu\t\t nu\nomega  omicron\tphi    pi\t\tpsi\t\t rho\n" +
			"sigma  tau\t\ttheta  upsilon\txi\t\t zeta\n", "", 0, -1}},
		{pipe("ls", "-T", "4", "-C", "-w", "50"), stubWant{"alpha  epsilon\tkappa\tomega\t psi\ttheta\n" +
			"beta   eta\t\tlambda\tomicron  rho\tupsilon\nchi    gamma\tmu\t\tphi\t\t sigma\txi\n" +
			"delta  iota\t\tnu\t\tpi\t\t tau\tzeta\n", "", 0, -1}},
		// the terminal's width wins over an exported COLUMNS (a terminal of 0 columns has none); a pipe
		// takes COLUMNS (0: no limit), not a shell variable of that name
		{mk(60, true, map[string]any{"COLUMNS": "40"}, "ls"), stubWant{c80, "", 0, -1}},
		{mk(0, true, map[string]any{"COLUMNS": "40"}, "ls"), stubWant{c40, "", 0, -1}},
		{mk(0, true, nil, "ls"), stubWant{c80, "", 0, -1}},
		{with(pipe("ls", "-C"), "shellvars", map[string]any{"COLUMNS": "40"}), stubWant{c80, "", 0, -1}},
		// a COLUMNS ls cannot read is warned of, once and first, where -C or -x would read it
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-C", "alpha", "beta"), stubWant{"alpha  beta\n", warn("x"), 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-x", "alpha", "beta"), stubWant{"alpha  beta\n", warn("x"), 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "-1"}, "ls", "-C", "alpha"), stubWant{"alpha\n", warn("-1"), 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": " "}, "ls", "-C", "alpha"), stubWant{"alpha\n", warn(" "), 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "40k"}, "ls", "-C", "alpha"), stubWant{"alpha\n", warn("40k"), 0, -1}},
		{mk(0, true, map[string]any{"COLUMNS": "x"}, "ls", "alpha", "beta"), stubWant{"alpha  beta\n", warn("x"), 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-C", "nope", "alpha", "beta"), stubWant{"alpha  beta\n",
			warn("x") + "ls: cannot access 'nope': No such file or directory\n", 2, -1}},
		{mk(80, false, map[string]any{"COLUMNS": ""}, "ls", "-C", "alpha"), stubWant{"alpha\n", "", 0, -1}},
		{mk(50, true, map[string]any{"COLUMNS": "x"}, "ls", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-C", "-w", "40", "alpha"), stubWant{"alpha\n", "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-1", "alpha", "beta"), stubWant{"alpha\nbeta\n", "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "alpha", "beta"), stubWant{"alpha\nbeta\n", "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "x"}, "ls", "-l", "alpha", "beta"), stubWant{long, "", 0, -1}},
		{mk(60, true, nil, "ls", "-1"), stubWant{one, "", 0, -1}},
		{mk(60, true, nil, "ls", "-w", "30"), stubWant{w30, "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "40"}, "ls", "-C"), stubWant{c40, "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "30"}, "ls", "-x"), stubWant{x30, "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "30"}, "ls"), stubWant{one, "", 0, -1}},
		{mk(80, false, map[string]any{"COLUMNS": "0"}, "ls", "-C"), stubWant{row("  "), "", 0, -1}},
		// the number in base 0, after blanks and a +
		{pipe("ls", "-C", "-w", "0x28"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "050"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", strings.Repeat("0", 80)+"50"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", " 40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "+40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "08"), stubWant{"", "ls: invalid line width: ‘08’\n", 2, -1}},
		{pipe("ls", "-C", "-w", "40k"), stubWant{"", "ls: invalid line width: ‘40k’\n", 2, -1}},
		{pipe("ls", "-w", "x"), stubWant{"", "ls: invalid line width: ‘x’\n", 2, -1}},
		{pipe("ls", "-w", "-1"), stubWant{"", "ls: invalid line width: ‘-1’\n", 2, -1}},
		{pipe("ls", "-T", "x"), stubWant{"", "ls: invalid tab size: ‘x’\n", 2, -1}},
		{pipe("ls", "-w"), stubWant{"", "ls: option requires an argument -- 'w'\n" + hint, 2, -1}},
		{pipe("ls", "-Y"), stubWant{"", "ls: invalid option -- 'Y'\n" + hint, 2, -1}},
		{pipe("ls", "--nope"), stubWant{"", "ls: unrecognized option '--nope'\n" + hint, 2, -1}},
		{pipe("ls", "--width"), stubWant{"", "ls: option '--width' requires an argument\n" + hint, 2, -1}},
		{pipe("ls", "--all=x"), stubWant{"", "ls: option '--all' doesn't allow an argument\n" + hint, 2, -1}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, argvLabel(c.c), got[i], c.want)
	}
}

// TestLsBusyBox: BusyBox's ls (recorded from 1.37) lays -C and -x out in
// columns two blanks wider than the longest name, as many as the width holds,
// with no blanks after a line's last name. The width is -w's (a decimal number
// up to INT_MAX), else one less than an exported COLUMNS or the terminal on
// stdin (below 2 or from 30000 up: 80); -T takes a value it ignores.
func TestLsBusyBox(t *testing.T) {
	files := map[string]any{}
	names := strings.Fields("alpha beta chi delta epsilon eta gamma iota kappa lambda mu nu omega omicron phi pi psi rho " +
		"sigma tau theta upsilon xi zeta")
	for _, n := range names {
		files["/b/"+n] = ""
	}
	mk := func(terminal bool, columns int, argv ...string) stubCase {
		return stubCase{"argv": argv, "persona": "openwrt", "files": files, "cwd": "/b", "terminal": terminal,
			"columns": columns, "config": map[string]any{"shell.ls_style": "busybox", "shell.not_found_style": "ash"}}
	}
	pipe := func(argv ...string) stubCase { return mk(false, 80, argv...) }
	with := func(c stubCase, key string, value any) stubCase { c[key] = value; return c }
	columns := func(value string, argv ...string) stubCase {
		return with(pipe(argv...), "env", map[string]any{"COLUMNS": value})
	}
	one := strings.Join(names, "\n") + "\n"
	c40 := "alpha    gamma    omega    sigma\nbeta     iota     omicron  tau\nchi      kappa    phi      theta\n" +
		"delta    lambda   pi       upsilon\nepsilon  mu       psi      xi\neta      nu       rho      zeta\n"
	c36 := "alpha    kappa    psi\nbeta     lambda   rho\nchi      mu       sigma\ndelta    nu       tau\n" +
		"epsilon  omega    theta\neta      omicron  upsilon\ngamma    phi      xi\niota     pi       zeta\n"
	c80 := "alpha    delta    gamma    lambda   omega    pi       sigma    upsilon\n" +
		"beta     epsilon  iota     mu       omicron  psi      tau      xi\n" +
		"chi      eta      kappa    nu       phi      rho      theta    zeta\n"
	x40 := "alpha    beta     chi      delta\nepsilon  eta      gamma    iota\nkappa    lambda   mu       nu\n" +
		"omega    omicron  phi      pi\npsi      rho      sigma    tau\ntheta    upsilon  xi       zeta\n"
	x30 := "alpha    beta     chi\ndelta    epsilon  eta\ngamma    iota     kappa\nlambda   mu       nu\n" +
		"omega    omicron  phi\npi       psi      rho\nsigma    tau      theta\nupsilon  xi       zeta\n"
	invalid := func(value string) stubWant { return stubWant{"", "ls: invalid number '" + value + "'\n", 1, -1} }
	ranged := func(value string) stubWant {
		return stubWant{"", "ls: number " + value + " is not in 0..2147483647 range\n", 1, -1}
	}
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		// -w as given, the last of -1, -C and -x (-l before -C gives way to it)
		{pipe("ls", "-C", "-w", "40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "36"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-x", "-w", "40"), stubWant{x40, "", 0, -1}},
		{pipe("ls", "-x", "-w", "30"), stubWant{x30, "", 0, -1}},
		{pipe("ls", "-1C"), stubWant{c80, "", 0, -1}},
		{pipe("ls", "-C1"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-xC", "-w", "40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-Cx", "-w", "40"), stubWant{x40, "", 0, -1}},
		{pipe("ls", "-lC", "-w", "40"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-1x", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{pipe("ls", "-x1", "alpha", "beta"), stubWant{"alpha\nbeta\n", "", 0, -1}},
		{pipe("ls", "-C", "-w", "18", "alpha", "beta", "chi"), stubWant{"alpha  chi\nbeta\n", "", 0, -1}},
		{pipe("ls", "-C", "-w", "0"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-C", "-w", "5"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-T", "4"), stubWant{one, "", 0, -1}},
		{pipe("ls", "-C", "-T", "x", "-w", "40", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{pipe("ls", "-C", "-w", "040"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "00000000000000000040"), stubWant{c40, "", 0, -1}},
		{pipe("ls", "-C", "-w", "2147483647", "alpha", "beta"), stubWant{"alpha  beta\n", "", 0, -1}},
		{pipe("ls", "-w", "x"), invalid("x")},
		{pipe("ls", "-w", "-1"), invalid("-1")},
		{pipe("ls", "-C", "-w", "+40"), invalid("+40")},
		{pipe("ls", "-C", "-w", " 40"), invalid(" 40")},
		{pipe("ls", "-C", "-w", ""), invalid("")},
		{pipe("ls", "-C", "-w", "99999999999"), invalid("99999999999")},
		{pipe("ls", "-C", "-w", "4294967296"), invalid("4294967296")},
		{pipe("ls", "-C", "-w", "2147483648"), ranged("2147483648")},
		{pipe("ls", "-C", "-w", "4294967295"), ranged("4294967295")},
		// no -w: one less than the terminal on stdin (whatever stdout is), else 80
		{mk(true, 36, "ls"), stubWant{c36, "", 0, -1}},
		{mk(true, 37, "ls"), stubWant{c40, "", 0, -1}},
		{mk(true, 0, "ls"), stubWant{c80, "", 0, -1}},
		{mk(true, 1, "ls"), stubWant{c80, "", 0, -1}},
		{mk(false, 36, "ls", "-C"), stubWant{c36, "", 0, -1}},
		{with(mk(false, 36, "ls", "-C"), "stdin", ""), stubWant{c80, "", 0, -1}},
		// ... or than an exported COLUMNS, as atoi reads it
		{columns("36", "ls", "-C"), stubWant{c36, "", 0, -1}},
		{columns("37", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns(" 37", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns("37x", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns("+37", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns("4294967333", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns("8589934629", "ls", "-C"), stubWant{c40, "", 0, -1}},
		{columns("9223372036854775844", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("99999999999999999999999", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("x", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("-5", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("1", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("30000", "ls", "-C"), stubWant{c80, "", 0, -1}},
		{columns("2", "ls", "-C"), stubWant{one, "", 0, -1}},
		{columns("37", "ls", "-C", "-w", "80"), stubWant{c80, "", 0, -1}},
		{with(mk(true, 36, "ls"), "env", map[string]any{"COLUMNS": "37"}), stubWant{c40, "", 0, -1}},
		{with(mk(true, 36, "ls"), "shellvars", map[string]any{"COLUMNS": "37"}), stubWant{c36, "", 0, -1}},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		checkStub(t, argvLabel(c.c), got[i], c.want)
	}
}

// TestLsColumnsBounded: the column layout of a large folder at the widths an
// attacker's terminal can claim takes a bounded share of the reactor.
func TestLsColumnsBounded(t *testing.T) {
	// 20000 names, and the same with one as long as a file system allows or of 30000 (Cowrie's tree takes
	// any): every column count that the long name alone pushes past the line is a count to pass over
	folders := map[string]map[string]any{}
	for dir, long := range map[string]int{"/d": 0, "/x": 255, "/y": 30000} {
		files := map[string]any{}
		for i := 0; i < 20000; i++ {
			files[fmt.Sprintf("%s/%05d", dir, i)] = ""
		}
		if long > 0 {
			files[dir+"/"+strings.Repeat("z", long)] = ""
		}
		folders[dir] = files
	}
	var cases []stubCase
	for _, w := range []int{80, 3000, 30000, 65535, 1 << 30} {
		for _, dir := range []string{"/d", "/x", "/y"} {
			for _, flag := range []string{"-C", "-x"} {
				cases = append(cases, stubCase{"argv": []string{"ls", flag, dir}, "persona": "debian-13",
					"files": folders[dir], "cwd": "/", "terminal": true, "columns": w})
			}
		}
	}
	got := runCowrieStub(t, cases)
	for i, c := range cases {
		label := fmt.Sprintf("%s at %d columns", argvLabel(c), c["columns"])
		if got[i].CPU > 0.6 || !got[i].Exited || got[i].code() != 0 {
			t.Errorf("%s: %.3f s of CPU, exited %v, code %d", label, got[i].CPU, got[i].Exited, got[i].code())
		}
		t.Logf("%s: %.3f s CPU, %d bytes out", label, got[i].CPU, len(got[i].Stdout))
	}
}

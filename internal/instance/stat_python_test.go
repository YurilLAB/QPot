package instance

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// The output these tests compare with was recorded from GNU coreutils 9.7,
// gzip 1.13 and BusyBox 1.37 (Debian 13) in the C.UTF-8 locale and UTC, on
// files made as the cases make them; the older stat's formats are those of
// coreutils 8.22's and 8.32's stat.c.

// statFiles is the folder the recordings were made in, as the persona's tree
// has it: t.txt (0640, written 2026-07-22 02:21:05), a link to it, a
// dangling link, an empty file, a folder; the gzip files are gzip 1.13's.
func statFiles() map[string]any {
	gz := func(b64 string) map[string]any { return map[string]any{"b64": b64, "mtime": 1784686865} }
	pgz, _ := base64.StdEncoding.DecodeString(gzP)
	named, _ := base64.StdEncoding.DecodeString(gzNamed)
	return map[string]any{
		"/srv/t.txt":       map[string]any{"text": "hello\n", "mode": 0o640, "mtime": 1784686865},
		"/srv/l":           map[string]any{"link": "t.txt", "mtime": 1784732523},
		"/srv/dead":        map[string]any{"link": "nowhere", "mtime": 1784732523},
		"/srv/empty":       map[string]any{"text": "", "mtime": 1784732523},
		"/srv/d":           map[string]any{"dir": true, "mtime": 1784732523},
		"/srv/p.gz":        gz(gzP),
		"/srv/named.gz":    gz(gzNamed),
		"/srv/nameless.gz": gz(gzNameless),
		"/srv/multi.gz":    gz(base64.StdEncoding.EncodeToString(append(append([]byte{}, pgz...), named...))),
		"/srv/short.gz":    gz(base64.StdEncoding.EncodeToString(pgz[:10])),
		"/proc/mounts":     "/dev/sda1 / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n",
	}
}

// gzip 1.13's files: p.gz (`gzip -9 -k p`, 500 lines "line"), named.gz (`gzip -k n` of "abc\n",
// renamed), nameless.gz (`printf xyz | gzip -n`)
const (
	gzP        = "H4sICBEpYGoCA3AAy8nMS+XKGSVGiVFilBglRolRYpQYJYYSAQCL5J6exAkAAA=="
	gzNamed    = "H4sICGvbYGoAA24AS0xK5gIAToGIRwQAAAA="
	gzNameless = "H4sIAAAAAAAAA6uorAIAZ7qO6wMAAAA="
)

func statCase(persona string, argv ...string) stubCase {
	return stubCase{"argv": argv, "persona": persona, "cwd": "/srv", "files": statFiles(), "terminal": true,
		"installed": 1767225600}
}

// statVaries are the parts of stat's output that are the machine's own (the
// device, the inode, the times): the tests compare the rest.
var (
	statDevice = regexp.MustCompile(`Device: [0-9a-f]+h/[0-9]+d\t|Device: [0-9]+,[0-9]+\t`)
	statInode  = regexp.MustCompile(`Inode: [0-9]+ +Links`)
	statTime   = regexp.MustCompile(`[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9} [+-][0-9]{4}`)
)

func statNormal(s string) string {
	s = statDevice.ReplaceAllString(s, "Device: D\t")
	s = statInode.ReplaceAllString(s, "Inode: I Links")
	return statTime.ReplaceAllString(s, "T")
}

// TestStatLikeCoreutils: stat's default output, -t, -c and --printf, its
// errors, as coreutils 9.7 gave them; the values agree with the tree.
func TestStatLikeCoreutils(t *testing.T) {
	block := func(name, size, blocks, kind, links, access string) string {
		return "  File: " + name + "\n  Size: " + size + "\tBlocks: " + blocks + " IO Block: 4096   " + kind + "\n" +
			"Device: D\tInode: I Links: " + links + "\nAccess: " + access +
			"  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: T\nModify: T\nChange: T\n Birth: T\n"
	}
	tTxt := block("t.txt", "6         ", "8         ", "regular file", "1", "(0640/-rw-r-----)")
	dir := block("d", "4096      ", "8         ", "directory", "2", "(0755/drwxr-xr-x)")
	try := "Try 'stat --help' for more information.\n"
	d13 := func(argv ...string) stubCase { return statCase("debian-13", argv...) }
	cases := []struct {
		c      stubCase
		want   stubWant
		normal bool
	}{
		{d13("stat", "t.txt"), stubWant{tTxt, "", 0, 0}, true},
		{d13("stat", "d"), stubWant{dir, "", 0, 0}, true},
		{d13("stat", "l"), stubWant{block("l -> t.txt", "5         ", "0         ", "symbolic link", "1",
			"(0777/lrwxrwxrwx)"), "", 0, 0}, true},
		{d13("stat", "-L", "l"), stubWant{strings.Replace(tTxt, "File: t.txt", "File: l", 1), "", 0, 0}, true},
		{d13("stat", "dead"), stubWant{block("dead -> nowhere", "7         ", "0         ", "symbolic link", "1",
			"(0777/lrwxrwxrwx)"), "", 0, 0}, true},
		{d13("stat", "-L", "dead"), stubWant{"", "stat: cannot statx 'dead': No such file or directory\n", 1, 0}, false},
		{d13("stat", "nope"), stubWant{"", "stat: cannot statx 'nope': No such file or directory\n", 1, 0}, false},
		{d13("stat", "t.txt", "nope", "d"), stubWant{tTxt + dir, "stat: cannot statx 'nope': No such file or directory\n", 1, 0}, true},
		{d13("stat", "empty"), stubWant{block("empty", "0         ", "0         ", "regular empty file", "1",
			"(0644/-rw-r--r--)"), "", 0, 0}, true},
		{d13("stat", "-c", "%a %A %b %B %f %F %g %G %h %n %N %o %s %t %T %u %U %m", "t.txt"),
			stubWant{"640 -rw-r----- 8 512 81a0 regular file 0 root 1 t.txt 't.txt' 4096 6 0 0 0 root /\n", "", 0, 0}, false},
		{d13("stat", "-c", "%n %N %F %s", "l"), stubWant{"l 'l' -> 't.txt' symbolic link 5\n", "", 0, 0}, false},
		{d13("stat", "-L", "-c", "%n %N %F %s", "l"), stubWant{"l 'l' regular file 6\n", "", 0, 0}, false},
		{d13("stat", "--format=%s:%n", "t.txt", "d"), stubWant{"6:t.txt\n4096:d\n", "", 0, 0}, false},
		{d13("stat", "-c", "%q|%%|%", "t.txt"), stubWant{"?|%|%\n", "", 0, 0}, false},
		{d13("stat", "-c"), stubWant{"", "stat: option requires an argument -- 'c'\n" + try, 1, 0}, false},
		{d13("stat"), stubWant{"", "stat: missing operand\n" + try, 1, 0}, false},
		{d13("stat", "-Z", "t.txt"), stubWant{"", "stat: invalid option -- 'Z'\n" + try, 1, 0}, false},
		{d13("stat", `--printf=%s\n%n`, "t.txt"), stubWant{"6\nt.txt", "", 0, 0}, false},
		// t.txt is older than the persona's installation here: its mtime is kept to the second
		{statCaseInstalled("debian-13", 1790000000, "stat", "-c", "%10s|%-6n|%05a|%.3Y|%Y", "t.txt"),
			stubWant{"         6|t.txt |00640|1784686865.000|1784686865\n", "", 0, 0}, false},
		{d13("stat", "-c", "%Hd,%Ld %D %d", "/"), stubWant{"8,1 801 2049\n", "", 0, 0}, false},
		// / has its block (the tree's has no size) and a link for each of its 5 folders
		{d13("stat", "-c", "%s %h %i", "/"), stubWant{"4096 7 2\n", "", 0, 0}, false},
		// the older releases (their stat.c)
		{statCase("ubuntu-22.04", "stat", "nope"), stubWant{"", "stat: cannot statx 'nope': No such file or directory\n", 1, 0}, false},
		{statCase("centos-7", "stat", "nope"), stubWant{"", "stat: cannot stat \u2018nope\u2019: No such file or directory\n", 1, 0}, false},
	}
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		if c.normal {
			got[i].Stdout = statNormal(got[i].Stdout)
		}
		checkStub(t, c.c["persona"].(string)+": "+argvLabel(c.c), got[i], c.want)
	}
	// 8.x prints the device in hex and decimal, 8.22 has no birth time
	old := runCowrieStub(t, []stubCase{statCase("ubuntu-22.04", "stat", "t.txt"), statCase("centos-7", "stat", "t.txt"),
		statCase("debian-13", "stat", "-t", "t.txt")})
	if !strings.Contains(old[0].Stdout, "\nDevice: 801h/2049d\tInode: ") || !strings.Contains(old[0].Stdout, " Birth: 20") {
		t.Errorf("coreutils 8.32: %q", old[0].Stdout)
	}
	if !strings.Contains(old[1].Stdout, "\nDevice: 801h/2049d\tInode: ") || !strings.HasSuffix(old[1].Stdout, " Birth: -\n") ||
		!strings.HasPrefix(old[1].Stdout, "  File: \u2018t.txt\u2019\n") {
		t.Errorf("coreutils 8.22: %q", old[1].Stdout)
	}
	terse := strings.Fields(old[2].Stdout)
	if len(terse) != 16 || strings.Join(terse[:6], " ") != "t.txt 6 8 81a0 0 0" || terse[6] != "801" ||
		strings.Join(terse[8:11], " ") != "1 0 0" || terse[12] != "1784686865" || terse[15] != "4096" {
		t.Errorf("stat -t: %q", old[2].Stdout)
	}
}

func statCaseInstalled(persona string, installed int64, argv ...string) stubCase {
	c := statCase(persona, argv...)
	c["installed"] = installed
	return c
}

// TestStatBusyBox: BusyBox's stat (1.37) where the persona's stat is a link
// to BusyBox: no birth line, the device in hex and decimal, a link quoted.
func TestStatBusyBox(t *testing.T) {
	bb := func(argv ...string) stubCase {
		c := statCase("openwrt", argv...)
		files := c["files"].(map[string]any)
		files["/bin/busybox"] = map[string]any{"text": "", "mode": 0o755}
		files["/bin/stat"] = map[string]any{"link": "busybox"}
		c["command"] = "/bin/stat"
		c["config"] = map[string]any{"shell.not_found_style": "ash"}
		return c
	}
	got := runCowrieStub(t, []stubCase{bb("stat", "t.txt"), bb("stat", "l"), bb("stat", "nope"),
		bb("stat", "-c", "%a %A %b %B %f %F %g %G %h %n %N %o %s %t %T %u %U", "t.txt"), bb("stat", "-t", "t.txt")})
	want := "  File: t.txt\n  Size: 6         \tBlocks: 8          IO Block: 4096   regular file\nDevice: D\tInode: I Links: 1\n" +
		"Access: (0640/-rw-r-----)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: T\nModify: T\nChange: T\n"
	if s := statNormal(got[0].Stdout); s != want {
		t.Errorf("busybox stat:\n%q\nwant\n%q", s, want)
	}
	if !strings.HasPrefix(got[1].Stdout, "  File: 'l' -> 't.txt'\n") {
		t.Errorf("busybox stat of a link: %q", got[1].Stdout)
	}
	if got[2].Stderr != "stat: can't stat 'nope': No such file or directory\n" || got[2].code() != 1 {
		t.Errorf("busybox stat nope: %d %q", got[2].code(), got[2].Stderr)
	}
	if got[3].Stdout != "640 -rw-r----- 8 512 81a0 regular file 0 root 1 t.txt t.txt 4096 6 0 0 0 root\n" {
		t.Errorf("busybox stat -c: %q", got[3].Stdout)
	}
	if f := strings.Fields(got[4].Stdout); len(f) != 15 || strings.Join(f[:6], " ") != "t.txt 6 8 81a0 0 0" {
		t.Errorf("busybox stat -t: %q", got[4].Stdout)
	}
}

// TestGzipListLikeGzip: gzip -l, -lv, -t of gzip 1.13 on the very files it
// listed.
func TestGzipListLikeGzip(t *testing.T) {
	head := "         compressed        uncompressed  ratio uncompressed_name\n"
	vhead := "method  crc     date  time           compressed        uncompressed  ratio uncompressed_name\n"
	d13 := func(argv ...string) stubCase { return statCase("debian-13", argv...) }
	cases := []struct {
		c    stubCase
		want stubWant
	}{
		{d13("gzip", "-l", "p.gz"), stubWant{head + "                 46                2500  99.0% p\n", "", 0, 0}},
		{d13("gzip", "-l", "named.gz"), stubWant{head + "                 26                   4 -50.0% named\n", "", 0, 0}},
		{d13("gzip", "-l", "nameless.gz"), stubWant{head + "                 23                   3 -66.7% nameless\n", "", 0, 0}},
		{d13("gzip", "-lv", "p.gz", "named.gz"), stubWant{vhead +
			"defla 9e9ee48b Jul 22 02:21                  46                2500  99.0% p\n" +
			"defla 4788814e Jul 22 15:02                  26                   4 -50.0% named\n" +
			"                                             72                2504  97.9% (totals)\n", "", 0, 0}},
		{d13("gzip", "-l", "t.txt"), stubWant{"", "\ngzip: t.txt: not in gzip format\n", 1, 0}},
		{d13("gzip", "-l", "nope.gz"), stubWant{"", "gzip: nope.gz: No such file or directory\n", 1, 0}},
		{d13("gzip", "-l", "empty"), stubWant{"", "\ngzip: empty: unexpected end of file\n", 1, 0}},
		{d13("gzip", "-l", "short.gz"), stubWant{"", "\ngzip: short.gz: unexpected end of file\n", 1, 0}},
		{d13("gzip", "-l", "p.gz", "nope.gz", "named.gz"), stubWant{head + "                 46                2500  99.0% p\n" +
			"                 26                   4 -50.0% named\n                 72                2504  97.9% (totals)\n",
			"gzip: nope.gz: No such file or directory\n", 1, 0}},
		{d13("gzip", "-t", "p.gz"), stubWant{"", "", 0, 0}},
		{d13("gzip", "-t", "t.txt"), stubWant{"", "\ngzip: t.txt: not in gzip format\n", 1, 0}},
		{d13("gzip", "-t", "short.gz"), stubWant{"", "\ngzip: short.gz: unexpected end of file\n", 1, 0}},
		{d13("gzip", "-tv", "p.gz"), stubWant{"", "p.gz:\t OK\n", 0, 0}},
		{d13("gzip", "-lq", "p.gz"), stubWant{"                 46                2500  99.0% p\n", "", 0, 0}},
		{d13("gzip", "-lN", "named.gz"), stubWant{head + "                 26                   4 -50.0% n\n", "", 0, 0}},
		{d13("gzip", "--list", "p.gz"), stubWant{head + "                 46                2500  99.0% p\n", "", 0, 0}},
		{d13("gzip", "--version"), stubWant{"gzip 1.13\nCopyright (C) 2023 Free Software Foundation, Inc.\n" +
			"Copyright (C) 1993 Jean-loup Gailly.\nThis is free software.  You may redistribute copies of it under the terms of\n" +
			"the GNU General Public License <https://www.gnu.org/licenses/gpl.html>.\n" +
			"There is NO WARRANTY, to the extent permitted by law.\n\nWritten by Jean-loup Gailly.\n", "", 0, 0}},
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

// TestStatVersion: stat --version as the persona's coreutils prints it
// (Debian 13's recorded, with the packager line the persona engine gives
// Debian 13; CentOS 7's 8.22 from its year and the http link of the time).
func TestStatVersion(t *testing.T) {
	d13 := statCase("debian-13", "stat", "--version", "nope")
	d13["config"] = map[string]any{"shell.text_style": "gnu", "shell.text_version": "9.7", "shell.text_year": "2025",
		"shell.text_packager": "Debian (9.7-3)"}
	// the persona engine's release wins over the os-release table (none here: 8.32 by default)
	engine := statCase("none", "stat", "--version")
	engine["config"] = map[string]any{"shell.text_style": "gnu", "shell.text_version": "9.4", "shell.text_year": "2023"}
	got := runCowrieStub(t, []stubCase{d13, statCase("centos-7", "stat", "--version"), engine})
	want := "stat (GNU coreutils) 9.7\nPackaged by Debian (9.7-3)\nCopyright (C) 2025 Free Software Foundation, Inc.\n" +
		"License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n" +
		"This is free software: you are free to change and redistribute it.\n" +
		"There is NO WARRANTY, to the extent permitted by law.\n\nWritten by Michael Meskes.\n"
	checkStub(t, "debian-13: stat --version nope", got[0], stubWant{want, "", 0, 0})
	old := strings.Replace(strings.Replace(strings.Replace(want, "9.7\nPackaged by Debian (9.7-3)", "8.22", 1), "2025", "2013", 1),
		"https://", "http://", 1)
	checkStub(t, "centos-7: stat --version", got[1], stubWant{old, "", 0, 0})
	checkStub(t, "engine 9.4: stat --version", got[2], stubWant{strings.Replace(strings.Replace(want,
		"9.7\nPackaged by Debian (9.7-3)", "9.4", 1), "2025", "2023", 1), "", 0, 0})
}

// gzCase is a gzip case with what its files must be afterwards: the
// contents and, where given, the time and mode of each path, and the paths
// that must be gone.
type gzCase struct {
	c     stubCase
	want  stubWant
	files map[string]string
	mtime map[string]float64
	mode  map[string]int
	owner map[string]int
	gone  []string
}

// gzEdgeFiles are the files of the cases on top of statFiles: empty and
// one-byte ones, a folder with a .gz name, members under other suffixes.
func gzEdgeFiles(c stubCase) stubCase {
	files := c["files"].(map[string]any)
	files["/srv/one"] = "x"
	files["/srv/e.gz"] = ""
	files["/srv/dd.gz"] = map[string]any{"dir": true}
	for _, name := range []string{"q.Z", "r-z", "s.tgz", "k.gz", "e.tgz", "F.GZ", "g.z"} {
		files["/srv/"+name] = map[string]any{"b64": gzNameless, "mtime": 1784686865}
	}
	return c
}

func checkGzipCases(t *testing.T, cases []gzCase) {
	t.Helper()
	var all []stubCase
	for _, c := range cases {
		all = append(all, c.c)
	}
	got := runCowrieStub(t, all)
	for i, c := range cases {
		label := argvLabel(c.c)
		checkStub(t, label, got[i], c.want)
		for path, text := range c.files {
			f, ok := got[i].Files[path]
			data, _ := base64.StdEncoding.DecodeString(f.B64)
			if !ok || string(data) != text {
				t.Errorf("%s: %s is %q (there: %v), want %q", label, path, data, ok, text)
			}
		}
		for path, when := range c.mtime {
			if f := got[i].Files[path]; f.Mtime != when {
				t.Errorf("%s: %s has the time %v, want %v", label, path, f.Mtime, when)
			}
		}
		for path, mode := range c.mode {
			if f := got[i].Files[path]; f.Mode != mode {
				t.Errorf("%s: %s has the mode %o, want %o", label, path, f.Mode, mode)
			}
		}
		for path, uid := range c.owner {
			if f := got[i].Files[path]; f.UID != uid {
				t.Errorf("%s: %s is uid %d's, want %d's", label, path, f.UID, uid)
			}
		}
		for _, path := range c.gone {
			if _, ok := got[i].Files[path]; ok {
				t.Errorf("%s: %s is still there", label, path)
			}
		}
	}
}

// TestGzipEdgesLikeGzip: gzip 1.13 on input too short for its magic, on
// folders (a warning, status 2, which an error outranks), on names that are
// not there (decompressing, it looks for name.gz, .z, -z and .Z and names
// name.gz when none is), and on a .gz to compress (left alone with status 0,
// compressed with -c or -f).
func TestGzipEdgesLikeGzip(t *testing.T) {
	d13 := func(argv ...string) stubCase { return gzEdgeFiles(statCase("debian-13", argv...)) }
	eof := func(name string) string { return "\ngzip: " + name + ": unexpected end of file\n" }
	folder := func(name string) string { return "gzip: " + name + " is a directory -- ignored\n" }
	missing := func(name string) string { return "gzip: " + name + ": No such file or directory\n" }
	cases := []gzCase{
		{c: d13("zcat", "empty"), want: stubWant{"", eof("empty"), 1, 0}},
		{c: d13("zcat", "one"), want: stubWant{"", eof("one"), 1, 0}},
		{c: d13("gzip", "-t", "empty"), want: stubWant{"", eof("empty"), 1, 0}},
		{c: d13("gzip", "-dc", "empty"), want: stubWant{"", eof("empty"), 1, 0}},
		{c: d13("gunzip", "e.gz"), want: stubWant{"", eof("e.gz"), 1, 0}},
		{c: d13("zcat", "d"), want: stubWant{"", folder("d"), 2, 0}},
		{c: d13("gzip", "-t", "d"), want: stubWant{"", folder("d"), 2, 0}},
		{c: d13("gzip", "d"), want: stubWant{"", folder("d"), 2, 0}},
		{c: d13("gzip", "-c", "d"), want: stubWant{"", folder("d"), 2, 0}},
		{c: d13("gzip", "-l", "d"), want: stubWant{"", folder("d"), 2, 0}},
		{c: d13("gunzip", "dd.gz"), want: stubWant{"", folder("dd.gz"), 2, 0}},
		{c: d13("gzip", "nope", "d"), want: stubWant{"", missing("nope") + folder("d"), 1, 0}},
		{c: d13("gzip", "d", "nope"), want: stubWant{"", folder("d") + missing("nope"), 1, 0}},
		{c: d13("gzip", "-t", "d", "empty"), want: stubWant{"", folder("d") + eof("empty"), 1, 0}},
		{c: d13("zcat", "d", "nope"), want: stubWant{"", folder("d") + missing("nope.gz"), 1, 0}},
		{c: d13("zcat", "nope"), want: stubWant{"", missing("nope.gz"), 1, 0}},
		{c: d13("zcat", "nope.z"), want: stubWant{"", missing("nope.z"), 1, 0}},
		{c: d13("zcat", "NOPE.GZ"), want: stubWant{"", missing("NOPE.GZ"), 1, 0}},
		{c: d13("zcat", "nope.tgz"), want: stubWant{"", missing("nope.tgz"), 1, 0}},
		{c: d13("gzip", "-t", "nope"), want: stubWant{"", missing("nope.gz"), 1, 0}},
		{c: d13("gzip", "-l", "nope"), want: stubWant{"", missing("nope.gz"), 1, 0}},
		{c: d13("gzip", "-d", "nope"), want: stubWant{"", missing("nope.gz"), 1, 0}},
		{c: d13("gzip", "nope"), want: stubWant{"", missing("nope"), 1, 0}},
		{c: d13("zcat", "q"), want: stubWant{"xyz", "", 0, 0}},
		{c: d13("zcat", "r"), want: stubWant{"xyz", "", 0, 0}},
		{c: d13("zcat", "s"), want: stubWant{"", missing("s.gz"), 1, 0}},
		{c: d13("gzip", "-t", "p"), want: stubWant{"", "", 0, 0}},
		{c: d13("gunzip", "k"), want: stubWant{"", "", 0, 0}, files: map[string]string{"/srv/k": "xyz"},
			mtime: map[string]float64{"/srv/k": 1784686865}, gone: []string{"/srv/k.gz"}},
		{c: d13("gzip", "p.gz"), want: stubWant{"", "gzip: p.gz already has .gz suffix -- unchanged\n", 0, 0},
			gone: []string{"/srv/p.gz.gz"}},
		{c: d13("gzip", "-k", "-f", "p.gz"), want: stubWant{"", "", 0, 0}, mtime: map[string]float64{"/srv/p.gz.gz": 1784686865}},
		// gzip keeps the owner and mode of the file (copy_stat)
		{c: owned(d13("gzip", "v.txt")), want: stubWant{"", "", 0, 0}, owner: map[string]int{"/srv/v.txt.gz": 1000},
			mode: map[string]int{"/srv/v.txt.gz": 0o100600}},
		{c: stdin(d13("gzip")), want: stubWant{"", "gzip: compressed data not written to a terminal. " +
			"Use -f to force compression.\nFor help, type: gzip -h\n", 1, 0}},
	}
	checkGzipCases(t, cases)
	// -c compresses a .gz too, to the terminal (gzip refuses that only for stdin)
	got := runCowrieStub(t, []stubCase{d13("gzip", "-c", "p.gz")})
	if got[0].code() != 0 || got[0].Stderr != "" || !strings.HasPrefix(got[0].Stdout, "\x1f") {
		t.Errorf("gzip -c p.gz: code %d err %q out %.12q", got[0].code(), got[0].Stderr, got[0].Stdout)
	}
}

// TestGzipBusyBox: BusyBox's gzip, gunzip and zcat (recorded from 1.37):
// each names itself in its errors ("gunzip: invalid magic"); gunzip knows .gz
// and .tgz only, as written, and opens the new file before it reads the old;
// gzip compresses a .gz again, writes to a terminal, keeps neither the name
// nor the time in the header and makes the file now, as the user; a folder
// reads as nothing; zcat cannot read the magic of a shorter file.
func TestGzipBusyBox(t *testing.T) {
	bb := func(name string, argv ...string) stubCase {
		c := gzEdgeFiles(statCase("openwrt", argv...))
		files := c["files"].(map[string]any)
		files["/bin/busybox"] = map[string]any{"text": "", "mode": 0o755}
		files["/bin/"+name] = map[string]any{"link": "busybox"}
		files["/srv/u.gz"] = "hello\n"
		c["command"] = "/bin/" + name
		c["config"] = map[string]any{"shell.not_found_style": "ash"}
		return c
	}
	with := func(c stubCase, path string, spec any) stubCase {
		c["files"].(map[string]any)[path] = spec
		return c
	}
	hello := string([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xe7, 2, 0, 0x20, 0x30, 0x3a, 0x36, 6, 0, 0, 0})
	nothing := string([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	cases := []gzCase{
		{c: bb("gzip", "gzip", "-t", "t.txt"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("gzip", "gzip", "-t", "u.gz"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("gzip", "gzip", "-t", "p.gz"), want: stubWant{"", "", 0, 0}},
		{c: bb("gzip", "gzip", "-d", "u.gz"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "u.gz"), want: stubWant{"", "gunzip: invalid magic\n", 1, 0}},
		{c: bb("gzip", "gzip", "-d", "t.txt"), want: stubWant{"", "gzip: t.txt: unknown suffix - ignored\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "t.txt"), want: stubWant{"", "gunzip: t.txt: unknown suffix - ignored\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "F.GZ"), want: stubWant{"", "gunzip: F.GZ: unknown suffix - ignored\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "g.z"), want: stubWant{"", "gunzip: g.z: unknown suffix - ignored\n", 1, 0}},
		{c: bb("gzip", "gzip", "-d", "nope"), want: stubWant{"", "gzip: nope: No such file or directory\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "nope.gz"), want: stubWant{"", "gunzip: nope.gz: No such file or directory\n", 1, 0}},
		{c: bb("gunzip", "gunzip", "k"), want: stubWant{"", "gunzip: k: No such file or directory\n", 1, 0}},
		{c: bb("gzip", "gzip", "nope"), want: stubWant{"", "gzip: nope: No such file or directory\n", 1, 0}},
		{c: with(bb("gunzip", "gunzip", "nameless.gz"), "/srv/nameless", "x\n"),
			want: stubWant{"", "gunzip: can't open 'nameless': File exists\n", 1, 0}, files: map[string]string{"/srv/nameless": "x\n"}},
		{c: with(bb("gunzip", "gunzip", "-f", "nameless.gz"), "/srv/nameless", "x\n"), want: stubWant{"", "", 0, 0},
			files: map[string]string{"/srv/nameless": "xyz"}, mtime: map[string]float64{"/srv/nameless": 0},
			gone: []string{"/srv/nameless.gz"}},
		{c: bb("gunzip", "gunzip", "named.gz"), want: stubWant{"", "", 0, 0}, files: map[string]string{"/srv/named": "abc\n"},
			mtime: map[string]float64{"/srv/named": 1784732523}},
		{c: bb("gunzip", "gunzip", "e.tgz"), want: stubWant{"", "", 0, 0}, files: map[string]string{"/srv/e.tar": "xyz"},
			gone: []string{"/srv/e.tgz"}},
		{c: bb("gzip", "gzip", "p.gz"), want: stubWant{"", "", 0, 0}, gone: []string{"/srv/p.gz"},
			mtime: map[string]float64{"/srv/p.gz.gz": 0}},
		{c: with(bb("gzip", "gzip", "t.txt"), "/srv/t.txt.gz", "y\n"),
			want: stubWant{"", "gzip: can't open 't.txt.gz': File exists\n", 1, 0}, files: map[string]string{"/srv/t.txt.gz": "y\n"}},
		{c: with(bb("gzip", "gzip", "-f", "t.txt"), "/srv/t.txt.gz", "y\n"), want: stubWant{"", "", 0, 0},
			files: map[string]string{"/srv/t.txt.gz": hello}},
		{c: bb("gzip", "gzip", "t.txt"), want: stubWant{"", "", 0, 0}, files: map[string]string{"/srv/t.txt.gz": hello},
			mtime: map[string]float64{"/srv/t.txt.gz": 0}, mode: map[string]int{"/srv/t.txt.gz": 0o100640},
			gone: []string{"/srv/t.txt"}},
		{c: bb("gzip", "gzip", "d"), want: stubWant{"", "gzip: can't remove file 'd': Is a directory\n", 1, 0},
			files: map[string]string{"/srv/d.gz": nothing}, mode: map[string]int{"/srv/d.gz": 0o100755}},
		{c: bb("gzip", "gzip", "nope", "d"), want: stubWant{"", "gzip: nope: No such file or directory\n" +
			"gzip: can't remove file 'd': Is a directory\n", 1, 0}},
		{c: bb("gzip", "gzip", "d", "t.txt"), want: stubWant{"", "gzip: can't remove file 'd': Is a directory\n", 1, 0},
			files: map[string]string{"/srv/t.txt": "hello\n"}, gone: []string{"/srv/t.txt.gz"}},
		{c: bb("gunzip", "gunzip", "dd.gz"), want: stubWant{"", "gunzip: invalid magic\n", 1, 0}, gone: []string{"/srv/dd"}},
		{c: bb("gzip", "gzip", "-t", "d"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("gzip", "gzip", "-dc", "empty"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("gzip", "gzip", "-dc", "d"), want: stubWant{"", "gzip: invalid magic\n", 1, 0}},
		{c: bb("zcat", "zcat", "empty"), want: stubWant{"", "zcat: short read\n", 1, 0}},
		{c: bb("zcat", "zcat", "one"), want: stubWant{"", "zcat: short read\n", 1, 0}},
		{c: bb("zcat", "zcat", "d"), want: stubWant{"", "zcat: short read\n", 1, 0}},
		{c: bb("zcat", "zcat", "t.txt"), want: stubWant{"", "zcat: invalid magic\n", 1, 0}},
		{c: bb("zcat", "zcat", "k"), want: stubWant{"", "zcat: k: No such file or directory\n", 1, 0}},
		// the new file is the user's, with the mode of the old one
		{c: owned(bb("gzip", "gzip", "v.txt")), want: stubWant{"", "", 0, 0}, owner: map[string]int{"/srv/v.txt.gz": 0},
			mode: map[string]int{"/srv/v.txt.gz": 0o100600}},
	}
	checkGzipCases(t, cases)
	// to the terminal, without a complaint: a file's and stdin
	got := runCowrieStub(t, []stubCase{bb("gzip", "gzip", "-c", "t.txt"), stdin(bb("gzip", "gzip"))})
	for i, label := range []string{"busybox gzip -c t.txt", "busybox gzip < t.txt"} {
		if got[i].code() != 0 || got[i].Stderr != "" || !strings.HasPrefix(got[i].Stdout, "\x1f") {
			t.Errorf("%s: code %d err %q out %.12q", label, got[i].code(), got[i].Stderr, got[i].Stdout)
		}
	}
}

// owned gives the case /srv/v.txt, uid 1000's and mode 0600.
func owned(c stubCase) stubCase {
	c["files"].(map[string]any)["/srv/v.txt"] = map[string]any{"text": "hello\n", "mode": 0o600, "uid": 1000, "gid": 1001}
	return c
}

// stdin gives the case "hello\n" on stdin.
func stdin(c stubCase) stubCase {
	c["stdin"] = "hello\n"
	return c
}

// TestStatGzipBounded: stat and gzip command lines of the attacker's
// making (60000 directives over 4096 operands, a flag run of 60000, huge
// widths, 20000 escapes, 4096 names of a gzip bomb or of a 4 MiB file of
// random bytes) take a bounded share of the reactor and of memory.
func TestStatGzipBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	random := make([]byte, 4<<20)
	for i := range random {
		random[i] = byte(rng.Intn(256))
	}
	var bomb, big bytes.Buffer
	for _, z := range []struct {
		out  *bytes.Buffer
		data []byte
	}{{&bomb, make([]byte, 8<<20)}, {&big, random}} {
		w, _ := gzip.NewWriterLevel(z.out, gzip.BestCompression)
		if _, err := w.Write(z.data); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	b64 := func(b []byte) map[string]any { return map[string]any{"b64": base64.StdEncoding.EncodeToString(b)} }
	files := map[string]any{"/srv/t.txt": "hello\n", "/srv/rand": b64(random), "/srv/bomb.gz": b64(bomb.Bytes()),
		"/srv/big.gz": b64(big.Bytes())}
	times := func(n int, words ...string) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, words...)
		}
		return out
	}
	argvs := [][]string{
		append([]string{"stat", "-c", strings.Repeat("%n%s%A%y", 15000)}, times(4096, "t.txt")...),
		{"stat", "-c", "%" + strings.Repeat("0", 60000) + "d", "t.txt"},
		{"stat", "-c", "%-99999999999s|%.99999999999Y|%099999999999a", "t.txt"},
		{"stat", "--printf", strings.Repeat(`\777\x41\n`, 20000), "t.txt"},
		append([]string{"stat"}, times(4096, "nope")...),
		append([]string{"gzip", "-l"}, times(4096, "big.gz")...),
		append([]string{"gzip", "-t"}, times(4096, "bomb.gz")...),
		append([]string{"gzip", "-cdf"}, times(4096, "bomb.gz")...),
		append([]string{"gzip", "-kfc"}, times(4096, "rand")...),
		append([]string{"gzip", "-lv"}, times(2048, "bomb.gz", "big.gz")...),
	}
	var cases, traced []stubCase
	for _, argv := range argvs {
		c := stubCase{"argv": argv, "persona": "debian-13", "cwd": "/srv", "files": files, "terminal": false}
		cases = append(cases, c)
		m := stubCase{}
		for k, v := range c {
			m[k] = v
		}
		m["memory"] = true
		traced = append(traced, m)
	}
	got := runCowrieStub(t, cases)
	peaks := runCowrieStub(t, traced)
	for i, r := range got {
		label := strings.Join(argvs[i][:2], " ")
		// the largest legitimate job, gzip of one 8 MiB file, takes about 0.3 s itself
		if r.CPU > 0.6 || peaks[i].Peak > 96<<20 || !r.Exited {
			t.Errorf("%s ...: %.3f s of CPU, %d MiB at the peak, exited %v", label, r.CPU, peaks[i].Peak>>20, r.Exited)
		}
		t.Logf("%s ...: %.3f s CPU, %d MiB at the peak, %d bytes out", label, r.CPU, peaks[i].Peak>>20, len(r.Stdout))
	}
}

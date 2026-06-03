package instance

import (
	"strings"
	"testing"
)

// FuzzHoneyfs feeds arbitrary usernames/passwords/hostnames into the honeyfs
// generator and asserts no panic and that no field can inject extra lines into
// /etc/passwd (a username with an embedded newline must not create a second
// account row).
func FuzzHoneyfs(f *testing.F) {
	f.Add("jmartin", "Summer1!", "web01", "seedA")
	f.Add("a\nroot:x:0:0", "p", "h\nx", "")
	f.Add("", "", "", "x")
	f.Add("usuário\x00", "\xff", "h", "\x00\xff")
	f.Fuzz(func(t *testing.T, user, pass, hostname, seed string) {
		tmpl := credentialTemplate{Name: "fuzz", Users: []credUser{{Username: user, Passwords: []string{pass}}}}
		files := generateHoneyfs(tmpl, distroProfiles[0], hostname, seed) // must not panic
		passwd := files["etc/passwd"]
		// Every passwd line must be a well-formed colon record (>=7 fields) or
		// empty — a stray newline in a username would otherwise inject a line.
		for _, line := range strings.Split(passwd, "\n") {
			if line == "" {
				continue
			}
			if strings.Count(line, ":") < 6 {
				t.Errorf("malformed /etc/passwd line (possible injection): %q", line)
			}
		}
		// /proc/cpuinfo must always list exactly two CPUs regardless of seed, so
		// it never contradicts Cowrie's hard-coded nproc=2 (a count mismatch is a
		// tell). Whatever the seed mutates to, the count is invariant.
		if n := strings.Count(files["proc/cpuinfo"], "processor\t:"); n != 2 {
			t.Errorf("/proc/cpuinfo must list exactly 2 processors (matches nproc), got %d", n)
		}
	})
}

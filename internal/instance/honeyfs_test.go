package instance

import (
	"strings"
	"testing"
)

// TestHoneyfsPersonaConsistency verifies that every persona's login accounts
// appear in the generated /etc/passwd — closing the #1 Cowrie tell (logging in
// as a user who is absent from /etc/passwd).
func TestHoneyfsPersonaConsistency(t *testing.T) {
	prof := profileForSeed("seedA")
	for _, tmpl := range credentialTemplates {
		files := generateHoneyfs(tmpl, prof, "host1")
		passwd := files["etc/passwd"]
		if !strings.Contains(passwd, "root:x:0:0:") {
			t.Errorf("persona %q: /etc/passwd missing root", tmpl.Name)
		}
		for _, u := range tmpl.Users {
			// Each login username must appear as a passwd account.
			if !strings.Contains(passwd, "\n"+u.Username+":") && !strings.HasPrefix(passwd, u.Username+":") {
				t.Errorf("persona %q: login user %q absent from /etc/passwd (consistency tell)", tmpl.Name, u.Username)
			}
		}
		// os-release/hostname/issue must be present and non-empty.
		for _, k := range []string{"etc/os-release", "etc/hostname", "etc/issue", "etc/group"} {
			if strings.TrimSpace(files[k]) == "" {
				t.Errorf("persona %q: missing honeyfs file %q", tmpl.Name, k)
			}
		}
	}
}

// TestHoneyfsOsReleaseMatchesDistro checks os-release is consistent with the
// distro profile (so `cat /etc/os-release` agrees with the SSH banner).
func TestHoneyfsOsReleaseMatchesDistro(t *testing.T) {
	for _, p := range distroProfiles {
		osr := osRelease(p, "h")
		if !strings.Contains(osr, "PRETTY_NAME=\""+p.OSPretty+"\"") {
			t.Errorf("os-release PRETTY_NAME mismatch for %q", p.OSPretty)
		}
		low := strings.ToLower(p.OSPretty)
		for _, fam := range []string{"ubuntu", "debian", "centos"} {
			if strings.Contains(low, fam) && !strings.Contains(osr, "ID="+fam) {
				t.Errorf("os-release ID should be %s for %q:\n%s", fam, p.OSPretty, osr)
			}
		}
	}
}

// TestHoneyfsASCII guards that honeyfs files are byte-clean (no control bytes
// beyond newline) so they can't break cowrie's file serving.
func TestHoneyfsASCII(t *testing.T) {
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "host")
	for k, v := range files {
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 && v[i] != '\n' && v[i] != '\t' {
				t.Errorf("honeyfs %q has control byte 0x%x at %d", k, v[i], i)
			}
		}
	}
}

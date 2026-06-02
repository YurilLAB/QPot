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
		// Enriched fields must be internally consistent: a real modern Debian/
		// Ubuntu box carries VERSION_CODENAME and SUPPORT/BUG report URLs, and
		// Ubuntu carries ID_LIKE=debian + a matching UBUNTU_CODENAME. A thin
		// os-release missing these is itself a tell.
		if p.Codename != "" && !strings.Contains(osr, "VERSION_CODENAME="+p.Codename) {
			t.Errorf("os-release missing VERSION_CODENAME=%s for %q", p.Codename, p.OSPretty)
		}
		if p.IDLike != "" && !strings.Contains(osr, "ID_LIKE="+p.IDLike) {
			t.Errorf("os-release missing ID_LIKE=%s for %q", p.IDLike, p.OSPretty)
		}
		if strings.Contains(low, "ubuntu") {
			if !strings.Contains(osr, "ID_LIKE=debian") {
				t.Errorf("Ubuntu os-release must declare ID_LIKE=debian: %q", p.OSPretty)
			}
			if !strings.Contains(osr, "UBUNTU_CODENAME="+p.Codename) {
				t.Errorf("Ubuntu os-release missing UBUNTU_CODENAME=%s", p.Codename)
			}
			if !strings.Contains(osr, "HOME_URL=\"https://www.ubuntu.com/\"") {
				t.Errorf("Ubuntu HOME_URL should be ubuntu.com, not .org: %q", p.OSPretty)
			}
		}
		if !strings.Contains(osr, "BUG_REPORT_URL=") {
			t.Errorf("os-release missing BUG_REPORT_URL for %q", p.OSPretty)
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

// TestHoneyfsMOTDPerDistro guards that the Debian boilerplate motd is only used
// on Debian profiles (it is a tell on Ubuntu/CentOS, which have an empty static
// /etc/motd), and that generateHoneyfs always emits the file so its bind mount
// never resolves to a missing source.
func TestHoneyfsMOTDPerDistro(t *testing.T) {
	for _, p := range distroProfiles {
		m := motd(p)
		isDebian := strings.Contains(strings.ToLower(p.OSPretty), "debian")
		if isDebian && !strings.Contains(m, "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY") {
			t.Errorf("Debian profile %q should have the Debian motd", p.OSPretty)
		}
		if !isDebian && strings.Contains(m, "Debian GNU/Linux") {
			t.Errorf("non-Debian profile %q leaks Debian motd boilerplate", p.OSPretty)
		}
	}
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "h")
	if _, ok := files["etc/motd"]; !ok {
		t.Error("generateHoneyfs must always emit etc/motd (its mount source)")
	}
}

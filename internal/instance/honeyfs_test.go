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
		files := generateHoneyfs(tmpl, prof, "host1", "seedA")
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
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "host", "seed1")
	for k, v := range files {
		for i := 0; i < len(v); i++ {
			if v[i] < 0x20 && v[i] != '\n' && v[i] != '\t' {
				t.Errorf("honeyfs %q has control byte 0x%x at %d", k, v[i], i)
			}
		}
	}
}

// TestHoneyfsEtcHostsConsistent verifies /etc/hosts carries the same per-instance
// hostname as /etc/hostname on the 127.0.1.1 line (Debian/Ubuntu convention), so
// `cat /etc/hosts` agrees with `hostname` instead of leaking cowrie's default.
func TestHoneyfsEtcHostsConsistent(t *testing.T) {
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "edge-01", "seed1")
	hosts, ok := files["etc/hosts"]
	if !ok {
		t.Fatal("generateHoneyfs must emit etc/hosts (its mount source)")
	}
	if !strings.Contains(hosts, "127.0.1.1\tedge-01\n") {
		t.Errorf("/etc/hosts missing the 127.0.1.1 <hostname> line:\n%s", hosts)
	}
	if !strings.Contains(hosts, "127.0.0.1\tlocalhost") {
		t.Error("/etc/hosts missing the localhost line")
	}
	// Must agree with /etc/hostname.
	if strings.TrimSpace(files["etc/hostname"]) != "edge-01" {
		t.Error("/etc/hostname does not match the requested hostname")
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
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "h", "seed1")
	if _, ok := files["etc/motd"]; !ok {
		t.Error("generateHoneyfs must always emit etc/motd (its mount source)")
	}
}

// TestHoneyfsProcVersionConsistent verifies /proc/version agrees with the
// distro profile's kernel release and build string (a mismatch with `uname` is
// itself a fingerprint).
func TestHoneyfsProcVersionConsistent(t *testing.T) {
	for _, p := range distroProfiles {
		pv := procVersion(p)
		if !strings.HasPrefix(pv, "Linux version "+p.KernelVersion+" ") {
			t.Errorf("%s: /proc/version does not start with the kernel release: %q", p.OSPretty, pv)
		}
		if !strings.Contains(pv, p.KernelBuildString) {
			t.Errorf("%s: /proc/version missing the uname build string", p.OSPretty)
		}
		if !strings.HasSuffix(pv, "\n") {
			t.Errorf("%s: /proc/version should end with a newline", p.OSPretty)
		}
	}
}

// TestHoneyfsFilesAreMounted is the data-loss/tell guard: every file
// generateHoneyfs produces must be bind-mounted into Cowrie by the deploy
// profile, otherwise the generated (consistent) content is never served and the
// image's stock file shows through - reintroducing the very tell we fixed.
func TestHoneyfsFilesAreMounted(t *testing.T) {
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "host", "seed1")
	mounts := map[string]bool{}
	for _, v := range deployProfileFor("cowrie").Volumes {
		if strings.HasPrefix(v.HostSubdir, "honeyfs/") {
			mounts[strings.TrimPrefix(v.HostSubdir, "honeyfs/")] = true
		}
	}
	for rel := range files {
		if !mounts[rel] {
			t.Errorf("honeyfs file %q is generated but not mounted into Cowrie (stock file would show through)", rel)
		}
	}
}

// TestHoneyfsProcCPUInfoConsistent verifies /proc/cpuinfo is internally
// consistent and, critically, always reports exactly two CPUs so it agrees with
// Cowrie's hard-coded `nproc`/`free` builtins (a core-count mismatch between
// `cat /proc/cpuinfo` and `nproc` is a honeypot tell). It also checks the model
// varies across seeds (no globally-identical cpuinfo fingerprint).
func TestHoneyfsProcCPUInfoConsistent(t *testing.T) {
	for _, m := range cpuModels {
		ci := procCPUInfo(m)
		// Exactly two "processor : N" entries, numbered 0 and 1.
		if n := strings.Count(ci, "processor\t:"); n != 2 {
			t.Errorf("%q: cpuinfo must list exactly 2 processors (matches nproc=2), got %d", m.ModelName, n)
		}
		if !strings.Contains(ci, "processor\t: 0\n") || !strings.Contains(ci, "processor\t: 1\n") {
			t.Errorf("%q: cpuinfo processors must be numbered 0 and 1", m.ModelName)
		}
		// cpu cores / siblings must agree with the 2-CPU presentation.
		if c := strings.Count(ci, "cpu cores\t: 2\n"); c != 2 {
			t.Errorf("%q: each cpuinfo block must report 'cpu cores: 2'", m.ModelName)
		}
		// The model name, vendor and flags must be present (a thin cpuinfo is a tell).
		if !strings.Contains(ci, "model name\t: "+m.ModelName) {
			t.Errorf("%q: cpuinfo missing model name", m.ModelName)
		}
		if !strings.Contains(ci, "vendor_id\t: "+m.VendorID) {
			t.Errorf("%q: cpuinfo missing vendor_id", m.ModelName)
		}
		// vendor_id ↔ flags consistency: Intel models must not carry the AMD-only
		// svm flag and AMD models must not carry Intel's avx512.
		if m.VendorID == "GenuineIntel" && strings.Contains(ci, " svm ") {
			t.Errorf("%q: Intel cpuinfo leaks AMD svm flag", m.ModelName)
		}
		if m.VendorID == "AuthenticAMD" && strings.Contains(ci, "avx512f") {
			t.Errorf("%q: AMD cpuinfo leaks Intel avx512 flag", m.ModelName)
		}
	}
	// The CPU model must vary by seed so two deployments don't share a cpuinfo.
	seen := map[string]bool{}
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		seen[cpuModelForSeed(s).ModelName] = true
	}
	if len(seen) < 2 {
		t.Errorf("cpuModelForSeed should vary across seeds, got %d distinct models", len(seen))
	}
	// And it must be deterministic for a given seed (stable identity across
	// compose regeneration).
	if cpuModelForSeed("stable").ModelName != cpuModelForSeed("stable").ModelName {
		t.Error("cpuModelForSeed must be deterministic")
	}
}

// TestHoneyfsTimezone checks /etc/timezone matches cowrie's UTC clock.
func TestHoneyfsTimezone(t *testing.T) {
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[0], "h", "seed1")
	if got := files["etc/timezone"]; got != "Etc/UTC\n" {
		t.Errorf("etc/timezone = %q, want %q", got, "Etc/UTC\n")
	}
}

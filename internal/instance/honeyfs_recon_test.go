package instance

import (
	"strconv"
	"strings"
	"testing"
)

// TestHoneyfsReconFilesPopulated guards that the recon files cowrie's stock
// honeyfs ships EMPTY (or wrong) are now filled with realistic content - an
// empty /etc/resolv.conf, /etc/ssh/sshd_config or /etc/fstab on a box that
// obviously resolves DNS, runs sshd and has a mounted root is a direct tell.
func TestHoneyfsReconFilesPopulated(t *testing.T) {
	files := generateHoneyfs(credentialTemplates[0], distroProfiles[3], "host", "seedR")
	for _, k := range []string{
		"etc/resolv.conf", "etc/ssh/sshd_config", "etc/fstab",
		"etc/debian_version", "usr/lib/os-release",
		"proc/meminfo", "proc/swaps", "proc/mounts",
	} {
		if strings.TrimSpace(files[k]) == "" {
			t.Errorf("honeyfs %q is empty (stock tell not fixed)", k)
		}
	}
	// resolv.conf must contain at least one nameserver.
	if !strings.Contains(files["etc/resolv.conf"], "nameserver ") {
		t.Error("resolv.conf has no nameserver line")
	}
	// sshd_config must look like a real one (Subsystem sftp is in every default).
	if !strings.Contains(files["etc/ssh/sshd_config"], "Subsystem\tsftp") {
		t.Error("sshd_config missing the sftp Subsystem line")
	}
	// fstab must reference the root mount by UUID (real fstabs do).
	if !strings.Contains(files["etc/fstab"], "UUID=") || !strings.Contains(files["etc/fstab"], " /               ext4") {
		t.Errorf("fstab does not look realistic:\n%s", files["etc/fstab"])
	}
	// /usr/lib/os-release must read identically to /etc/os-release (symlink target).
	if files["usr/lib/os-release"] != files["etc/os-release"] {
		t.Error("/usr/lib/os-release must match /etc/os-release (they are the same file on a real box)")
	}
	// /proc/mounts must carry the kernel pseudo-filesystems a real box has.
	for _, m := range []string{"proc /proc proc", "sysfs /sys sysfs", "/ ext4"} {
		if !strings.Contains(files["proc/mounts"], m) {
			t.Errorf("/proc/mounts missing %q", m)
		}
	}
}

// TestHoneyfsMeminfoConsistent verifies /proc/meminfo carries the eight keys
// Cowrie's `free` builtin parses, that MemTotal/SwapTotal match the per-instance
// memProfile (so `free` and `cat /proc/meminfo` agree once the same file is
// bind-mounted over the real /proc/meminfo), and that the values are internally
// sane (MemFree <= MemAvailable <= MemTotal).
func TestHoneyfsMeminfoConsistent(t *testing.T) {
	parse := func(s string) map[string]int {
		m := map[string]int{}
		for _, ln := range strings.Split(s, "\n") {
			f := strings.Fields(ln)
			if len(f) >= 2 && strings.HasSuffix(f[0], ":") {
				if v, err := strconv.Atoi(f[1]); err == nil {
					m[strings.TrimSuffix(f[0], ":")] = v
				}
			}
		}
		return m
	}
	for _, seed := range []string{"a", "b", "c", "d", "e", "f"} {
		mem := memForSeed(seed)
		mi := parse(procMeminfo(mem))
		// The exact keys free.py needs.
		for _, k := range []string{"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree", "Shmem"} {
			if _, ok := mi[k]; !ok {
				t.Errorf("seed %s: /proc/meminfo missing key %q that `free` parses", seed, k)
			}
		}
		if mi["MemTotal"] != mem.TotalKB {
			t.Errorf("seed %s: MemTotal=%d, want %d (must match memForSeed for free/cat agreement)", seed, mi["MemTotal"], mem.TotalKB)
		}
		if mi["SwapTotal"] != mem.SwapKB {
			t.Errorf("seed %s: SwapTotal=%d, want %d", seed, mi["SwapTotal"], mem.SwapKB)
		}
		if !(mi["MemFree"] <= mi["MemAvailable"] && mi["MemAvailable"] <= mi["MemTotal"]) {
			t.Errorf("seed %s: meminfo values not sane: free=%d avail=%d total=%d", seed, mi["MemFree"], mi["MemAvailable"], mi["MemTotal"])
		}
		// swaps file must report the same swap size.
		if mem.SwapKB > 0 && !strings.Contains(procSwaps(mem), strconv.Itoa(mem.SwapKB)) {
			t.Errorf("seed %s: /proc/swaps does not report SwapTotal=%d", seed, mem.SwapKB)
		}
	}
	// Memory size must vary across instances (no globally-identical meminfo).
	seen := map[int]bool{}
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		seen[memForSeed(s).TotalKB] = true
	}
	if len(seen) < 2 {
		t.Errorf("memForSeed should vary across seeds, got %d distinct sizes", len(seen))
	}
}

// TestDistroProfilesAreDebianFamily is the coherence guard: Cowrie's bundled
// fake filesystem is a Debian box (apt, dpkg, /etc/debian_version, no
// /etc/redhat-release), so every distro identity MUST be Debian-family. A
// CentOS/RHEL profile would contradict the on-disk apt/debian_version the moment
// an attacker looks - the exact kind of tell this work removes.
func TestDistroProfilesAreDebianFamily(t *testing.T) {
	for _, p := range distroProfiles {
		low := strings.ToLower(p.OSPretty)
		for _, bad := range []string{"centos", "rhel", "red hat", "fedora", "rocky", "alma", "suse"} {
			if strings.Contains(low, bad) {
				t.Errorf("profile %q is not Debian-family but Cowrie's fake fs is Debian (apt/debian_version tell)", p.OSPretty)
			}
		}
		// Every profile must supply /etc/debian_version content (the fake fs has
		// the file; an empty value would render a blank line, itself odd).
		if strings.TrimSpace(p.DebianVersion) == "" {
			t.Errorf("profile %q has no DebianVersion (the Debian fake fs ships /etc/debian_version)", p.OSPretty)
		}
		// debian_version rendered into honeyfs must match the profile and agree
		// with the distro family (Ubuntu reports "<codename>/sid"; Debian a number).
		files := generateHoneyfs(credentialTemplates[0], p, "h", "s")
		if strings.TrimSpace(files["etc/debian_version"]) != p.DebianVersion {
			t.Errorf("profile %q: honeyfs /etc/debian_version != profile value", p.OSPretty)
		}
		if strings.Contains(low, "ubuntu") && !strings.HasSuffix(p.DebianVersion, "/sid") {
			t.Errorf("Ubuntu profile %q should report a '<codename>/sid' debian_version, got %q", p.OSPretty, p.DebianVersion)
		}
	}
}

// TestCowrieMeminfoBindMountedOverProc guards the /proc/meminfo bind mount that
// makes cowrie's `free` (which open()s the real /proc/meminfo, not honeyfs) read
// our fake size instead of leaking the Docker host's true RAM. The same
// generated file must be mounted BOTH into honeyfs (the `cat` path) and over the
// real /proc/meminfo (the `free` path).
func TestCowrieMeminfoBindMountedOverProc(t *testing.T) {
	var honeyfsMeminfo, procMeminfoMount bool
	for _, v := range deployProfileFor("cowrie").Volumes {
		if v.HostSubdir != "honeyfs/proc/meminfo" {
			continue
		}
		switch v.ContainerPath {
		case "/home/cowrie/cowrie/honeyfs/proc/meminfo":
			honeyfsMeminfo = true
		case "/proc/meminfo":
			procMeminfoMount = true
		}
	}
	if !honeyfsMeminfo {
		t.Error("cowrie must mount the generated meminfo into honeyfs (the `cat /proc/meminfo` path)")
	}
	if !procMeminfoMount {
		t.Error("cowrie must bind the SAME meminfo over /proc/meminfo (the `free` path) so free does not leak the host RAM")
	}
}

// TestEveryPersonaHasHostnamePool tightens the persona/host coherence invariant:
// EVERY credential persona must have a role-appropriate hostname pool, so the
// auto-derived hostname always matches the accounts that work (never a generic,
// possibly-mismatched fallback). New personas without a pool are caught here.
func TestEveryPersonaHasHostnamePool(t *testing.T) {
	for _, tmpl := range credentialTemplates {
		if len(personaHostnames[tmpl.Name]) == 0 {
			t.Errorf("persona %q has no hostname pool (add one to personaHostnames for coherence)", tmpl.Name)
		}
	}
}

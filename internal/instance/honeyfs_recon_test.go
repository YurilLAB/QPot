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
		mi := parse(procMeminfo(mem, seed))
		// The exact keys free.py needs.
		for _, k := range []string{"MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapTotal", "SwapFree", "Shmem"} {
			if _, ok := mi[k]; !ok {
				t.Errorf("seed %s: /proc/meminfo missing key %q that `free` parses", seed, k)
			}
		}
		// MemTotal must be the realistic non-power-of-two size (memTotalKB): a real
		// box never reports the exact nominal RAM, so MemTotal must be strictly
		// below nominal but within a few percent, and never the round nominal value.
		wantTotal := int(memTotalKB(mem, seed))
		if mi["MemTotal"] != wantTotal {
			t.Errorf("seed %s: MemTotal=%d, want %d (memTotalKB)", seed, mi["MemTotal"], wantTotal)
		}
		if mi["MemTotal"] == mem.TotalKB {
			t.Errorf("seed %s: MemTotal is the exact power-of-two nominal %d - real firmware/kernel reserve a few percent", seed, mem.TotalKB)
		}
		if !(mi["MemTotal"] < mem.TotalKB && mi["MemTotal"] > mem.TotalKB*94/100) {
			t.Errorf("seed %s: MemTotal=%d not within (94%%, 100%%) of nominal %d", seed, mi["MemTotal"], mem.TotalKB)
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

// TestHoneyfsCPUInfoBugsBogomips guards the /proc/cpuinfo realism fixes: every
// modern kernel prints a `bugs:` line, BogoMIPS is ~2x the base clock (not equal
// to cpu MHz), and the cpuid level / address sizes are the per-model values -
// and AMD parts, which are not affected by Meltdown/L1TF/MDS, must never list
// those bugs (an AMD block carrying cpu_meltdown is an internal contradiction).
func TestHoneyfsCPUInfoBugsBogomips(t *testing.T) {
	fieldValue := func(ci, key string) string {
		for _, ln := range strings.Split(ci, "\n") {
			if strings.HasPrefix(ln, key) {
				if i := strings.Index(ln, ":"); i >= 0 {
					return strings.TrimSpace(ln[i+1:])
				}
			}
		}
		return ""
	}
	for _, m := range cpuModels {
		ci := procCPUInfo(m)
		bugs := fieldValue(ci, "bugs\t")
		if bugs == "" {
			t.Errorf("%q: /proc/cpuinfo has no bugs line (every kernel >=2018 prints one)", m.ModelName)
		}
		// bogomips must be ~2x the cpu MHz, and must NOT equal cpu MHz.
		bogo, err1 := strconv.ParseFloat(fieldValue(ci, "bogomips"), 64)
		mhz, err2 := strconv.ParseFloat(m.MHz, 64)
		if err1 != nil || err2 != nil {
			t.Fatalf("%q: unparseable bogomips/MHz", m.ModelName)
		}
		if bogo == mhz {
			t.Errorf("%q: bogomips equals cpu MHz (%.3f) - emulation artifact", m.ModelName, mhz)
		}
		if diff := bogo - 2*mhz; diff > 0.5 || diff < -0.5 {
			t.Errorf("%q: bogomips=%.3f, want ~2x MHz=%.3f", m.ModelName, bogo, 2*mhz)
		}
		// cpuid level / address sizes must be the per-model values, not hardcoded.
		if got := fieldValue(ci, "cpuid level"); got != strconv.Itoa(m.CPUIDLevel) {
			t.Errorf("%q: cpuid level=%q, want %d", m.ModelName, got, m.CPUIDLevel)
		}
		if got := fieldValue(ci, "address sizes"); got != m.AddressSizes {
			t.Errorf("%q: address sizes=%q, want %q", m.ModelName, got, m.AddressSizes)
		}
		if m.VendorID == "AuthenticAMD" {
			for _, forbidden := range []string{"cpu_meltdown", "l1tf", "mds", "srbds", "taa"} {
				if strings.Contains(bugs, forbidden) {
					t.Errorf("%q: AMD bugs line contains Intel-only bug %q: %q", m.ModelName, forbidden, bugs)
				}
			}
		}
	}
}

// TestHoneyfsFstabEfiIsFatVolumeID guards that the EFI (vfat) partition in
// /etc/fstab carries a FAT volume serial (XXXX-XXXX uppercase), not an
// ext4-style lowercase UUID - the wrong format on a vfat line is a hard tell.
func TestHoneyfsFstabEfiIsFatVolumeID(t *testing.T) {
	for _, seed := range []string{"s1", "s2", "s3", "s4"} {
		fs := fstab(seed, memForSeed(seed))
		var efiLine string
		for _, ln := range strings.Split(fs, "\n") {
			if strings.Contains(ln, "/boot/efi") && strings.Contains(ln, "vfat") {
				efiLine = ln
			}
		}
		if efiLine == "" {
			t.Fatalf("seed %s: no /boot/efi vfat line in fstab:\n%s", seed, fs)
		}
		// Extract UUID=... token.
		var id string
		for _, f := range strings.Fields(efiLine) {
			if strings.HasPrefix(f, "UUID=") {
				id = strings.TrimPrefix(f, "UUID=")
			}
		}
		// Must match XXXX-XXXX with uppercase hex.
		if len(id) != 9 || id[4] != '-' {
			t.Errorf("seed %s: EFI vfat id %q is not FAT XXXX-XXXX form", seed, id)
		}
		if id != strings.ToUpper(id) {
			t.Errorf("seed %s: EFI vfat id %q must be uppercase (FAT serials are)", seed, id)
		}
		for _, r := range id {
			if r == '-' {
				continue
			}
			if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F')) {
				t.Errorf("seed %s: EFI vfat id %q has non-hex rune %q", seed, id, string(r))
			}
		}
	}
}

// TestHoneyfsProcMountsSizesTrackRAM guards that the devtmpfs/tmpfs sizes in
// /proc/mounts are derived from the per-instance RAM (not the old hardcoded
// ~8 GB), so udev never exceeds MemTotal (impossible on the 4 GB profile) and
// two different-size boxes report different mounts.
func TestHoneyfsProcMountsSizesTrackRAM(t *testing.T) {
	sizeOf := func(mounts, dev string) int64 {
		for _, ln := range strings.Split(mounts, "\n") {
			fields := strings.Fields(ln)
			if len(fields) < 2 || fields[1] != dev {
				continue
			}
			for _, opt := range strings.Split(ln, ",") {
				if strings.HasPrefix(opt, "size=") {
					v := strings.TrimSuffix(strings.TrimPrefix(opt, "size="), "k")
					n, _ := strconv.ParseInt(v, 10, 64)
					return n
				}
			}
		}
		return -1
	}
	for _, seed := range []string{"a", "b", "c", "d", "e", "f"} {
		mem := memForSeed(seed)
		total := memTotalKB(mem, seed)
		mounts := procMounts(mem, seed)
		udev := sizeOf(mounts, "/dev")
		run := sizeOf(mounts, "/run")
		if udev <= 0 || run <= 0 {
			t.Fatalf("seed %s: could not parse udev/run size from mounts:\n%s", seed, mounts)
		}
		// udev (devtmpfs) must never exceed total RAM, and must be ~half of it.
		if udev >= total {
			t.Errorf("seed %s: udev size %dk >= MemTotal %dk (devtmpfs cannot exceed RAM)", seed, udev, total)
		}
		if diff := udev - total/2; diff > total/50 || diff < -total/50 {
			t.Errorf("seed %s: udev size %dk not ~half of RAM %dk", seed, udev, total)
		}
		// /run must be ~10% of RAM.
		if diff := run - total/10; diff > total/50 || diff < -total/50 {
			t.Errorf("seed %s: /run size %dk not ~10%% of RAM %dk", seed, run, total)
		}
		if udev == 8155316 {
			t.Errorf("seed %s: udev size is the old hardcoded 8155316k", seed)
		}
	}
}

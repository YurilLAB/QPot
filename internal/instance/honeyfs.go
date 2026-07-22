package instance

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
)

// honeyfs.go generates a per-instance fake-filesystem layer for Cowrie so that
// post-login recon is internally consistent with the login persona and the
// advertised system identity.
//
// Research basis (Cowrie HONEYFS docs; Cowrie #1102 "/home/richard" tell;
// "Gotta Catch 'em All" DTRAP 2023; cryptax "Customizing Cowrie"): the dominant
// remaining Cowrie tell after identity/credential randomization is INTERNAL
// INCONSISTENCY — an attacker logs in as a persona user (e.g. jmartin), runs
// `cat /etc/passwd`, and that user is absent. Stock Cowrie also ships no
// /etc/os-release and a generic /etc/passwd/issue/hostname identical on every
// deployment. We generate these honeyfs files from the SAME persona + distro
// seed used for the credentials and the SSH identity, then bind-mount them over
// the image's honeyfs so `cat /etc/passwd`, `/etc/os-release`, `hostname`, the
// login banner, etc. all tell one coherent, deployment-unique story.
//
// Files are returned keyed by their path under honeyfs/ (e.g. "etc/passwd").

// systemPasswd is a realistic base set of Debian/Ubuntu system accounts. Real
// boxes have these; persona users are appended after them.
const systemPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin`

// serviceAccounts are persona usernames that, in a real system, are service
// accounts (nologin, system home) rather than human login users with /home.
var serviceAccounts = map[string]string{ // username -> home dir
	"www-data": "/var/www", "postgres": "/var/lib/postgresql", "mysql": "/var/lib/mysql",
	"oracle": "/opt/oracle", "dovecot": "/usr/lib/dovecot", "apache": "/var/www",
	"nagios": "/var/lib/nagios", "jenkins": "/var/lib/jenkins", "git": "/var/lib/git",
	"cpanel": "/usr/local/cpanel", "ftpuser": "/srv/ftp", "ubnt": "/home/ubnt",
	"gitlab-runner": "/home/gitlab-runner", "grafana": "/usr/share/grafana",
	"zabbix": "/var/lib/zabbix", "prometheus": "/var/lib/prometheus",
	"ftp": "/srv/ftp",
}

// presentInBase reports whether a username already exists in the system base.
func presentInBase(u string) bool {
	return strings.Contains(systemPasswd, "\n"+u+":") || strings.HasPrefix(systemPasswd, u+":")
}

// generateHoneyfs returns the per-instance honeyfs files for Cowrie, consistent
// with the given persona, distro profile, and hostname. seed selects the
// per-instance CPU model so two deployments don't report an identical
// /proc/cpuinfo.
func generateHoneyfs(t credentialTemplate, p distroProfile, hostname, seed string) map[string]string {
	hostname = sanitizeConfigValue(hostname)
	mem := memForSeed(seed)
	files := map[string]string{
		"etc/passwd":     etcPasswd(t),
		"etc/group":      etcGroup(t),
		"etc/hostname":   hostname + "\n",
		"etc/hosts":      etcHosts(hostname),
		"etc/os-release": osRelease(p, hostname),
		// /usr/lib/os-release is the canonical location modern distros ship; on a
		// real box /etc/os-release is a symlink to it, so the two must read
		// identically. Stock honeyfs leaves it empty, so `cat /usr/lib/os-release`
		// returns nothing while `cat /etc/os-release` has content - an easy tell.
		"usr/lib/os-release": osRelease(p, hostname),
		"etc/issue":          issue(p),
		"etc/motd":           motd(p, seed),
		// /etc/debian_version is present in Cowrie's (Debian) fake fs and is common
		// recon. Stock ships a fixed "12.5"; we render the value matching the
		// advertised release (Debian point version, or "<codename>/sid" on Ubuntu)
		// so it agrees with /etc/os-release and the SSH banner.
		"etc/debian_version": p.DebianVersion + "\n",
		// /etc/resolv.conf, /etc/ssh/sshd_config and /etc/fstab all exist in the
		// fake fs but ship EMPTY, so `cat` on any of them returns nothing on a box
		// that obviously has DNS, a running sshd and a mounted root - three direct
		// tells. Fill them with realistic, internally-consistent content.
		"etc/resolv.conf":     resolvConf(p, hostname),
		"etc/ssh/sshd_config": sshdConfig(p),
		"etc/fstab":           fstab(seed, mem),
		// /proc/version must agree with `uname -r` / `uname -v`; Cowrie's static
		// default contradicts the per-instance kernel/distro we advertise.
		"proc/version": procVersion(p),
		// /etc/timezone must agree with the shell's clock (cowrie timezone=UTC);
		// the file exists in the fake fs and `cat /etc/timezone` is common recon.
		"etc/timezone": "Etc/UTC\n",
		// /proc/cpuinfo exists in Cowrie's fake fs and `cat /proc/cpuinfo` is one
		// of the first recon commands. Cowrie's stock file is globally identical
		// (same model/MHz on every honeypot) - a fingerprint. We emit a realistic,
		// per-instance server CPU at a fixed 2-vcpu count (see procCPUInfo).
		"proc/cpuinfo": procCPUInfo(cpuModelForSeed(seed)),
		// /proc/meminfo, /proc/swaps and /proc/mounts: stock meminfo claims 256 MB
		// while `free` (which opens the REAL /proc/meminfo) leaks the Docker host's
		// true RAM - both a tell and a contradiction. We render a believable,
		// per-instance size here AND bind-mount this same file over the real
		// /proc/meminfo (see deploy.go) so `cat /proc/meminfo` and `free` agree and
		// neither leaks the host. swaps/mounts are filled to match.
		"proc/meminfo": procMeminfo(mem, seed),
		"proc/swaps":   procSwaps(mem),
		"proc/mounts":  procMounts(mem, seed),
	}
	return files
}

// procCPUInfo renders a realistic /proc/cpuinfo for exactly two logical CPUs.
//
// The CPU *model* varies per instance (via cpuModelForSeed) so two deployments
// do not share an identical /proc/cpuinfo, but the processor *count* is pinned
// at two - a believable small VPS shape - rather than seeded: it keeps the file
// stable across regenerations and avoids contradicting the 2-vcpu story the rest
// of the profile tells. (Cowrie does not implement `nproc`, and `free` reads the
// /proc/meminfo we bind-mount, so there is no builtin reporting a different core
// count to disagree with.)
func procCPUInfo(m cpuModel) string {
	var b strings.Builder
	for cpu := 0; cpu < 2; cpu++ {
		fmt.Fprintf(&b, "processor\t: %d\n", cpu)
		fmt.Fprintf(&b, "vendor_id\t: %s\n", m.VendorID)
		fmt.Fprintf(&b, "cpu family\t: %d\n", m.Family)
		fmt.Fprintf(&b, "model\t\t: %d\n", m.Model)
		fmt.Fprintf(&b, "model name\t: %s\n", m.ModelName)
		fmt.Fprintf(&b, "stepping\t: %d\n", m.Stepping)
		fmt.Fprintf(&b, "microcode\t: %s\n", m.Microcode)
		fmt.Fprintf(&b, "cpu MHz\t\t: %s\n", m.MHz)
		fmt.Fprintf(&b, "cache size\t: %d KB\n", m.CacheKB)
		fmt.Fprintf(&b, "physical id\t: 0\n")
		fmt.Fprintf(&b, "siblings\t: 2\n")
		fmt.Fprintf(&b, "core id\t\t: %d\n", cpu)
		fmt.Fprintf(&b, "cpu cores\t: 2\n")
		fmt.Fprintf(&b, "apicid\t\t: %d\n", cpu)
		fmt.Fprintf(&b, "initial apicid\t: %d\n", cpu)
		fmt.Fprintf(&b, "fpu\t\t: yes\n")
		fmt.Fprintf(&b, "fpu_exception\t: yes\n")
		fmt.Fprintf(&b, "cpuid level\t: %d\n", m.CPUIDLevel)
		fmt.Fprintf(&b, "wp\t\t: yes\n")
		fmt.Fprintf(&b, "flags\t\t: %s\n", m.Flags)
		fmt.Fprintf(&b, "bugs\t\t: %s\n", m.Bugs)
		// BogoMIPS on modern x86 is ~2x the CPU's rated base clock (e.g. a 2.80 GHz
		// part reports ~5586.87, i.e. 2*2793.436), NOT equal to `cpu MHz`. bogomips
		// == cpu MHz is a well-known emulation artifact, so derive it as 2*MHz.
		fmt.Fprintf(&b, "bogomips\t: %s\n", bogomipsFor(m.MHz))
		fmt.Fprintf(&b, "clflush size\t: 64\n")
		fmt.Fprintf(&b, "cache_alignment\t: 64\n")
		fmt.Fprintf(&b, "address sizes\t: %s\n", m.AddressSizes)
		fmt.Fprintf(&b, "power management:\n")
		b.WriteString("\n")
	}
	return b.String()
}

// bogomipsFor renders a realistic BogoMIPS string for a given "cpu MHz" value:
// ~2x the base clock, keeping two decimals the way real /proc/cpuinfo does. If
// the MHz string is unparseable it falls back to the input so the file is never
// malformed.
func bogomipsFor(mhz string) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(mhz), 64)
	if err != nil {
		return mhz
	}
	return strconv.FormatFloat(f*2, 'f', 2, 64)
}

// procVersion builds a realistic /proc/version consistent with the distro
// profile's kernel release (uname -r) and build string (uname -v).
func procVersion(p distroProfile) string {
	// All distro profiles are Debian-family (see deception.go), so only the
	// Ubuntu default and the Debian branch can ever apply here.
	builder, gcc := "buildd@lcy02-amd64-079", "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	if strings.Contains(strings.ToLower(p.OSPretty), "debian") {
		builder, gcc = "debian-kernel@lists.debian.org", "gcc-12 (Debian 12.2.0-14) 12.2.0"
	}
	return fmt.Sprintf("Linux version %s (%s) (%s, GNU ld) %s\n",
		p.KernelVersion, builder, gcc, p.KernelBuildString)
}

// etcHosts builds a standard Debian/Ubuntu /etc/hosts. The 127.0.1.1 line must
// carry the SAME per-instance hostname as /etc/hostname and the shell prompt;
// cowrie's stock /etc/hosts hard-codes a fixed hostname, so `cat /etc/hosts`
// otherwise both reveals the default and contradicts `hostname`.
func etcHosts(hostname string) string {
	return "127.0.0.1\tlocalhost\n" +
		"127.0.1.1\t" + hostname + "\n\n" +
		"# The following lines are desirable for IPv6 capable hosts\n" +
		"::1     ip6-localhost ip6-loopback\n" +
		"fe00::0 ip6-localnet\n" +
		"ff00::0 ip6-mcastprefix\n" +
		"ff02::1 ip6-allnodes\n" +
		"ff02::2 ip6-allrouters\n"
}

// debianMOTD is the stock /etc/motd shipped on a Debian system.
const debianMOTD = `
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
`

// motd returns a per-instance /etc/motd - the login-time message the attacker
// sees on EVERY session, and the single most-repeated piece of "communication"
// a honeypot emits. Cowrie's default ships the Debian boilerplate on every box (a
// globally-identical fingerprint, and a tell on a non-Debian box). We instead
// derive it from the distro AND a seed-picked STYLE, so the greeting differs
// across deployments rather than being one canned response:
//
//   - Ubuntu boxes show the real update-motd shape (welcome/version line, the
//     canonical doc/management/support links, and a per-instance "N updates can
//     be applied / M security updates" count) - the exact stable parts of a real
//     Ubuntu login (volatile load/memory stats are deliberately omitted so two
//     logins never show a suspiciously-identical live figure).
//   - a MIXTURE of three styles varies it further: full, links-stripped, or
//     fronted by an "authorized access only" legal banner (common on corporate /
//     bastion boxes). Debian keeps its standard boilerplate, optionally behind the
//     same banner.
//
// The Ubuntu version/kernel in the banner match uname; the update counts and
// banner choice come from the seed, so no two deployments greet identically.
func motd(p distroProfile, seed string) string {
	low := strings.ToLower(p.OSPretty)
	style := seededIndex("motdstyle:"+seed, 3)
	var b strings.Builder
	if style == 2 {
		b.WriteString("*******************************************************************\n")
		b.WriteString("*                                                                 *\n")
		b.WriteString("*  Authorized access only. All activity on this system is logged  *\n")
		b.WriteString("*  and monitored. Disconnect now if you are not an authorized      *\n")
		b.WriteString("*  user.                                                          *\n")
		b.WriteString("*                                                                 *\n")
		b.WriteString("*******************************************************************\n\n")
	}
	if strings.Contains(low, "ubuntu") {
		fmt.Fprintf(&b, "Welcome to %s (GNU/Linux %s x86_64)\n\n", p.OSPretty, p.KernelVersion)
		if style != 1 {
			b.WriteString(" * Documentation:  https://help.ubuntu.com\n")
			b.WriteString(" * Management:     https://landscape.canonical.com\n")
			b.WriteString(" * Support:        https://ubuntu.com/pro\n\n")
		}
		// Force >=2 pending (and >=2 security) updates so the wording is always
		// plural (matches real Ubuntu grammar) and avoids a singular-edge tell.
		upd := 4 + seededIndex("motdupd:"+seed, 80)
		sec := 2 + seededIndex("motdsec:"+seed, upd/2)
		fmt.Fprintf(&b, "%d updates can be applied immediately.\n", upd)
		fmt.Fprintf(&b, "%d of these updates are standard security updates.\n", sec)
		b.WriteString("To see these additional updates run: apt list --upgradable\n\n")
		return b.String()
	}
	// Debian (all non-Ubuntu profiles are Debian): standard boilerplate.
	b.WriteString(debianMOTD)
	return b.String()
}

// etcPasswd builds /etc/passwd = system base + the persona's accounts, so every
// username the userdb accepts actually exists on the box.
func etcPasswd(t credentialTemplate) string {
	var b strings.Builder
	b.WriteString(systemPasswd)
	b.WriteString("\n")
	uid := 1000
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		if home, ok := serviceAccounts[name]; ok {
			// Service account: nologin, lower system-ish uid range.
			fmt.Fprintf(&b, "%s:x:%d:%d:%s:%s:/usr/sbin/nologin\n", name, uid, uid, name, home)
		} else {
			fmt.Fprintf(&b, "%s:x:%d:%d:%s,,,:/home/%s:/bin/bash\n", name, uid, uid, name, name)
		}
		uid++
	}
	return b.String()
}

// humanLoginUsers returns the persona's human login accounts (not root, not a
// base system account, not a service account) in persona order. These are the
// users that get a /home/<name>, a shell and - being the box's administrators -
// membership in sudo/adm. Deterministic and dedup'd, matching etcPasswd's set.
func humanLoginUsers(t credentialTemplate) []string {
	var out []string
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		if _, isService := serviceAccounts[name]; isService {
			continue
		}
		out = append(out, name)
	}
	return out
}

// etcGroup builds a matching /etc/group with a primary group per persona user.
// The human login accounts are added to sudo (gid 27) and adm (gid 4): a box
// whose ~/.bash_history is full of `sudo ...` must have its admin users actually
// IN the sudo group, or `id`/`groups`/`getent group sudo` contradicts the
// history (an empty sudo group on an admin box is a tell). A `shadow` group
// (gid 42) is also present so /etc/shadow's root:shadow ownership resolves.
func etcGroup(t credentialTemplate) string {
	humans := humanLoginUsers(t)
	admins := strings.Join(humans, ",")
	var b strings.Builder
	b.WriteString("root:x:0:\n")
	fmt.Fprintf(&b, "adm:x:4:%s\n", admins)
	fmt.Fprintf(&b, "sudo:x:27:%s\n", admins)
	b.WriteString("www-data:x:33:\n")
	b.WriteString("shadow:x:42:\n")
	b.WriteString("staff:x:50:\n")
	b.WriteString("users:x:100:\n")
	gid := 1000
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		fmt.Fprintf(&b, "%s:x:%d:\n", name, gid)
		gid++
	}
	return b.String()
}

// osRelease builds a plausible /etc/os-release consistent with the distro
// profile (so `cat /etc/os-release` agrees with the SSH banner's distro). Stock
// Cowrie ships no os-release at all, which is itself a tell on a modern box.
func osRelease(p distroProfile, hostname string) string {
	pretty := p.OSPretty
	id, name, versionID := "linux", "Linux", ""
	low := strings.ToLower(pretty)
	switch {
	case strings.Contains(low, "ubuntu"):
		id, name = "ubuntu", "Ubuntu"
		versionID = extractVersion(pretty)
	case strings.Contains(low, "debian"):
		id, name = "debian", "Debian GNU/Linux"
		versionID = extractVersion(pretty)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "PRETTY_NAME=\"%s\"\n", pretty)
	fmt.Fprintf(&b, "NAME=\"%s\"\n", name)
	if versionID != "" {
		fmt.Fprintf(&b, "VERSION_ID=\"%s\"\n", versionID)
		fmt.Fprintf(&b, "VERSION=\"%s\"\n", strings.TrimPrefix(pretty, name+" "))
	}
	// VERSION_CODENAME / UBUNTU_CODENAME: real os-release files carry the release
	// codename, and Ubuntu repeats it in UBUNTU_CODENAME. A missing codename on a
	// modern Debian/Ubuntu box is itself a tell.
	if p.Codename != "" {
		fmt.Fprintf(&b, "VERSION_CODENAME=%s\n", p.Codename)
	}
	fmt.Fprintf(&b, "ID=%s\n", id)
	// ID_LIKE places the distro in its family (Ubuntu -> debian, CentOS -> rhel
	// fedora); Debian itself has none.
	if p.IDLike != "" {
		fmt.Fprintf(&b, "ID_LIKE=%s\n", p.IDLike)
	}
	// HOME_URL / SUPPORT_URL / BUG_REPORT_URL round out the file the way a real
	// install has them, with the correct per-distro URLs (Ubuntu uses .com).
	switch id {
	case "ubuntu":
		b.WriteString("HOME_URL=\"https://www.ubuntu.com/\"\n")
		b.WriteString("SUPPORT_URL=\"https://help.ubuntu.com/\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n")
		if p.Codename != "" {
			fmt.Fprintf(&b, "UBUNTU_CODENAME=%s\n", p.Codename)
		}
	case "debian":
		b.WriteString("HOME_URL=\"https://www.debian.org/\"\n")
		b.WriteString("SUPPORT_URL=\"https://www.debian.org/support\"\n")
		b.WriteString("BUG_REPORT_URL=\"https://bugs.debian.org/\"\n")
	default:
		b.WriteString("HOME_URL=\"https://www." + id + ".org/\"\n")
	}
	return b.String()
}

// issue builds /etc/issue referencing the distro (login banner realism).
func issue(p distroProfile) string {
	return p.OSPretty + " \\n \\l\n\n"
}

// extractVersion pulls the first dotted/numeric version token out of an OS
// pretty name (e.g. "Ubuntu 22.04.3 LTS" -> "22.04").
func extractVersion(pretty string) string {
	for _, tok := range strings.Fields(pretty) {
		if len(tok) > 0 && tok[0] >= '0' && tok[0] <= '9' {
			parts := strings.Split(tok, ".")
			if len(parts) >= 2 {
				return parts[0] + "." + parts[1]
			}
			return parts[0]
		}
	}
	return ""
}

// uuidForSeed returns a deterministic RFC-4122-shaped UUID derived from seed.
// Used for /etc/fstab device identifiers so each instance has stable, unique,
// realistic UUIDs (real fstabs reference filesystems by UUID, not /dev names).
func uuidForSeed(seed string) string {
	h := func(s string) uint32 {
		f := fnv.New32a()
		_, _ = f.Write([]byte(s))
		return f.Sum32()
	}
	a := h("uuid-a:" + seed)
	b := h("uuid-b:" + seed)
	c := h("uuid-c:" + seed)
	d := h("uuid-d:" + seed)
	// Shape as xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (version 4, variant 1).
	return fmt.Sprintf("%08x-%04x-4%03x-%x%03x-%04x%08x",
		a, b&0xffff, (b>>16)&0xfff, 8+(c&0x3), (c>>2)&0xfff, (c>>16)&0xffff, d)
}

// fatVolumeIDForSeed returns a FAT/vfat volume serial in the canonical
// XXXX-XXXX uppercase form blkid/fstab use for an EFI System Partition. Derived
// from the seed so it is stable and unique per instance.
func fatVolumeIDForSeed(seed string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte("fatvol:" + seed))
	v := h.Sum32()
	return fmt.Sprintf("%04X-%04X", v>>16, v&0xffff)
}

// resolvConf renders a believable /etc/resolv.conf. Stock honeyfs leaves it
// empty, so `cat /etc/resolv.conf` returns nothing on a box that clearly resolves
// names. Ubuntu servers typically run systemd-resolved (the 127.0.0.53 stub);
// Debian servers more often carry static upstream resolvers. Either is realistic
// for that distro, so we branch on it to stay coherent with /etc/os-release.
func resolvConf(p distroProfile, hostname string) string {
	if strings.Contains(strings.ToLower(p.OSPretty), "ubuntu") {
		return "# This file is managed by man:systemd-resolved(8). Do not edit.\n" +
			"#\n" +
			"# This is a dynamic resolv.conf file for connecting local clients to the\n" +
			"# internal DNS stub resolver of systemd-resolved. This file lists all\n" +
			"# configured search domains.\n" +
			"#\n" +
			"# Run \"resolvectl status\" to see details about the uplink DNS servers\n" +
			"# currently in use.\n" +
			"nameserver 127.0.0.53\n" +
			"options edns0 trust-ad\n" +
			"search .\n"
	}
	return "nameserver 1.1.1.1\n" +
		"nameserver 8.8.8.8\n" +
		"nameserver 8.8.4.4\n"
}

// fstab renders a realistic /etc/fstab for an ext4 root + EFI + swapfile box,
// with per-instance UUIDs. Stock honeyfs ships it empty, so `cat /etc/fstab`
// returns nothing on a machine that obviously has a mounted root - a tell.
func fstab(seed string, mem memProfile) string {
	rootUUID := uuidForSeed("root:" + seed)
	// The EFI System Partition is vfat/FAT32. blkid and fstab express a FAT
	// volume's 32-bit serial as XXXX-XXXX (uppercase hex, with the dash) - NOT a
	// full RFC-4122 UUID and NOT lowercase. Rendering an ext4-style id on a vfat
	// line is an impossible format that flags a fabricated fstab.
	efiID := fatVolumeIDForSeed("efi:" + seed)
	var b strings.Builder
	b.WriteString("# /etc/fstab: static file system information.\n")
	b.WriteString("#\n")
	b.WriteString("# Use 'blkid' to print the universally unique identifier for a\n")
	b.WriteString("# device; this may be used with UUID= as a more robust way to name devices\n")
	b.WriteString("# that works even if disks are added and removed. See fstab(5).\n")
	b.WriteString("#\n")
	b.WriteString("# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n")
	b.WriteString("# / was on /dev/sda1 during installation\n")
	fmt.Fprintf(&b, "UUID=%s /               ext4    errors=remount-ro 0       1\n", rootUUID)
	b.WriteString("# /boot/efi was on /dev/sda15 during installation\n")
	fmt.Fprintf(&b, "UUID=%s  /boot/efi       vfat    umask=0077      0       1\n", efiID)
	if mem.SwapKB > 0 {
		b.WriteString("/swapfile                                 none            swap    sw              0       0\n")
	}
	return b.String()
}

// sshdConfig renders a realistic /etc/ssh/sshd_config for a Debian/Ubuntu box.
// Stock honeyfs ships it empty, yet sshd is plainly running (the attacker just
// logged in over it), so an empty config is a tell. The content is the standard
// distribution default - mostly the commented-out defaults a real install keeps,
// plus the handful of active lines Debian/Ubuntu ship - and contains nothing
// that contradicts the advertised OpenSSH version.
func sshdConfig(p distroProfile) string {
	sftp := "/usr/lib/openssh/sftp-server"
	return `# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

#KerberosAuthentication no
#GSSAPIAuthentication no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem	sftp	` + sftp + `
`
}

// procMeminfo renders a realistic /proc/meminfo for the given memory size. It
// includes every field a real meminfo carries (so `cat /proc/meminfo` looks
// genuine) and, crucially, the eight keys Cowrie's `free` builtin parses
// (MemTotal/MemFree/MemAvailable/Buffers/Cached/SwapTotal/SwapFree/Shmem) with
// internally-consistent values, since this same file is bind-mounted over the
// real /proc/meminfo that `free` reads.
func procMeminfo(mem memProfile, seed string) string {
	// int64 throughout: a few fields (notably VmallocTotal, ~32 TiB in kB) exceed
	// 2^31, so plain int would overflow on 32-bit build targets (linux/arm).
	// MemTotal is the realistic (non-power-of-two, per-instance) size, not the
	// round nominal - see memTotalKB.
	total := memTotalKB(mem, seed)
	// Believable proportions for a lightly-loaded server.
	free := total * 58 / 100
	buffers := total * 2 / 100
	cached := total * 24 / 100
	available := free + cached + buffers
	shmem := total / 512
	swapTotal := int64(mem.SwapKB)
	swapFree := swapTotal
	sReclaim := total * 3 / 100
	slab := sReclaim + total/100
	f := func(k string, v int64) string { return fmt.Sprintf("%-16s%9d kB\n", k+":", v) }
	var b strings.Builder
	b.WriteString(f("MemTotal", total))
	b.WriteString(f("MemFree", free))
	b.WriteString(f("MemAvailable", available))
	b.WriteString(f("Buffers", buffers))
	b.WriteString(f("Cached", cached))
	b.WriteString(f("SwapCached", 0))
	b.WriteString(f("Active", total*30/100))
	b.WriteString(f("Inactive", total*18/100))
	b.WriteString(f("Active(anon)", total*12/100))
	b.WriteString(f("Inactive(anon)", total/100))
	b.WriteString(f("Active(file)", total*18/100))
	b.WriteString(f("Inactive(file)", total*17/100))
	b.WriteString(f("Unevictable", 0))
	b.WriteString(f("Mlocked", 0))
	b.WriteString(f("SwapTotal", swapTotal))
	b.WriteString(f("SwapFree", swapFree))
	b.WriteString(f("Dirty", 128))
	b.WriteString(f("Writeback", 0))
	b.WriteString(f("AnonPages", total*13/100))
	b.WriteString(f("Mapped", total*3/100))
	b.WriteString(f("Shmem", shmem))
	b.WriteString(f("KReclaimable", sReclaim))
	b.WriteString(f("Slab", slab))
	b.WriteString(f("SReclaimable", sReclaim))
	b.WriteString(f("SUnreclaim", total/100))
	b.WriteString(f("KernelStack", 8192))
	b.WriteString(f("PageTables", total/256))
	b.WriteString(f("NFS_Unstable", 0))
	b.WriteString(f("Bounce", 0))
	b.WriteString(f("WritebackTmp", 0))
	b.WriteString(f("CommitLimit", total/2+swapTotal))
	b.WriteString(f("Committed_AS", total*20/100))
	b.WriteString(f("VmallocTotal", 34359738367))
	b.WriteString(f("VmallocUsed", total/400))
	b.WriteString(f("VmallocChunk", 0))
	b.WriteString(f("Percpu", 2048))
	b.WriteString(f("HardwareCorrupted", 0))
	b.WriteString(f("AnonHugePages", 0))
	b.WriteString(f("ShmemHugePages", 0))
	b.WriteString(f("ShmemPmdMapped", 0))
	b.WriteString(f("Hugepagesize", 2048))
	b.WriteString(f("DirectMap4k", total*8/100))
	b.WriteString(f("DirectMap2M", total*92/100))
	return b.String()
}

// procSwaps renders /proc/swaps consistent with the meminfo swap size. Stock
// honeyfs ships it empty.
func procSwaps(mem memProfile) string {
	b := "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	if mem.SwapKB > 0 {
		b += fmt.Sprintf("/swapfile                               file\t\t%d\t\t0\t\t-2\n", mem.SwapKB)
	}
	return b
}

// procMounts renders a realistic /proc/mounts for an ext4-root server. Stock
// honeyfs ships a near-empty file; `cat /proc/mounts` (and `mount`) is common
// recon, and the absence of the usual kernel pseudo-filesystems is a tell.
//
// The devtmpfs (/dev) and tmpfs (/run, /run/user/0) SIZES are derived from the
// per-instance RAM, not hardcoded: real Linux sizes devtmpfs at ~half of RAM and
// /run at ~10%, so a fixed "size=8155316k" (≈8 GB) both contradicts the box's
// own /proc/meminfo (impossible - larger than total RAM - on the 4 GB profile)
// and is byte-identical across every deployment (a cross-QPot fingerprint). We
// compute them from the same MemTotal /proc/meminfo reports (memTotalKB) so the
// two agree, with the real nr_inodes≈size/4 relationship.
func procMounts(mem memProfile, seed string) string {
	total := memTotalKB(mem, seed)
	devSize := total / 2 // devtmpfs defaults to ~half of RAM
	devInodes := devSize / 4
	runSize := total / 10 // /run tmpfs defaults to ~10% of RAM
	runUserSize := runSize - 4
	runUserInodes := runUserSize / 4
	return strings.Join([]string{
		"sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0",
		"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
		fmt.Sprintf("udev /dev devtmpfs rw,nosuid,relatime,size=%dk,nr_inodes=%d,mode=755 0 0", devSize, devInodes),
		"devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0",
		fmt.Sprintf("tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size=%dk,mode=755 0 0", runSize),
		"/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0",
		"securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0",
		"tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0",
		"tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0",
		"cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0",
		"pstore /sys/fs/pstore pstore rw,nosuid,nodev,noexec,relatime 0 0",
		"bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0",
		"mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0",
		"debugfs /sys/kernel/debug debugfs rw,nosuid,nodev,noexec,relatime 0 0",
		"tracefs /sys/kernel/tracing tracefs rw,nosuid,nodev,noexec,relatime 0 0",
		"/dev/sda15 /boot/efi vfat rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=mixed,errors=remount-ro 0 0",
		fmt.Sprintf("tmpfs /run/user/0 tmpfs rw,nosuid,nodev,relatime,size=%dk,nr_inodes=%d,mode=700 0 0", runUserSize, runUserInodes),
	}, "\n") + "\n"
}

// --- per-instance system-identity files served via the fs-patch realfile path
// (see cowriefs.go). These are files the stock fake fs either lacks a node for
// (machine-id, lsb-release), ships as an empty size-0 node (/proc/loadavg,
// /proc/sys/kernel/*), or fills with content that contradicts QPot's rewritten
// /etc/passwd (/etc/shadow). Each is generated coherently with the same
// persona/distro/hostname/seed the rest of the identity uses. ---

// machineIDForSeed returns a per-instance /etc/machine-id: 32 lowercase hex
// (128-bit), created once per install on every systemd distro. Stock Cowrie
// ships none, so `cat /etc/machine-id` is empty/absent on a box that plainly
// runs systemd (a tell), and a fixed value would be a perfect cross-deployment
// correlator - so it must be unique per instance. /var/lib/dbus/machine-id is
// the same value on a real box.
func machineIDForSeed(seed string) string {
	sum := sha512.Sum512([]byte("machine-id:" + seed))
	return hex.EncodeToString(sum[:16])
}

// lsbRelease returns /etc/lsb-release for Ubuntu profiles (Debian ships none by
// default). An Ubuntu box whose /etc/os-release says "Ubuntu 22.04" but whose
// /etc/lsb-release is empty/absent is an internal contradiction, and
// `lsb_release -a` reads this file. Returns "" for non-Ubuntu (caller omits it).
func lsbRelease(p distroProfile) string {
	if !strings.Contains(strings.ToLower(p.OSPretty), "ubuntu") {
		return ""
	}
	ver := extractVersion(p.OSPretty)
	return fmt.Sprintf("DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=%s\nDISTRIB_CODENAME=%s\nDISTRIB_DESCRIPTION=\"%s\"\n",
		ver, p.Codename, p.OSPretty)
}

// procLoadavg returns a believable /proc/loadavg. The three load figures are
// 0.00 to stay CONSISTENT with Cowrie's `w`, which hardcodes "load average:
// 0.00, 0.00, 0.00" - a non-zero /proc/loadavg would contradict `w`. The
// running/total task counts and last-pid vary per instance. (Stock ships this
// as an empty size-0 node, so `cat /proc/loadavg` returns nothing - a tell.)
func procLoadavg(seed string) string {
	total := 90 + seededIndex("loadprocs:"+seed, 240)
	lastpid := 1200 + seededIndex("lastpid:"+seed, 30000)
	return fmt.Sprintf("0.00 0.00 0.00 1/%d %d\n", total, lastpid)
}

// shadowSaltForSeed returns a stable 16-char crypt salt (from the crypt(3)
// alphabet) for a user, derived from the seed so hashes are per-instance and
// deterministic.
func shadowSaltForSeed(name, seed string) string {
	sum := sha512.Sum512([]byte("shadowsalt:" + name + ":" + seed))
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		b[i] = cryptAlphabet[sum[i]&0x3f]
	}
	return string(b)
}

// etcShadow builds /etc/shadow consistent with the generated /etc/passwd: every
// account that can actually log in (the persona's users, incl. root and any
// service account the persona accepts) carries a REAL $6$ sha512-crypt hash of
// its primary password, so an attacker who dumps and cracks shadow recovers a
// password that genuinely works - reinforcing the illusion rather than
// contradicting it. Locked system accounts (daemon, bin, sshd, ...) get "*".
func etcShadow(t credentialTemplate, seed string) string {
	pw := map[string]string{} // username -> primary (first) password
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || len(u.Passwords) == 0 {
			continue
		}
		if _, ok := pw[name]; !ok {
			pw[name] = u.Passwords[0]
		}
	}
	lastchg := 19000 + seededIndex("shadowage:"+seed, 700) // days since epoch (~2022-2024)
	field := func(name string) string {
		if p, ok := pw[name]; ok {
			return sha512Crypt(p, shadowSaltForSeed(name, seed))
		}
		return "*"
	}
	var b strings.Builder
	emit := func(name string) {
		fmt.Fprintf(&b, "%s:%s:%d:0:99999:7:::\n", name, field(name), lastchg)
	}
	// Base system accounts, in the same order as systemPasswd.
	for _, ln := range strings.Split(systemPasswd, "\n") {
		if i := strings.Index(ln, ":"); i > 0 {
			emit(ln[:i])
		}
	}
	// Persona users appended after the base set (same dedup rules as etcPasswd).
	seen := map[string]bool{}
	for _, u := range t.Users {
		name := sanitizeConfigValue(u.Username)
		if name == "" || seen[name] || presentInBase(name) {
			continue
		}
		seen[name] = true
		emit(name)
	}
	return b.String()
}

// seqRepeat returns src repeated/truncated to exactly n bytes (a helper for
// sha512Crypt's P/S sequences).
func seqRepeat(src []byte, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = src[i%len(src)]
	}
	return out
}

// cryptAlphabet is the crypt(3) base64 alphabet (NOT standard base64 ordering).
const cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// sha512Crypt implements the glibc SHA-512 crypt ($6$) scheme (Ulrich Drepper's
// spec, 5000 rounds) so a generated /etc/shadow hash actually verifies against
// the given password - matching `openssl passwd -6` and glibc crypt(3) exactly.
func sha512Crypt(password, salt string) string {
	const rounds = 5000
	if len(salt) > 16 {
		salt = salt[:16]
	}
	key := []byte(password)
	saltb := []byte(salt)

	// Digest B = SHA512(key + salt + key).
	bh := sha512.New()
	bh.Write(key)
	bh.Write(saltb)
	bh.Write(key)
	digestB := bh.Sum(nil)

	// Digest A.
	ah := sha512.New()
	ah.Write(key)
	ah.Write(saltb)
	for cnt := len(key); cnt > 0; {
		if cnt > 64 {
			ah.Write(digestB)
			cnt -= 64
		} else {
			ah.Write(digestB[:cnt])
			cnt = 0
		}
	}
	for i := len(key); i > 0; i >>= 1 {
		if i&1 == 1 {
			ah.Write(digestB)
		} else {
			ah.Write(key)
		}
	}
	digestA := ah.Sum(nil)

	// DP -> P (length len(key)).
	dp := sha512.New()
	for i := 0; i < len(key); i++ {
		dp.Write(key)
	}
	p := seqRepeat(dp.Sum(nil), len(key))

	// DS -> S (length len(salt)).
	dsh := sha512.New()
	for i := 0; i < 16+int(digestA[0]); i++ {
		dsh.Write(saltb)
	}
	s := seqRepeat(dsh.Sum(nil), len(saltb))

	// Rounds.
	c := digestA
	for i := 0; i < rounds; i++ {
		h := sha512.New()
		if i&1 == 1 {
			h.Write(p)
		} else {
			h.Write(c)
		}
		if i%3 != 0 {
			h.Write(s)
		}
		if i%7 != 0 {
			h.Write(p)
		}
		if i&1 == 1 {
			h.Write(c)
		} else {
			h.Write(p)
		}
		c = h.Sum(nil)
	}
	return "$6$" + salt + "$" + b64Crypt(c)
}

// b64Crypt encodes the 64-byte SHA-512 digest with the crypt(3) byte
// permutation and alphabet (86 chars). glibc's b64_from_24bit(B2,B1,B0) treats
// the first source byte as the high byte of the 24-bit group.
func b64Crypt(c []byte) string {
	order := [][3]int{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26},
		{6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38},
		{18, 39, 60}, {40, 61, 19}, {62, 20, 41},
	}
	var out []byte
	emit := func(w uint, n int) {
		for i := 0; i < n; i++ {
			out = append(out, cryptAlphabet[w&0x3f])
			w >>= 6
		}
	}
	for _, g := range order {
		emit(uint(c[g[0]])<<16|uint(c[g[1]])<<8|uint(c[g[2]]), 4)
	}
	emit(uint(c[63]), 2)
	return string(out)
}

// embeddedSystemFiles returns the per-instance system-identity files planted
// into the fake fs by the startup patch (cowriefs.go), coherent with the same
// persona/distro/hostname/seed the rest of the deception uses. hostname must be
// the SAME name cowrie.cfg/etc-hostname advertise.
func embeddedSystemFiles(t credentialTemplate, p distroProfile, hostname, seed string) []embeddedFile {
	machineID := machineIDForSeed(seed) + "\n"
	files := []embeddedFile{
		{Path: "/etc/machine-id", UID: 0, GID: 0, Mode: 0o100444, Content: machineID},
		{Path: "/var/lib/dbus/machine-id", UID: 0, GID: 0, Mode: 0o100444, Content: machineID},
		{Path: "/etc/shadow", UID: 0, GID: 42, Mode: 0o100640, Content: etcShadow(t, seed)},
		{Path: "/proc/loadavg", UID: 0, GID: 0, Mode: 0o100444, Content: procLoadavg(seed)},
		{Path: "/proc/sys/kernel/hostname", UID: 0, GID: 0, Mode: 0o100644, Content: sanitizeConfigValue(hostname) + "\n"},
		{Path: "/proc/sys/kernel/osrelease", UID: 0, GID: 0, Mode: 0o100444, Content: p.KernelVersion + "\n"},
		{Path: "/proc/sys/kernel/ostype", UID: 0, GID: 0, Mode: 0o100444, Content: "Linux\n"},
		{Path: "/proc/sys/kernel/version", UID: 0, GID: 0, Mode: 0o100444, Content: p.KernelBuildString + "\n"},
	}
	if lsb := lsbRelease(p); lsb != "" {
		files = append(files, embeddedFile{Path: "/etc/lsb-release", UID: 0, GID: 0, Mode: 0o100644, Content: lsb})
	}
	return files
}

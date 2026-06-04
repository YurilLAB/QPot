// Package instance: deception.go provides per-instance honeypot identity
// derivation to reduce fingerprintability.
//
// Research basis: the dominant weakness of a stock T-Pot deployment is that
// every instance ships globally-identical static identity strings — the same
// Cowrie hostname, the same advertised SSH version
// ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"), the same kernel/uname output.
// Those constants are themselves the fingerprint, and internet-scale scanners
// (Shodan Honeyscore, "Gotta Catch 'em All", and default-config probes) key on
// them. The literature's central recommendation is per-deployment randomization
// of all identity strings, kept INTERNALLY CONSISTENT (e.g. the advertised SSH
// version's distro must match the uname/kernel output, or the mismatch is
// itself a tell — Vetterl & Clayton, USENIX WOOT '18; "Gotta Catch 'em All",
// ACM DTRAP 2023; SANS ISC diary 31064; Cowrie issue #1102).
//
// QPot derives a deterministic-but-unique identity per instance from a stable
// seed (the QPot ID). Deterministic so a regenerated compose keeps a stable
// identity; unique so no two QPot instances — and no QPot-vs-T-Pot — share a
// signature. Operators can still override any field explicitly via the stealth
// config. NOTE: this raises the bar against keyword/Shodan/script detection and
// default-config tells; it does NOT defeat single-packet protocol-level
// fingerprinting (Vetterl), which is rooted in the honeypot's Python transport
// libraries and requires a high-interaction/proxy mode.
package instance

import (
	"fmt"
	"hash/fnv"
)

// distroProfile bundles a self-consistent Linux identity: the advertised SSH
// version string and the matching uname/kernel fields. Keeping these together
// guarantees the emulated system is internally consistent (the SSH banner's
// distro matches what `uname -a` / `/proc/version` report).
type distroProfile struct {
	// SSHVersion is the OpenSSH version token (without the "SSH-2.0-" prefix),
	// matching the strings real distros advertise.
	SSHVersion string
	// KernelVersion is `uname -r`.
	KernelVersion string
	// KernelBuildString is the build tag shown in `uname -v`.
	KernelBuildString string
	// HardwarePlatform is `uname -i`/`-m` (architecture).
	HardwarePlatform string
	// OperatingSystem is `uname -o`.
	OperatingSystem string
	// OSPretty is the human distro string (e.g. /etc/os-release PRETTY_NAME).
	OSPretty string
	// Codename is the release codename (/etc/os-release VERSION_CODENAME), e.g.
	// "bookworm" or "jammy". Empty for distros that do not use one (CentOS 7).
	Codename string
	// IDLike is the /etc/os-release ID_LIKE value, e.g. "debian" for Ubuntu or
	// "rhel fedora" for CentOS. Empty for Debian (which has no ID_LIKE).
	IDLike string
}

// distroProfiles are realistic, internally-consistent identities drawn from
// common real-world Linux servers. Each pairs an OpenSSH version actually
// shipped by that distro release with that release's kernel. None of these is
// the static value T-Pot's Cowrie advertises by default.
var distroProfiles = []distroProfile{
	{
		SSHVersion:        "OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
		KernelVersion:     "5.4.0-169-generic",
		KernelBuildString: "#187-Ubuntu SMP Thu Nov 23 14:52:28 UTC 2023",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Ubuntu 20.04.6 LTS",
		Codename:          "focal",
		IDLike:            "debian",
	},
	{
		SSHVersion:        "OpenSSH_8.4p1 Debian-5+deb11u3",
		KernelVersion:     "5.10.0-27-amd64",
		KernelBuildString: "#1 SMP Debian 5.10.205-2 (2023-12-31)",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Debian GNU/Linux 11 (bullseye)",
		Codename:          "bullseye",
	},
	{
		SSHVersion:        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		KernelVersion:     "5.15.0-91-generic",
		KernelBuildString: "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Ubuntu 22.04.3 LTS",
		Codename:          "jammy",
		IDLike:            "debian",
	},
	{
		SSHVersion:        "OpenSSH_9.2p1 Debian-2+deb12u3",
		KernelVersion:     "6.1.0-18-amd64",
		KernelBuildString: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Debian GNU/Linux 12 (bookworm)",
		Codename:          "bookworm",
	},
	{
		SSHVersion:        "OpenSSH_7.4",
		KernelVersion:     "3.10.0-1160.105.1.el7.x86_64",
		KernelBuildString: "#1 SMP Thu Dec 7 15:39:45 UTC 2023",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "CentOS Linux 7 (Core)",
		IDLike:            "rhel fedora",
	},
	{
		SSHVersion:        "OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
		KernelVersion:     "6.8.0-31-generic",
		KernelBuildString: "#31-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 20 00:40:06 UTC 2024",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Ubuntu 24.04 LTS",
		Codename:          "noble",
		IDLike:            "debian",
	},
}

// realisticHostnames is a pool of plausible production-server hostnames. None is
// Cowrie's default "svr04" or T-Pot's "srv01".
var realisticHostnames = []string{
	"web01", "web-prod-02", "app-server-1", "db-prod", "db01", "mail",
	"ns1", "gw-01", "vps-3", "srv-app-04", "backend-2", "edge-01",
	"node-07", "api-prod", "cache-1", "fileserver",
}

// seededIndex returns a stable index in [0,n) derived from seed. Deterministic
// (FNV-1a) so the same instance always maps to the same identity.
func seededIndex(seed string, n int) int {
	if n <= 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	return int(h.Sum32() % uint32(n))
}

// profileForSeed returns the internally-consistent distro identity for a seed.
func profileForSeed(seed string) distroProfile {
	return distroProfiles[seededIndex(seed, len(distroProfiles))]
}

// hostnameForSeed returns a per-instance hostname from the generic pool. A
// second, differently-salted index keeps the hostname uncorrelated with the
// distro choice. This is the fallback used when no credential persona is in
// play (or a persona defines no role-specific names); persona-driven honeypots
// should prefer hostnameForPersona so the name matches the accepted accounts.
func hostnameForSeed(seed string) string {
	return realisticHostnames[seededIndex("host:"+seed, len(realisticHostnames))]
}

// personaHostnames maps each credential persona to role-appropriate hostnames.
// When a honeypot derives its identity from a persona (Cowrie, the HiFi
// ssh-proxy), the per-instance hostname is drawn from THIS pool rather than the
// generic one, so the shell prompt, /etc/hostname and /etc/hosts match the kind
// of box the accepted credentials imply. Without this, the hostname and persona
// were chosen from independent salts, so a "voip-pbx" persona (asterisk/freepbx
// logins) could present "db-prod" - an internal contradiction a human attacker
// notices (a database server with only PBX accounts and no DB daemon). Keeping
// the two coherent is the "no persona/host mismatch" invariant credentials.go
// promises. Names avoid the known T-Pot/Cowrie defaults (srv01/svr04) and reuse
// across personas (vps-3, router) is intentional and realistic.
var personaHostnames = map[string][]string{
	"corp-ubuntu":      {"app-server-01", "appsrv-prod", "corp-app-02", "web-app-1"},
	"edge-router":      {"gw-01", "edge-fw", "border-gw", "router-01"},
	"web-hosting":      {"web01", "cpanel-host", "www-prod", "hosting-02"},
	"db-server":        {"db-prod", "db01", "postgres-01", "mysql-prod"},
	"dev-ci":           {"ci-runner-1", "jenkins-01", "build-node-2", "dev-ci"},
	"nas-storage":      {"nas-01", "storage-1", "fileshare", "synology"},
	"iot-camera":       {"ipcam-01", "camera-1", "ipc-front", "cam-lobby"},
	"mail-server":      {"mail", "mx1", "smtp-01", "mailsrv"},
	"k8s-node":         {"k8s-worker-1", "kube-node-3", "worker-02", "node-07"},
	"legacy-centos":    {"centos-app", "legacy-db", "vps-3", "oldbox-1"},
	"soho-router":      {"openwrt", "home-gw", "router", "mikrotik"},
	"voip-pbx":         {"pbx-01", "asterisk", "freepbx", "voip-gw"},
	"cctv-nvr":         {"nvr-01", "dvr-1", "cctv-rec", "nvr-back"},
	"cloud-default":    {"ip-10-0-1-23", "cloud-vm-1", "vps-3", "ec2-prod"},
	"abandoned-vps":    {"vps-3", "vm-01", "srv-app-04", "host-12"},
	"game-server":      {"ts3-server", "game-01", "mc-prod", "steam-1"},
	"jump-bastion":     {"bastion", "jump-01", "jumpbox", "bastion-prod"},
	"proxmox-host":     {"pve", "proxmox-01", "vmhost-1", "pve-node-2"},
	"gitlab-devops":    {"gitlab", "git-runner-1", "scm-prod", "ci-gitlab"},
	"monitoring-stack": {"grafana", "monitor-01", "zabbix-srv", "prometheus-1"},
	"raspberry-pi":     {"raspberrypi", "pi-01", "rpi-home", "octopi"},
	"ftp-fileserver":   {"ftp", "fileserver", "files-01", "ftp-prod"},
}

// hostnameForPersona returns a per-instance hostname coherent with the persona's
// role, drawn from that persona's own pool so the name matches the box the
// accepted credentials imply. If the persona defines no names (a new persona, or
// one deliberately left generic) it falls back to the generic pool. The same
// "host:"+seed salt as hostnameForSeed keeps the choice stable per instance.
func hostnameForPersona(t credentialTemplate, seed string) string {
	pool := personaHostnames[t.Name]
	if len(pool) == 0 {
		return hostnameForSeed(seed)
	}
	return pool[seededIndex("host:"+seed, len(pool))]
}

// cpuModel bundles the fields a realistic /proc/cpuinfo reports for one CPU
// type, kept internally consistent (vendor_id ↔ model name ↔ family/model/
// stepping ↔ flags). These are real, common cloud/server CPUs so the emulated
// box looks like an ordinary VPS/dedicated server rather than a honeypot.
type cpuModel struct {
	VendorID  string // vendor_id, e.g. "GenuineIntel" / "AuthenticAMD"
	ModelName string // "model name", e.g. "Intel(R) Xeon(R) ... @ 2.80GHz"
	Family    int    // cpu family
	Model     int    // model
	Stepping  int    // stepping
	Microcode string // microcode revision
	MHz       string // cpu MHz (string so we can keep the ".000" form)
	CacheKB   int    // cache size in KB ("cache size")
	Flags     string // the CPU flags line (per-vendor, KVM-guest typical)
}

// intelKVMFlags / amdKVMFlags are the CPU flag sets a typical KVM guest exposes
// for that vendor — long, real, and a strong realism signal (a too-short or
// vendor-mismatched flags line is a tell). Kept as constants so every Intel
// model shares Intel-consistent flags and likewise for AMD.
const intelKVMFlags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat avx512_vnni md_clear arch_capabilities"

const amdKVMFlags = "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl tsc_reliable nonstop_tsc cpuid extd_apicid pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy svm cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext perfctr_core ssbd ibrs ibpb stibp vmmcall fsgsbase tsc_adjust bmi1 avx2 smep bmi2 rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves clzero xsaveerptr arat npt nrip_save umip rdpid"

// cpuModels is a pool of realistic 64-bit server/cloud CPUs. The seed selects
// one per instance so two QPot deployments do not report an identical
// /proc/cpuinfo, while each block stays internally consistent. (The CPU *count*
// is fixed at 2 elsewhere to match Cowrie's hard-coded `nproc`/`free` builtins —
// see procCPUInfo — so only the model varies, not the core count.)
var cpuModels = []cpuModel{
	{VendorID: "GenuineIntel", ModelName: "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz", Family: 6, Model: 106, Stepping: 6, Microcode: "0xd0003d1", MHz: "2793.436", CacheKB: 49152, Flags: intelKVMFlags},
	{VendorID: "GenuineIntel", ModelName: "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", Family: 6, Model: 79, Stepping: 1, Microcode: "0xb000040", MHz: "2399.996", CacheKB: 35840, Flags: intelKVMFlags},
	{VendorID: "GenuineIntel", ModelName: "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz", Family: 6, Model: 85, Stepping: 7, Microcode: "0x5003604", MHz: "2999.998", CacheKB: 36608, Flags: intelKVMFlags},
	{VendorID: "GenuineIntel", ModelName: "Intel(R) Xeon(R) CPU E5-2650 v3 @ 2.30GHz", Family: 6, Model: 63, Stepping: 2, Microcode: "0x43", MHz: "2299.998", CacheKB: 25600, Flags: intelKVMFlags},
	{VendorID: "AuthenticAMD", ModelName: "AMD EPYC 7401P 24-Core Processor", Family: 23, Model: 1, Stepping: 2, Microcode: "0x8001250", MHz: "1996.250", CacheKB: 512, Flags: amdKVMFlags},
	{VendorID: "AuthenticAMD", ModelName: "AMD EPYC 7763 64-Core Processor", Family: 25, Model: 1, Stepping: 1, Microcode: "0xa001144", MHz: "2445.406", CacheKB: 512, Flags: amdKVMFlags},
	{VendorID: "AuthenticAMD", ModelName: "AMD EPYC 7302P 16-Core Processor", Family: 23, Model: 49, Stepping: 0, Microcode: "0x830104d", MHz: "2994.374", CacheKB: 512, Flags: amdKVMFlags},
}

// cpuModelForSeed returns a per-instance CPU model. A distinct salt keeps the
// CPU choice uncorrelated with the distro/hostname selection.
func cpuModelForSeed(seed string) cpuModel {
	return cpuModels[seededIndex("cpu:"+seed, len(cpuModels))]
}

// icsStationPrefixes are believable industrial device/station tag prefixes used
// to build a Conpot sensor_id that looks like a real PLC/RTU/SCADA asset rather
// than a honeypot. Real ICS assets carry tags like "PLC-01", "RTU-A", "S7-300".
var icsStationPrefixes = []string{
	"PLC", "RTU", "HMI", "S7-300", "S7-1200", "MTU", "IED", "DCS", "SCADA",
}

// conpotSensorIDForSeed builds a per-instance Conpot sensor_id that (a) does NOT
// contain "qpot"/"conpot"/"honeypot" - the stock value "qpot-conpot" literally
// announced both the platform and that it is a honeypot - and (b) is unique per
// deployment so two QPot instances do not share a SCADA-sensor signature. The
// result looks like a plausible industrial asset tag, e.g. "RTU-7a3f".
func conpotSensorIDForSeed(seed string) string {
	prefix := icsStationPrefixes[seededIndex("conpot-prefix:"+seed, len(icsStationPrefixes))]
	h := fnv.New32a()
	_, _ = h.Write([]byte("conpot-id:" + seed))
	return fmt.Sprintf("%s-%04x", prefix, h.Sum32()&0xffff)
}

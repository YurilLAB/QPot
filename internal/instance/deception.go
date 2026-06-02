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
	},
	{
		SSHVersion:        "OpenSSH_8.4p1 Debian-5+deb11u3",
		KernelVersion:     "5.10.0-27-amd64",
		KernelBuildString: "#1 SMP Debian 5.10.205-2 (2023-12-31)",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Debian GNU/Linux 11 (bullseye)",
	},
	{
		SSHVersion:        "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
		KernelVersion:     "5.15.0-91-generic",
		KernelBuildString: "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Ubuntu 22.04.3 LTS",
	},
	{
		SSHVersion:        "OpenSSH_9.2p1 Debian-2+deb12u3",
		KernelVersion:     "6.1.0-18-amd64",
		KernelBuildString: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Debian GNU/Linux 12 (bookworm)",
	},
	{
		SSHVersion:        "OpenSSH_7.4",
		KernelVersion:     "3.10.0-1160.105.1.el7.x86_64",
		KernelBuildString: "#1 SMP Thu Dec 7 15:39:45 UTC 2023",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "CentOS Linux 7 (Core)",
	},
	{
		SSHVersion:        "OpenSSH_9.6p1 Ubuntu-3ubuntu13.4",
		KernelVersion:     "6.8.0-31-generic",
		KernelBuildString: "#31-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 20 00:40:06 UTC 2024",
		HardwarePlatform:  "x86_64",
		OperatingSystem:   "GNU/Linux",
		OSPretty:          "Ubuntu 24.04 LTS",
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

// hostnameForSeed returns a per-instance hostname. A second, differently-salted
// index keeps the hostname uncorrelated with the distro choice.
func hostnameForSeed(seed string) string {
	return realisticHostnames[seededIndex("host:"+seed, len(realisticHostnames))]
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

package instance

// deploy.go describes the per-honeypot container runtime requirements.
//
// Each upstream honeypot image expects specific mount points, tmpfs, and ports
// — a single generic "/var/log/honeypot + /data" mount (the previous behavior)
// does not work for any of them, so honeypots either failed to start or wrote
// their logs to a path the collector never reads. These profiles are derived
// from T-Pot's reference compose files (vendored under docker/<name>/) and the
// cowrie/endlessh profiles are verified by actually running the images.

// deployVolume maps a host path (under {DataPath}/honeypots/<name>) to a path
// inside the honeypot container.
type deployVolume struct {
	HostSubdir    string
	ContainerPath string
	// File indicates HostSubdir is a single file (e.g. a generated config),
	// not a directory — so setup creates its parent dir and writes the file,
	// rather than creating a directory at that path.
	File bool
}

// honeypotDeploy is the deployment profile for one honeypot image.
type honeypotDeploy struct {
	// Tmpfs are raw docker-compose tmpfs entries the image needs (e.g. cowrie
	// requires a writable /tmp/cowrie for its pidfile and state).
	Tmpfs []string
	// Volumes are host-subdir -> container-path mounts. The "logs" subdir, when
	// present, is the directory the collector (Vector) reads
	// ({DataPath}/honeypots/<name>/logs), so each honeypot's log path must mount
	// from that subdir.
	Volumes []deployVolume
	// Ports are the TCP container ports to publish. Each is given a
	// deterministic host port via Config.AllocatePortFor. Empty means "use the
	// honeypot's configured HP.Port" (generic fallback).
	Ports []int
	// UDPPorts are the UDP container ports to publish (e.g. ddospot, conpot
	// SNMP/BACnet). Rendered with a /udp suffix.
	UDPPorts []int
	// ConfigSubdir is the host subdir into which generated config files
	// (cowrie.cfg, userdb.txt, ...) are written. It must be one of the Volumes'
	// HostSubdir so the files land inside a mounted directory.
	ConfigSubdir string
	// Env are image-specific environment variables the honeypot's entrypoint
	// requires (e.g. conpot's CONPOT_* args). Keys are sorted for deterministic
	// output.
	Env map[string]string
}

// NeedsNetBind reports whether the honeypot binds a privileged port (<1024)
// INSIDE the container. Such images (e.g. cowrie on 22/23) need
// CAP_NET_BIND_SERVICE in the capability bounding set; without it, exec of a
// binary carrying file capabilities fails with EPERM under cap_drop=ALL. This
// is keyed on the container-internal ports, not the host-facing HP.Port.
func (d honeypotDeploy) NeedsNetBind() bool {
	for _, p := range append(append([]int{}, d.Ports...), d.UDPPorts...) {
		if p > 0 && p < 1024 {
			return true
		}
	}
	return false
}

// deployProfileFor returns the deployment profile for a honeypot by name.
// Unknown honeypots get a generic profile (legacy behavior) so they are not
// broken further, but the verified images (cowrie, endlessh) get correct specs.
func deployProfileFor(name string) honeypotDeploy {
	switch name {
	case "cowrie":
		// Verified by running ghcr.io/telekom-security/cowrie:24.04.1: needs a
		// writable etc (cowrie auto-generates SSH host keys there and reads
		// cowrie.cfg/userdb.txt from it), tmpfs /tmp/cowrie for its pidfile, and
		// listens on 22 (SSH) + 23 (telnet).
		return honeypotDeploy{
			Tmpfs: []string{
				"/tmp/cowrie:uid=2000,gid=2000",
				"/tmp/cowrie/data:uid=2000,gid=2000",
			},
			Volumes: []deployVolume{
				{HostSubdir: "etc", ContainerPath: "/home/cowrie/cowrie/etc"},
				{HostSubdir: "logs", ContainerPath: "/home/cowrie/cowrie/log"},
				{HostSubdir: "dl", ContainerPath: "/home/cowrie/cowrie/dl"},
				// The image bakes cowrie.cfg in the working dir, which cowrie
				// reads LAST and thus takes precedence over etc/cowrie.cfg.
				// Mount our generated config there too so our settings (incl.
				// auth_class=UserDB, which enforces the credential persona) win.
				{HostSubdir: "etc/cowrie.cfg", ContainerPath: "/home/cowrie/cowrie/cowrie.cfg", File: true},
				// Persona-consistent fake-filesystem files, mounted over the
				// image's honeyfs so post-login recon (cat /etc/passwd, hostname,
				// cat /etc/os-release) matches the login persona and distro.
				{HostSubdir: "honeyfs/etc/passwd", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/passwd", File: true},
				{HostSubdir: "honeyfs/etc/group", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/group", File: true},
				{HostSubdir: "honeyfs/etc/hostname", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/hostname", File: true},
				{HostSubdir: "honeyfs/etc/os-release", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/os-release", File: true},
				{HostSubdir: "honeyfs/etc/issue", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/issue", File: true},
			},
			Ports:        []int{22, 23},
			ConfigSubdir: "etc",
		}
	case "endlessh":
		// Verified: endlessh redirects its log to /var/log/endlessh and listens
		// on 2222 inside the container (T-Pot maps host 22 -> 2222).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/endlessh"},
			},
			Ports: []int{2222},
		}
	case "redishoneypot":
		// Redis honeypot: single TCP port 6379, logs to /var/log/redishoneypot.
		// Derived from docker/redishoneypot/docker-compose.yml.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/redishoneypot"},
			},
			Ports: []int{6379},
		}
	case "adbhoney":
		// Android Debug Bridge honeypot: port 5555, logs to /opt/adbhoney/log.
		// Derived from docker/adbhoney/docker-compose.yml.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/adbhoney/log"},
			},
			Ports: []int{5555},
		}

	// The profiles below are derived from T-Pot's tested reference composes
	// (docker/<name>/docker-compose.yml): the in-container log path, the ports
	// each honeypot listens on, and any required tmpfs.
	case "dionaea":
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/dionaea/var/log"}},
			Ports:    []int{20, 21, 42, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 5060, 5061, 27017},
			UDPPorts: []int{69, 5060},
		}
	case "conpot":
		// conpot's CMD references CONPOT_* env vars; without them the entrypoint
		// passes empty args (--mibcache <empty>) and crashes. The "default"
		// template emulates a Siemens S7-200 over the ICS ports below.
		return honeypotDeploy{
			Tmpfs:   []string{"/tmp/conpot:uid=2000,gid=2000"},
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/conpot"}},
			Ports:   []int{21, 80, 102, 1025, 2404, 10001, 44818, 50100},
			UDPPorts: []int{69, 161, 623, 47808},
			Env: map[string]string{
				"CONPOT_TMP":      "/tmp/conpot",
				"CONPOT_TEMPLATE":  "default",
				"CONPOT_CONFIG":    "/etc/conpot/conpot.cfg",
				"CONPOT_LOG":       "/var/log/conpot/conpot.log",
				"CONPOT_JSON_LOG":  "/var/log/conpot/conpot.json",
			},
		}
	case "heralding":
		return honeypotDeploy{
			Tmpfs:   []string{"/tmp/heralding:uid=2000,gid=2000"},
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/heralding"}},
			Ports:   []int{21, 22, 23, 25, 80, 110, 143, 443, 465, 993, 995, 1080, 3306, 3389, 5432, 5900},
		}
	case "mailoney":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/mailoney/logs"}},
			Ports:   []int{25},
		}
	case "ddospot":
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/ddospot/ddospot/logs"}},
			UDPPorts: []int{19, 53, 123, 161, 1900},
		}
	case "ciscoasa":
		return honeypotDeploy{
			Tmpfs:    []string{"/tmp/ciscoasa:uid=2000,gid=2000"},
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/ciscoasa"}},
			Ports:    []int{8443},
			UDPPorts: []int{5000},
		}
	case "citrixhoneypot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/citrixhoneypot/logs"}},
			Ports:   []int{443},
		}
	case "elasticpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/elasticpot/log"}},
			Ports:   []int{9200},
		}
	case "ipphoney":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/ipphoney/log"}},
			Ports:   []int{631},
		}
	case "medpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/medpot"}},
			Ports:   []int{2575},
		}
	case "dicompot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/dicompot"}},
			Ports:   []int{11112},
		}
	case "honeyaml":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/honeyaml/log"}},
			Ports:   []int{8080},
		}
	case "tanner":
		// Web honeypot. NOTE: upstream Tanner is a multi-service stack
		// (snare + tanner + redis + phpox); this single-container profile is
		// best-effort and the full stack is not yet orchestrated by QPot.
		return honeypotDeploy{
			Tmpfs:   []string{"/tmp/tanner:uid=2000,gid=2000"},
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/tanner"}},
			Ports:   []int{80},
		}

	// Newer / 2024-2026 honeypots (vendored under docker/). Derived from their
	// reference composes.
	case "beelzebub":
		// LLM-backed SSH/HTTP/TCP. Runs without an LLM provider (static replies)
		// but is most convincing with Ollama configured.
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/beelzebub/configurations/log"}},
			Ports:   []int{22, 80, 2222, 3306, 8080},
		}
	case "galah":
		// LLM-backed dynamic web honeypot.
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/galah/log"}},
			Ports:   []int{80, 443, 8080, 8443},
		}
	case "go-pot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/go-pot/log"}},
			Ports:   []int{8080},
		}
	case "h0neytr4p":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/h0neytr4p/log"}},
			Ports:   []int{80, 443},
		}
	case "hellpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/hellpot"}},
			Ports:   []int{8080},
		}
	case "log4pot":
		return honeypotDeploy{
			Tmpfs:   []string{"/tmp:uid=2000,gid=2000"},
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/log4pot/log"}},
			Ports:   []int{8080},
		}
	case "miniprint":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/miniprint/log"}},
			Ports:   []int{9100},
		}
	case "sentrypeer":
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/sentrypeer"}},
			UDPPorts: []int{4222, 5060},
		}
	case "wordpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/wordpot/logs"}},
			Ports:   []int{80},
		}

	default:
		// Generic fallback for honeypots without a verified profile.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/honeypot"},
				{HostSubdir: "data", ContainerPath: "/data"},
			},
		}
	}
}

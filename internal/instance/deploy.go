package instance

// deploy.go describes the per-honeypot container runtime requirements.
//
// Each upstream honeypot image expects specific mount points, tmpfs, and ports
// — a single generic "/var/log/honeypot + /data" mount (the previous behavior)
// does not work for any of them, so honeypots either failed to start or wrote
// their logs to a path the collector never reads. These profiles are derived
// from T-Pot's reference compose files (vendored under docker/<name>/) and the
// cowrie/endlessh profiles are verified by actually running the images.

import (
	"fmt"
	"slices"
	"strings"
)

// deployVolume maps a host path (under {DataPath}/honeypots/<name>) to a path
// inside the honeypot container.
type deployVolume struct {
	HostSubdir    string
	ContainerPath string
	// File indicates HostSubdir is a single file (e.g. a generated config),
	// not a directory — so setup creates its parent dir and writes the file,
	// rather than creating a directory at that path.
	File bool
	// ReadOnly mounts it read-only. The host writes it; the container must
	// not be able to change it.
	ReadOnly bool
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
	// ExtraCaps are Linux capabilities to ADD back to the cap_drop=ALL bounding
	// set, beyond the default SETUID/SETGID (+ NET_BIND_SERVICE for privileged
	// ports). Needed when an image's entrypoint binary carries FILE capabilities:
	// the kernel refuses to execve a file whose permitted file-caps are not in the
	// process bounding set (EPERM), even if the program never uses them. E.g.
	// log4pot's /usr/bin/python3 has cap_net_bind_service=ep but binds only 8080,
	// so without NET_BIND_SERVICE in the bounding set the interpreter cannot start.
	ExtraCaps []string
	// Command overrides the image's default CMD. Set only when the image's own
	// entrypoint would defeat QPot's generated config (e.g. cowrie:24.04.1 ships
	// a start-cowrie-persona launcher that copies a RANDOM built-in persona's
	// cowrie.cfg into a runtime dir and runs from there, overriding the config
	// QPot mounts - so QPot's credential personas, hostname and SSH-algorithm
	// settings never take effect). Empty means "use the image default".
	Command []string
	// WorkingDir overrides the container working directory. Paired with Command
	// when QPot must run the service from a specific CWD so its relative config
	// paths (etc/cowrie.cfg, etc/userdb.txt, honeyfs/) resolve to QPot's mounts.
	WorkingDir string
	// NoShell marks images without /bin/sh (static Go binaries on scratch /
	// distroless). The /proc/net healthcheck runs through a shell, so it can
	// never succeed there; such honeypots get no in-container healthcheck and
	// `qpot setup`/`doctor` probe their published TCP ports from the host.
	NoShell bool
	// HealthPorts are the container ports the healthcheck probes when they
	// differ from the published ones (e.g. tanner's server, whose web front end
	// is the snare companion).
	HealthPorts []int
	// Internal means the service publishes no host port itself (tanner: the
	// attacker-facing port is published by its snare companion).
	Internal bool
	// RunAsUID is the image's non-root user ("uid:gid"). Mounted directories
	// listed in OwnedSubdirs are handed to it before start, for images that
	// chmod their own log dir (only the owner may; capabilities do not apply
	// to a non-root process).
	RunAsUID     string
	OwnedSubdirs []string
	// LLMEnv maps honeypot custom_config keys to the container environment
	// variables of an LLM-backed honeypot; LLMRequired are the keys that must
	// be set (the image refuses to start without a provider).
	LLMEnv      map[string]string
	LLMRequired []string
	// LLMValues restricts settings to the values the image accepts.
	LLMValues map[string][]string
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
				{HostSubdir: "honeyfs/etc/hosts", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/hosts", File: true},
				{HostSubdir: "honeyfs/etc/os-release", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/os-release", File: true},
				{HostSubdir: "honeyfs/etc/issue", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/issue", File: true},
				// Per-distro /etc/motd: overrides cowrie's stock Debian-boilerplate
				// motd, which is a global fingerprint and a tell on a non-Debian
				// profile.
				{HostSubdir: "honeyfs/etc/motd", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/motd", File: true},
				// A /proc/version consistent with the advertised kernel, and an
				// /etc/timezone matching the shell clock. (Both paths exist in
				// Cowrie's fake fs, so overriding them is actually served.)
				{HostSubdir: "honeyfs/proc/version", ContainerPath: "/home/cowrie/cowrie/honeyfs/proc/version", File: true},
				{HostSubdir: "honeyfs/etc/timezone", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/timezone", File: true},
				// A per-instance, realistic /proc/cpuinfo (2 CPUs). Overrides the
				// stock globally-identical cpuinfo, which is a cross-deployment
				// fingerprint.
				{HostSubdir: "honeyfs/proc/cpuinfo", ContainerPath: "/home/cowrie/cowrie/honeyfs/proc/cpuinfo", File: true},
				// Additional recon files the stock honeyfs leaves empty or wrong, so
				// `cat` on a box that obviously has DNS / a running sshd / a mounted
				// root / RAM does not betray the honeypot. All exist in cowrie's fake
				// fs (verified against fs.pickle), so these overrides are actually
				// served. See honeyfs.go for the per-file rationale.
				{HostSubdir: "honeyfs/usr/lib/os-release", ContainerPath: "/home/cowrie/cowrie/honeyfs/usr/lib/os-release", File: true},
				{HostSubdir: "honeyfs/etc/debian_version", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/debian_version", File: true},
				{HostSubdir: "honeyfs/etc/resolv.conf", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/resolv.conf", File: true},
				{HostSubdir: "honeyfs/etc/ssh/sshd_config", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/ssh/sshd_config", File: true},
				{HostSubdir: "honeyfs/etc/fstab", ContainerPath: "/home/cowrie/cowrie/honeyfs/etc/fstab", File: true},
				{HostSubdir: "honeyfs/proc/meminfo", ContainerPath: "/home/cowrie/cowrie/honeyfs/proc/meminfo", File: true},
				{HostSubdir: "honeyfs/proc/swaps", ContainerPath: "/home/cowrie/cowrie/honeyfs/proc/swaps", File: true},
				{HostSubdir: "honeyfs/proc/mounts", ContainerPath: "/home/cowrie/cowrie/honeyfs/proc/mounts", File: true},
				// Bind the SAME generated meminfo over the REAL /proc/meminfo too:
				// cowrie's `free` builtin does open("/proc/meminfo") against the
				// container's real proc (not honeyfs), so without this it leaks the
				// Docker host's true RAM and disagrees with `cat /proc/meminfo`. With
				// it, `free` and `cat` report the same believable per-instance size.
				{HostSubdir: "honeyfs/proc/meminfo", ContainerPath: "/proc/meminfo", File: true},
				// The generated fake-fs patch script (cowriefs.go), run at startup
				// before twistd to add the persona home directories.
				{HostSubdir: "qpot_patch_fs.py", ContainerPath: "/home/cowrie/cowrie/qpot_patch_fs.py", File: true},
			},
			Ports:        []int{22, 23},
			ConfigSubdir: "etc",
			// Bypass the image's start-cowrie-persona launcher and run cowrie
			// directly from /home/cowrie/cowrie. That launcher picks a RANDOM
			// built-in persona, copies its cowrie.cfg into /tmp/cowrie/runtime and
			// execs twistd from there - so cowrie reads the persona's config
			// (auth_class=AuthRandom, the image's identity) and QPot's mounted
			// cowrie.cfg/userdb.txt/honeyfs are silently ignored. Running twistd
			// ourselves with WorkingDir=/home/cowrie/cowrie makes cowrie read
			// etc/cowrie.cfg + etc/userdb.txt + honeyfs from QPot's mounts, so the
			// curated credential persona, coherent hostname and SSH-algorithm
			// normalization actually take effect. PYTHONPATH is baked into the image
			// env. We first run qpot_patch_fs.py, which writes the persona-patched
			// fake filesystem to /tmp/cowrie/fs.pickle (the path cowrie.cfg's
			// `filesystem` points at), then exec twistd. The script always produces
			// that file - the unchanged base pickle on any error - so cowrie's shell
			// never starts without a valid filesystem.
			Command: []string{"/bin/sh", "-c",
				"python3 /home/cowrie/cowrie/qpot_patch_fs.py 2>>/tmp/cowrie/patch.log; " +
					"exec /usr/bin/twistd --nodaemon --pidfile /tmp/cowrie/cowrie.pid cowrie"},
			WorkingDir: "/home/cowrie/cowrie",
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
	case "ssh-proxy":
		// HiFi broker (cmd/qpot-sshproxy): a transparent L4 splice listening on
		// 2222 (>1024, so no NET_BIND_SERVICE needed) and writing its NDJSON
		// session log under logs/, which the collector ingests. The broker needs
		// no generated config (it is env-configured) and no other mounts; the
		// real-OpenSSH backends are rendered as companion services (sshproxy.go).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/ssh-proxy"},
				// Backend recreation counters, written by the host recycler
				// (instance.BackendRecycler) and read by the broker's
				// proxy.GenerationGate.
				{HostSubdir: "generations", ContainerPath: sshProxyGenerationsPath, ReadOnly: true},
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
			Tmpfs:    []string{"/tmp/conpot:uid=2000,gid=2000"},
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/conpot"}},
			Ports:    []int{21, 80, 102, 1025, 2404, 10001, 44818, 50100},
			UDPPorts: []int{69, 161, 623, 47808},
			Env: map[string]string{
				"CONPOT_TMP":      "/tmp/conpot",
				"CONPOT_TEMPLATE": "default",
				"CONPOT_CONFIG":   "/etc/conpot/conpot.cfg",
				"CONPOT_LOG":      "/var/log/conpot/conpot.log",
				"CONPOT_JSON_LOG": "/var/log/conpot/conpot.json",
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
		// ddospot v2 (T-Pot 24.04.2) is a static Go rewrite: CHARGEN 19/udp,
		// DNS 53/udp+tcp, NTP 123/udp, SSDP 1900/udp (SNMP 161 is gone, as in
		// T-Pot). It logs JSON lines to DDOSPOT_LOG_DIR (default
		// /var/log/ddospot); the v1 mount at /opt/ddospot/ddospot/logs - still
		// in T-Pot's own compose - leaves it writing to the read-only root, so
		// every log line is lost ("log write errors").
		return honeypotDeploy{
			Volumes:  []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/ddospot"}},
			Env:      map[string]string{"DDOSPOT_LOG_DIR": "/var/log/ddospot"},
			Ports:    []int{53},
			UDPPorts: []int{19, 53, 123, 1900},
			NoShell:  true,
		}
	case "ciscoasa":
		// 24.04.2 is a static Go rewrite (asapot) that keeps its device
		// identity (identity.json) and captured payloads in /var/lib/ciscoasa;
		// under a read-only root it exits with "mkdir /var/lib: read-only file
		// system" - also with T-Pot's own compose. A persistent state dir keeps
		// the identity stable across restarts.
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/ciscoasa:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/ciscoasa"},
				{HostSubdir: "state", ContainerPath: "/var/lib/ciscoasa"},
			},
			Ports:    []int{8443},
			UDPPorts: []int{5000},
			NoShell:  true,
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
			NoShell: true,
		}
	case "dicompot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/dicompot"}},
			Ports:   []int{11112},
			NoShell: true,
		}
	case "honeyaml":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/honeyaml/log"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "tanner":
		// Web application honeypot, run as T-Pot runs it: this service is the
		// tanner analysis server (internal, :8090); the attacker-facing web
		// front end is the snare companion, which publishes tanner's port, and
		// tanner_api / tanner_phpox / tanner_redis complete the stack on the
		// egress-blocked tanner_backend network (see tannerStack in compose.go).
		// T-Pot did not rebuild these images for 24.04.2 (tpotPinned).
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/tanner:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/tanner"},
				{HostSubdir: "files", ContainerPath: "/opt/tanner/files"},
			},
			Ports:       []int{80}, // allocated for tanner, published by snare
			Internal:    true,
			HealthPorts: []int{8090},
		}
	case "beelzebub":
		// LLM-backed SSH/HTTP/TCP. Its SSH, HTTP and PostgreSQL services fail
		// validation without an LLM, so custom_config must set llm_provider
		// (ollama or openai), llm_model and, for Ollama or an
		// OpenAI-compatible server, llm_host; `qpot honeypot enable` checks.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/beelzebub/configurations/log"},
				{HostSubdir: "key", ContainerPath: "/opt/beelzebub/configurations/key"},
			},
			Ports:   []int{22, 80, 2222, 3306, 8080},
			NoShell: true,
			LLMEnv: map[string]string{
				"llm_provider": "LLM_PROVIDER",
				"llm_model":    "LLM_MODEL",
				"llm_host":     "LLM_HOST",
			},
			LLMRequired: []string{"llm_provider", "llm_model"},
			LLMValues:   map[string][]string{"llm_provider": {"ollama", "openai"}},
		}
	case "galah":
		// LLM-backed dynamic web honeypot; exits without a provider, so
		// custom_config must set llm_provider (and llm_server_url + llm_model
		// for Ollama, or llm_api_key for a hosted model).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/galah/log"},
				{HostSubdir: "cache", ContainerPath: "/opt/galah/config/cache"},
			},
			Ports: []int{80, 443, 8080, 8443},
			LLMEnv: map[string]string{
				"llm_provider":       "LLM_PROVIDER",
				"llm_server_url":     "LLM_SERVER_URL",
				"llm_model":          "LLM_MODEL",
				"llm_temperature":    "LLM_TEMPERATURE",
				"llm_api_key":        "LLM_API_KEY",
				"llm_cloud_location": "LLM_CLOUD_LOCATION",
				"llm_cloud_project":  "LLM_CLOUD_PROJECT",
			},
			LLMRequired: []string{"llm_provider", "llm_model"},
		}
	case "go-pot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/opt/go-pot/log"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "h0neytr4p":
		// Needs a writable payloads dir; the read-only root otherwise blocks
		// its `mkdir /data`. It runs as 2000:2000 and chmods its log dir at
		// start, which only the owner may do, so QPot hands that dir to it
		// (T-Pot's tpotinit does the same for its data dirs).
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/opt/h0neytr4p/log"},
				{HostSubdir: "payloads", ContainerPath: "/data/h0neytr4p/payloads"},
			},
			Ports:        []int{80, 443},
			NoShell:      true,
			RunAsUID:     "2000:2000",
			OwnedSubdirs: []string{"logs", "payloads"},
		}
	case "hellpot":
		return honeypotDeploy{
			Volumes: []deployVolume{{HostSubdir: "logs", ContainerPath: "/var/log/hellpot"}},
			Ports:   []int{8080},
			NoShell: true,
		}
	case "log4pot":
		// log4pot writes captured payloads to /var/log/log4pot/payloads via
		// os.mkdir at startup; with a read-only root that directory must be a
		// writable mount or the server crashes before binding. Mirror T-Pot's
		// reference compose (log + payloads).
		return honeypotDeploy{
			Tmpfs: []string{"/tmp:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/log4pot/log"},
				{HostSubdir: "payloads", ContainerPath: "/var/log/log4pot/payloads"},
			},
			Ports: []int{8080},
			// The image's /usr/bin/python3 carries cap_net_bind_service=ep; under
			// cap_drop=ALL the kernel won't exec it ("operation not permitted")
			// unless the cap is in the bounding set, even though log4pot binds 8080.
			ExtraCaps: []string{"NET_BIND_SERVICE"},
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

// MissingLLMConfig returns the custom_config keys an LLM-backed honeypot
// still needs (nil when it needs none or all are set).
func MissingLLMConfig(name string, custom map[string]string) []string {
	var missing []string
	for _, k := range deployProfileFor(name).LLMRequired {
		if strings.TrimSpace(custom[k]) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

// CheckLLMSetting reports whether value is accepted for the honeypot's LLM
// setting key (an empty value, which removes the setting, always is).
func CheckLLMSetting(name, key, value string) error {
	allowed := deployProfileFor(name).LLMValues[key]
	if value == "" || len(allowed) == 0 || slices.Contains(allowed, value) {
		return nil
	}
	return fmt.Errorf("%s: %s must be one of: %s", name, key, strings.Join(allowed, ", "))
}

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
	_ "embed"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/qpot/qpot/internal/config"
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
	// Content is what setup writes to a File volume before start.
	Content []byte
}

// heraldingConfig is the /etc/heralding/heralding.yml of
// ghcr.io/telekom-security/heralding at TPotVersion with the values that
// override heralding's persona cleared: the banners and FTP system type of
// ftp, pop3(s), imap(s), ssh and smtp(s), and the certificate country. The
// image's file kept stock greetings that every install shared and that
// contradicted the persona on the other ports (an RHEL persona answering SSH
// as OpenSSH 6.6.1p1 on Ubuntu 14.04, FTP as "Microsoft FTP Server" and SMTP
// as Exchange). Empty values come from the persona. The rest of the file is
// the image's; compare it again when TPotVersion changes.
//
//go:embed honeypotfiles/heralding.yml
var heraldingConfig []byte

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
	// Settings are the other custom_config keys the honeypot reads (set with
	// `qpot honeypot set`), e.g. cowrie's persona or ssh-proxy's backends.
	Settings []string
	// Values restricts settings to the values the image accepts.
	Values map[string][]string
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

// deployProfile returns the deployment profile of a honeypot in this instance:
// deployProfileFor plus the parts that depend on the configuration. Conpot
// runs the template conpotTemplate picks and publishes exactly the ports that
// template listens on, no more: a published port with nothing behind it
// accepts the connection and drops it, which no real device does.
func deployProfile(cfg *config.Config, name string) honeypotDeploy {
	d := deployProfileFor(name)
	if name == "conpot" && cfg != nil {
		t := conpotTemplate(cfg)
		d.Ports = slices.Clone(t.TCP)
		d.UDPPorts = slices.Clone(t.UDP)
		d.Env = maps.Clone(d.Env)
		d.Env["CONPOT_TEMPLATE"] = t.ID
	}
	return d
}

// deployProfileFor returns the configuration-independent deployment profile
// for a honeypot by name; use deployProfile for what an instance runs.
// Unknown honeypots get a generic profile (legacy behavior) so they are not
// broken further, but the verified images (cowrie, endlessh) get correct specs.
func deployProfileFor(name string) honeypotDeploy {
	switch name {
	case "cowrie":
		// The image's own launcher (start-cowrie-persona) renders Cowrie as the
		// persona in COWRIE_PERSONA (see deception.go and the compose template)
		// into the tmpfs /tmp/cowrie/runtime and runs twistd from there. It
		// needs: a writable etc (the persona's SSH host keys in etc/<persona>/
		// and persona-state.json, which keeps the drawn identity across
		// restarts), the log and download dirs, and tmpfs /tmp/cowrie plus
		// /tmp/cowrie/data for the rendered runtime, pidfile and state. It
		// listens on 22 (SSH) and 23 (telnet). Verified by running
		// ghcr.io/telekom-security/cowrie:24.04.2 this way and logging in.
		return honeypotDeploy{
			Tmpfs: []string{
				"/tmp/cowrie:uid=2000,gid=2000",
				"/tmp/cowrie/data:uid=2000,gid=2000",
			},
			Volumes: []deployVolume{
				{HostSubdir: "etc", ContainerPath: "/home/cowrie/cowrie/etc"},
				{HostSubdir: "logs", ContainerPath: "/home/cowrie/cowrie/log"},
				{HostSubdir: "dl", ContainerPath: "/home/cowrie/cowrie/dl"},
			},
			Ports:    []int{22, 23},
			Settings: []string{"persona", "persona_rotation"},
			Values:   map[string][]string{"persona": CowriePersonaIDs()},
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
			Ports:    []int{2222},
			Settings: []string{"backends"},
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
		// The image's CMD (tpot_templates.py render "$CONPOT_TEMPLATE") renders
		// the template into CONPOT_TMP with the device identity it keeps in
		// /var/lib/conpot, then starts conpot with the other CONPOT_* paths.
		// Without a writable /var/lib/conpot it draws a new identity (address,
		// MAC, serials) on every start. The template and its ports depend on
		// the instance: deployProfile fills them in (see conpotTemplate).
		// Verified by running ghcr.io/telekom-security/conpot:24.04.2 this way
		// with each template.
		return honeypotDeploy{
			Tmpfs: []string{"/tmp/conpot:uid=2000,gid=2000"},
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/conpot"},
				{HostSubdir: "state", ContainerPath: "/var/lib/conpot"},
			},
			Env: map[string]string{
				"CONPOT_TMP":      "/tmp/conpot",
				"CONPOT_CONFIG":   "/etc/conpot/conpot.cfg",
				"CONPOT_LOG":      "/var/log/conpot/conpot.log",
				"CONPOT_JSON_LOG": "/var/log/conpot/conpot.json",
			},
			Settings: []string{"template"},
			Values:   map[string][]string{"template": ConpotTemplateIDs()},
		}
	case "heralding":
		// Heralding draws a persona (host name, OS, banners, certificate
		// subject) on first start and keeps it, with the TLS certificates and
		// SSH host keys made for it, in its working directory /tmp/heralding.
		// On a tmpfs, as T-Pot mounts it, every restart turned the box into a
		// different machine with new host keys, so the directory is a
		// persistent volume. The config is QPot's (see heraldingConfig).
		// Verified by running ghcr.io/telekom-security/heralding:24.04.2 this
		// way: same persona, banners and certificate after a restart.
		return honeypotDeploy{
			Volumes: []deployVolume{
				{HostSubdir: "logs", ContainerPath: "/var/log/heralding"},
				{HostSubdir: "state", ContainerPath: "/tmp/heralding"},
				{HostSubdir: "heralding.yml", ContainerPath: "/etc/heralding/heralding.yml", File: true, ReadOnly: true, Content: heraldingConfig},
			},
			Ports: []int{21, 22, 23, 25, 80, 110, 143, 443, 465, 993, 995, 1080, 3306, 3389, 5432, 5900},
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
			Values:      map[string][]string{"llm_provider": {"ollama", "openai"}},
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

// CheckSetting reports whether value is accepted for the honeypot's setting
// key (an empty value, which removes the setting, always is).
func CheckSetting(name, key, value string) error {
	if value == "" {
		return nil
	}
	if name == "cowrie" && key == "persona_rotation" {
		if _, ok := parsePersonaRotation(value); !ok {
			return fmt.Errorf("%s: %s must be a number of days from 0 to %d", name, key, cowriePersonaMaxRotation)
		}
		return nil
	}
	allowed := deployProfileFor(name).Values[key]
	if len(allowed) == 0 || slices.Contains(allowed, value) {
		return nil
	}
	return fmt.Errorf("%s: %s must be one of: %s", name, key, strings.Join(allowed, ", "))
}

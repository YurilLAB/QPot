// Package instance handles Docker Compose generation
package instance

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// portKey identifies a (honeypot, container port) pair in the host-port map.
func portKey(honeypot string, port int) string {
	return honeypot + "\x00" + strconv.Itoa(port)
}

// vrlStringLiteral renders s as a safe double-quoted Vector Remap Language
// string literal. The stealth "blocked probe" strings are operator-supplied and
// were previously interpolated raw into a VRL contains() call inside a YAML
// block scalar - a probe containing a double quote, backslash or newline would
// break the whole Vector config (silently killing the log pipeline) or inject
// VRL. Strip control characters (newlines would also break the block-scalar
// line) and escape backslash and double-quote.
func vrlStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		// Drop C0 controls (incl. CR/LF/TAB), DEL, and C1 controls (0x80-0x9f).
		// YAML rejects these inside the block scalar that holds the VRL filter.
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			continue
		}
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// buildHostPortMap assigns a unique host port to every (honeypot, container
// port) pair across all enabled honeypots. config.AllocatePortFor alone is a
// pure hash, so with the ~100 port mappings a full honeypot set produces, two
// pairs eventually hash to the same host port and `docker compose up` then
// fails to bind it. Here we resolve collisions deterministically: honeypots are
// processed in sorted order, each port starts from its AllocatePortFor hash, and
// a taken port is linearly probed upward (wrapping in range) until free. The
// instance's infra ports (database) are reserved first so honeypots avoid them.
func (g *ComposeGenerator) buildHostPortMap() map[string]int {
	// Same window as config.AllocatePortFor: a width kept below the Linux
	// ephemeral range so published ports never race the kernel's dynamic
	// allocator (see config.HostPortSpread).
	const rangeSize = config.HostPortSpread
	base := g.Config.Ports.BasePort
	if base < 1024 {
		base = 10000
	}

	used := map[int]bool{}
	for p := range g.ReservedPorts {
		used[p] = true
	}
	if g.Config.Ports.AutoAllocate {
		for _, infra := range []int{9000, 8123, 5432} {
			used[g.Config.AllocatePort(infra)] = true
		}
	}

	names := make([]string, 0, len(g.Config.Honeypots))
	for name, hp := range g.Config.Honeypots {
		if hp.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	assign := make(map[string]int)
	for _, name := range names {
		d := deployProfileFor(name)
		ports := append(append([]int{}, d.Ports...), d.UDPPorts...)
		if len(ports) == 0 {
			ports = []int{g.Config.Honeypots[name].Port}
		}
		for _, p := range ports {
			key := portKey(name, p)
			if _, ok := assign[key]; ok {
				continue // TCP+UDP on the same number share one host port (fine)
			}
			cand := g.Config.AllocatePortFor(name, p)
			if !g.Config.Ports.AutoAllocate {
				assign[key] = cand // fixed mapping; caller opted out of allocation
				continue
			}
			for used[cand] {
				cand++
				if cand >= base+rangeSize {
					cand = base
				}
			}
			used[cand] = true
			assign[key] = cand
		}
	}
	return assign
}

// ComposeGenerator generates Docker Compose files
type ComposeGenerator struct {
	Config  *config.Config
	Sandbox *security.Sandbox
	// ReservedPorts / ReservedSubnets are host ports and subnets other
	// instances already use (see siblingReservations); allocation skips them.
	ReservedPorts   map[int]bool
	ReservedSubnets map[string]bool
	// ReservedNets are subnets of other docker networks on the host (any
	// size); no allocated subnet may overlap them.
	ReservedNets []*net.IPNet
}

// bridgeName builds the Linux bridge interface name for a honeypot network.
// Linux interface names are capped at 15 chars (IFNAMSIZ), so the name is a
// "br-" prefix, a readable (possibly truncated) honeypot prefix, and a 4-hex
// suffix hashed from the (instance, honeypot) pair.
//
// The instance name MUST be part of the hash: the bridge interface name is a
// host-global Linux resource, so two QPot instances that both enable the same
// honeypot (e.g. instance "a" and instance "b" both running cowrie) would
// otherwise both ask Docker for "br-cowrie" and the second `qpot up` fails with
// "networks have same bridge name". Hashing the pair keeps the name unique per
// instance while staying within IFNAMSIZ. (subnetForNetwork already scopes the
// /24 by instance the same way.)
func bridgeName(instanceName, honeypot string) string {
	const max = 15
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s:%s", instanceName, honeypot)
	suffix := fmt.Sprintf("%04x", h.Sum32()&0xffff)
	prefixLen := max - len("br-") - len(suffix) // 8 chars for the honeypot
	hp := honeypot
	if len(hp) > prefixLen {
		hp = hp[:prefixLen]
	}
	return fmt.Sprintf("br-%s%s", hp, suffix)
}

// macForSeed derives a stable, locally-administered unicast MAC address for a
// honeypot container from the (instance, honeypot) pair. The first octet is
// fixed to 0x02 (bit 1 = locally administered, bit 0 = unicast) so it is a
// valid, non-OUI address that does not collide with a real vendor prefix, and
// the remaining five octets come from a hash so each (instance, honeypot) gets
// a distinct but deterministic MAC. Used only when NetworkIsolation.RandomizeMAC
// is set.
func macForSeed(instanceName, honeypot string) string {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "mac:%s:%s", instanceName, honeypot)
	v := h.Sum64()
	return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x",
		byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// subnetForNetwork computes a stable /24 subnet for a Docker bridge network
// given an (instanceName, networkName) pair. The result always falls in the
// 172.20.x.0/24 .. 172.31.x.0/24 range (RFC 1918). This is only the starting
// point; buildSubnetMap resolves any collisions deterministically.
func subnetForNetwork(instanceName, networkName string) string {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s:%s", instanceName, networkName)
	v := h.Sum32()
	x := 20 + int((v>>8)%12) // 20–31
	y := int(v % 256)        // 0–255
	return fmt.Sprintf("172.%d.%d.0/24", x, y)
}

// nextSubnet returns the next /24 after the given 172.x.y.0/24, advancing y then
// x and wrapping within the 172.20-31 range. Used to probe past a collision.
func nextSubnet(s string) string {
	var x, y int
	if _, err := fmt.Sscanf(s, "172.%d.%d.0/24", &x, &y); err != nil {
		return "172.20.0.0/24"
	}
	y++
	if y > 255 {
		y = 0
		x++
		if x > 31 {
			x = 20
		}
	}
	return fmt.Sprintf("172.%d.%d.0/24", x, y)
}

// buildSubnetMap assigns a unique /24 to every enabled honeypot network.
// subnetForNetwork alone is a pure hash over ~3072 possible /24s, so a handful
// of honeypots eventually collide and `docker compose up` fails with "Pool
// overlaps with other one". Resolve deterministically: process honeypots in
// sorted order, start at the hashed subnet, and probe to the next free /24.
func (g *ComposeGenerator) buildSubnetMap() map[string]string {
	names := make([]string, 0, len(g.Config.Honeypots)+3)
	for name, hp := range g.Config.Honeypots {
		if hp.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	// QPot's own networks are allocated too (after the honeypots, so adding
	// them did not move any existing honeypot subnet).
	names = append(names, "qpot_internal", "qpot_dbhost")
	if sshProxyEnabled(g.Config) {
		names = append(names, "ssh-proxy_backend")
	}

	used := map[string]bool{}
	for s := range g.ReservedSubnets {
		used[s] = true
	}
	taken := func(sub string) bool {
		if used[sub] {
			return true
		}
		_, cand, err := net.ParseCIDR(sub)
		if err != nil {
			return true
		}
		for _, n := range g.ReservedNets {
			if n.Contains(cand.IP) || cand.Contains(n.IP) {
				return true
			}
		}
		return false
	}
	assign := make(map[string]string)
	for _, name := range names {
		sub := subnetForNetwork(g.Config.InstanceName, name)
		for tries := 0; taken(sub) && tries < 12*256; tries++ {
			sub = nextSubnet(sub)
		}
		used[sub] = true
		assign[name] = sub
	}
	return assign
}

// listenHealthCheck builds the CMD-SHELL test that verifies a honeypot is
// actually listening on at least one of its expected INTERNAL ports.
//
// It reads /proc/net/tcp{,6} (or /proc/net/udp{,6} for UDP-only honeypots)
// directly rather than shelling out to netstat/ss. The previous check
// (`netstat -tln | grep ':PORT' || ss -tln | grep ':PORT'`) had two fatal flaws
// that left every affected container perpetually "unhealthy" - so QPot's startup
// verifier reported the honeypot as "did not start" even though it was serving:
//
//  1. It probed .HP.Port (the host/config port), but several honeypots listen on
//     a DIFFERENT internal port - cowrie on 22/23 (not 2222, because QPot's own
//     cowrie.cfg moves it to the standard ports) and endlessh on 2222 (not 2223)
//     - so the grep could never match.
//  2. Many minimal honeypot images ship neither netstat nor ss (cowrie has
//     netstat but not ss; others have neither), so the check failed closed.
//
// /proc/net is always present on Linux and needs no tools, so this works across
// busybox, distroless-with-shell and full distros alike. A listening socket is
// identified by a zero remote address (rem_port ":0000"): an established
// connection carries a non-zero peer port, so matching ":PORT <hexrem>:0000"
// selects only the bound listener. Ports are 4-digit uppercase hex (the
// /proc/net encoding); any one expected port listening is enough to call the
// service up. Returns "" only when no port is known (caller omits healthcheck).
func listenHealthCheck(d honeypotDeploy, fallbackPort int) string {
	ports := d.Ports
	files := "/proc/net/tcp /proc/net/tcp6"
	if len(ports) == 0 && len(d.UDPPorts) > 0 {
		ports = d.UDPPorts
		files = "/proc/net/udp /proc/net/udp6"
	}
	if len(ports) == 0 {
		if fallbackPort <= 0 {
			return ""
		}
		ports = []int{fallbackPort}
	}
	seen := map[string]bool{}
	hexes := make([]string, 0, len(ports))
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			continue
		}
		h := fmt.Sprintf("%04X", p)
		if !seen[h] {
			seen[h] = true
			hexes = append(hexes, h)
		}
	}
	if len(hexes) == 0 {
		return ""
	}
	return fmt.Sprintf("grep -qE ':(%s) [0-9A-F]+:0000 ' %s 2>/dev/null",
		strings.Join(hexes, "|"), files)
}

// Generate generates a Docker Compose file
// composeEnvEntry renders a KEY=value list item as a double-quoted YAML
// string. Operator-set stealth values (banners, OS strings) routinely contain
// ": " or "#", which unquoted turned the entry into a YAML map or truncated it;
// "$" is doubled so Compose does not interpolate it.
func composeEnvEntry(key, value string) string {
	return strconv.Quote(key + "=" + strings.ReplaceAll(value, "$", "$$"))
}

// dbMinPids is the lowest pids limit the database container gets. The global
// per-honeypot limit (100 by default) is far too small for a database server:
// ClickHouse starts ~380 threads and exits on boot when it cannot create them.
const dbMinPids = 1024

// dbPidsLimit returns the pids limit for the database service: 0 (unlimited)
// stays unlimited, anything else is raised to at least dbMinPids.
func dbPidsLimit(globalMax int64) int64 {
	if globalMax == 0 || globalMax >= dbMinPids {
		return globalMax
	}
	return dbMinPids
}

func (g *ComposeGenerator) Generate() (string, error) {
	tmpl := `# QPot Instance: {{.Config.InstanceName}}
# QPot ID: {{.Config.QPotID}}
# Auto-generated - Do not edit manually

networks:
  # Every network gets an explicit subnet from QPot's allocator (which avoids
  # subnets already in use on the docker host). Left to docker, a network takes
  # a whole /16 from its default pool, which overlapped QPot's own per-honeypot
  # /24s ("Pool overlaps") as soon as a few networks existed.
  qpot_internal:
    internal: true
    ipam:
      config:
        - subnet: {{netSubnet "qpot_internal"}}

  # Only the database joins this one. Docker cannot publish a port for a
  # container that is attached solely to an internal network, so without it
  # the host-side qpot process could never reach the database (and so never
  # created its schema). The port is bound to 127.0.0.1 only.
  qpot_dbhost:
    driver: bridge
    ipam:
      config:
        - subnet: {{netSubnet "qpot_dbhost"}}
{{if sshProxyEnabled .Config}}
  # HiFi backends sit here ONLY. internal:true removes the default gateway, so
  # the real-OpenSSH backends (genuine attacker code execution) have NO outbound
  # connectivity and can never be used to pivot, scan, mine, or DDoS. This egress
  # lock is the single most important control for high-interaction mode.
  ssh-proxy_backend:
    internal: true
    ipam:
      config:
        - subnet: {{netSubnet "ssh-proxy_backend"}}
{{end}}{{range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
  {{$name}}_net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: {{bridgeName $.Config.InstanceName $name}}
    ipam:
      config:
        - subnet: {{netSubnet $name}}
{{end}}{{end}}

# The data and database directories are plain bind mounts, NOT named volumes:
# a named volume records its host path when first created and keeps it, so a
# re-created instance (or another user's instance with the same name on this
# docker host) silently got the OLD directory - its collector read the wrong
# logs and its database mounted someone else's data.

secrets:
  qpot_id:
    file: {{.Config.DataPath}}/qpot.id

services:
  # Database - {{.Config.Database.Type}}
  {{if eq .Config.Database.Type "clickhouse"}}database:
    image: clickhouse/clickhouse-server:latest
    container_name: {{.Config.InstanceName}}_db
    restart: unless-stopped
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    environment:
      CLICKHOUSE_DB: {{.Config.Database.Database}}
      CLICKHOUSE_USER: {{.Config.Database.Username}}
      CLICKHOUSE_PASSWORD: {{.Config.Database.Password}}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - {{.Config.GetDatabasePath}}:/var/lib/clickhouse
      - {{.Config.DataPath}}/clickhouse-config:/etc/clickhouse-server/conf.d
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "127.0.0.1:{{.Config.DatabaseHostPort}}:9000"
    networks:
      - qpot_internal
      - qpot_dbhost
    {{template "dbsecurity" dict "Config" $.Config "GlobalLimits" $.Config.Security.ResourceLimits "Name" "database"}}
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8123/ping"]
      interval: 10s
      timeout: 5s
      retries: 3
{{else if eq .Config.Database.Type "timescaledb"}}database:
    image: timescale/timescaledb:latest-pg15
    container_name: {{.Config.InstanceName}}_db
    restart: unless-stopped
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    environment:
      POSTGRES_DB: {{.Config.Database.Database}}
      POSTGRES_USER: {{.Config.Database.Username}}
      POSTGRES_PASSWORD: {{.Config.Database.Password}}
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - {{.Config.GetDatabasePath}}:/var/lib/postgresql/data
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "127.0.0.1:{{.Config.DatabaseHostPort}}:5432"
    networks:
      - qpot_internal
      - qpot_dbhost
    {{template "dbsecurity" dict "Config" $.Config "GlobalLimits" $.Config.Security.ResourceLimits "Name" "database"}}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U {{.Config.Database.Username}} -d {{.Config.Database.Database}}"]
      interval: 10s
      timeout: 5s
      retries: 3
{{end}}

  # Log collector (Vector) with QPot ID tagging
  collector:
    image: timberio/vector:latest-alpine
    container_name: {{.Config.InstanceName}}_collector
    restart: unless-stopped
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    # Point Vector explicitly at the YAML config so parser selection never
    # depends on the image's default config path/extension.
    command: ["--config", "/etc/vector/vector.yaml"]
    environment:
      QPOT_ID: {{.Config.QPotID}}
      QPOT_INSTANCE: {{.Config.InstanceName}}
    volumes:
      - {{.Config.DataPath}}/vector.yaml:/etc/vector/vector.yaml:ro
      - {{.Config.DataPath}}:/data:ro
      # The only writable path: the file_backup sink. Everything else under
      # /data stays read-only (it holds attacker-influenced honeypot logs).
      - {{.Config.DataPath}}/backup:/data/backup
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    networks:
      - qpot_internal
    cap_add:
      - DAC_READ_SEARCH

{{range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
{{template "honeypot" dict "Name" $name "HP" $hp "Config" $.Config "Sandbox" $.Sandbox}}
{{end}}{{end}}
{{if sshProxyEnabled .Config}}{{range $b := sshProxyBackends .Config}}
  # HiFi backend: a REAL Debian + OpenSSH server. The attacker's SSH handshake
  # terminates HERE (the broker only splices opaque TCP), which is what closes
  # the protocol-fingerprinting gap. This is genuine code execution, made safe by
  # the egress lock (ssh-proxy_backend is internal:true), the isolation runtime,
  # a minimal capability set, resource caps, and being reset between sessions. It
  # publishes NO host port - it is reachable only by the broker.
  {{$b.Service}}:
    image: {{GetHoneypotImage "ssh-backend"}}
    container_name: {{$.Config.InstanceName}}_{{$b.Service}}
    restart: unless-stopped
    # Every backend presents the SAME hostname and SAME SSH host keys (shared
    # volume below) so the pool looks like ONE server: a returning attacker routed
    # to a different backend never sees the hostname or host-key fingerprint
    # change (which would warn their SSH client / reveal the honeypot pool).
    hostname: "{{sshBackendHostname $.Config}}"
    {{- if $.Sandbox.ContainerRuntime}}
    # Stronger isolation runtime (gVisor/Kata) - strongly recommended for real RCE.
    runtime: {{$.Sandbox.ContainerRuntime}}
    {{- end}}
    networks:
      - ssh-proxy_backend
    environment:
      - BACKEND_USERS={{$b.UsersCSV}}
    volumes:
      # SHARED host keys (one fingerprint for the whole pool), generated by qpot
      # on the host and mounted READ-ONLY at /etc/ssh/keys (never shadowing the
      # image's hardened sshd_config): root on a backend cannot swap or plant
      # the pool's key. Plus this backend's own session recordings / sshd logs.
      - {{$.Config.DataPath}}/honeypots/ssh-backend/shared-hostkeys:/etc/ssh/keys:ro
      - {{$.Config.DataPath}}/honeypots/ssh-backend/{{$b.Service}}/logs:/var/log/ssh-backend
    labels:
      qpot.instance: "{{$.Config.InstanceName}}"
      qpot.honeypot: "ssh-backend"
    security_opt:
      - no-new-privileges:true
    # sshd privilege separation needs a small, specific capability set; everything
    # else is dropped. (Do NOT cap_drop ALL - sshd auth would break.)
    cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETPCAP
      - KILL
      - SYS_CHROOT
      - AUDIT_WRITE
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          cpus: '{{divf $.Config.Security.ResourceLimits.MaxCPUPercent 100}}'
          memory: {{$.Config.Security.ResourceLimits.MaxMemoryMB}}M
          {{if $.Config.Security.ResourceLimits.MaxPids}}pids: {{$.Config.Security.ResourceLimits.MaxPids}}{{end}}
        reservations:
          cpus: '0.05'
          memory: 32M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: {{$.Config.Security.ResourceLimits.RestartAttempts}}
        window: 120s
    mem_swappiness: 0
    oom_kill_disable: false
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "qpot.instance,qpot.honeypot"
{{end}}{{end}}

  # Note: the Web UI is served in-process by the qpot binary itself ("qpot up"
  # starts an HTTP server on Config.WebUI.Port). There is no separate web UI
  # container — adding one here would both duplicate that listener (port
  # conflict) and depend on an image that isn't published.

{{define "honeypot"}}
  # Honeypot: {{.Name}}
  {{.Name}}:
    image: {{GetHoneypotImage .Name}}
    container_name: {{$.Config.InstanceName}}_{{.Name}}
    restart: on-failure:{{$.Config.Security.ResourceLimits.RestartAttempts}}
    {{- if $.Config.Security.NetworkIsolation.RandomizeMAC}}
    # Stable, locally-administered MAC per (instance, honeypot) so containers do
    # not all share Docker's default vendor prefix / a predictable address.
    mac_address: {{macFor $.Config.InstanceName .Name}}
    {{- end}}
    {{if $.Sandbox.ContainerRuntime}}# Stronger isolation runtime (gVisor/Kata) for this attacker-facing container
    runtime: {{$.Sandbox.ContainerRuntime}}
    {{end}}
    {{- $d := deployFor .Name}}
    {{- $hpName := .Name}}
    {{- if $d.Command}}
    # Run the service directly instead of the image's default entrypoint; see the
    # deploy profile (deploy.go) for why - e.g. cowrie's launcher would otherwise
    # override QPot's generated config with a random built-in persona.
    command: [{{range $i, $c := $d.Command}}{{if $i}}, {{end}}"{{$c}}"{{end}}]
    {{- end}}
    {{- if $d.WorkingDir}}
    working_dir: {{$d.WorkingDir}}
    {{- end}}
    ports:
    {{- if or $d.Ports $d.UDPPorts}}
    {{- range $p := $d.Ports}}
      - "{{hostPort $hpName $p}}:{{$p}}"
    {{- end}}
    {{- range $p := $d.UDPPorts}}
      - "{{hostPort $hpName $p}}:{{$p}}/udp"
    {{- end}}
    {{- else}}
      - "{{hostPort $hpName .HP.Port}}:{{.HP.Port}}"
    {{- end}}
    volumes:
      # The QPot ID (the API credential) is deliberately NOT mounted or passed
      # to honeypot containers — they run attacker-controlled workloads, so a
      # honeypot RCE must not yield the management-API credential. Log tagging is
      # done by the Vector collector. Mounts below come from the per-honeypot
      # deployment profile (deploy.go), derived from T-Pot's reference composes
      # and verified by running the images.
    {{- range $v := $d.Volumes}}
      - {{$.Config.DataPath}}/honeypots/{{$.Name}}/{{$v.HostSubdir}}:{{$v.ContainerPath}}
    {{- end}}
    networks:
      - qpot_internal
      - {{.Name}}_net
    {{- if eq .Name "ssh-proxy"}}
      # The broker also joins the egress-locked backend network so it can reach
      # the real-OpenSSH backends (and nothing else can).
      - ssh-proxy_backend
    {{- end}}
    labels:
      # Host-side identification for QPot's tooling and the docker log driver.
      # Docker labels are NOT visible to a process running inside the container
      # (unlike environment variables, which 'env' dumps), so the honeypot is
      # identifiable for management WITHOUT handing an attacker who lands
      # in-container code execution a "this is a honeypot / this is QPot" tell.
      qpot.instance: "{{$.Config.InstanceName}}"
      qpot.honeypot: "{{.Name}}"
    environment:
      # Deliberately minimal and non-self-identifying. Earlier revisions set
      # platform/honeypot-naming variables inside every honeypot container, so an
      # attacker who got a real shell and ran env immediately learned it was a
      # honeypot. None were needed: the log pipeline derives the honeypot from
      # the bind-mounted log path and QPot's own metadata now lives in the
      # host-side labels above. Only innocuous, commonly-present values and the
      # per-honeypot stealth/profile knobs (set only when configured) remain.
      - LOG_LEVEL=info
      {{if hostnameSafe .HP.Stealth.FakeHostname}}- {{envEntry "FAKE_HOSTNAME" (hostnameSafe .HP.Stealth.FakeHostname)}}{{end}}
      {{if .HP.Stealth.FakeOS}}- {{envEntry "FAKE_OS" .HP.Stealth.FakeOS}}{{end}}
      {{if .HP.Stealth.FakeKernel}}- {{envEntry "FAKE_KERNEL" .HP.Stealth.FakeKernel}}{{end}}
      {{if .HP.Stealth.BannerString}}- {{envEntry "BANNER_STRING" .HP.Stealth.BannerString}}{{end}}
      {{if .HP.Stealth.RandomizeSSHVersion}}- RANDOMIZE_SSH_VERSION=1{{end}}
      {{if .HP.Stealth.AddArtificialDelay}}- {{envEntry "ARTIFICIAL_DELAY" (printf "%v" .HP.Stealth.DelayRangeMs)}}{{end}}
      {{- if eq .Name "ssh-proxy"}}
      # HiFi broker: the operator-fixed backend pool (never attacker-derived, so
      # no SSRF) and the logical name used in the broker's session events.
      - QPOT_SSHPROXY_NAME=ssh-proxy
      - QPOT_SSHPROXY_BACKENDS={{sshBackendCSV $.Config}}
      {{- end}}
      {{- range $k, $v := $d.Env}}
      - {{$k}}={{$v}}
      {{- end}}
    {{template "security" dict "Config" $.Config "HP" .HP "GlobalLimits" $.Config.Security.ResourceLimits "Name" .Name "FakeHostname" .HP.Stealth.FakeHostname}}
    {{- if ne .Name "ssh-proxy"}}
    {{- $hc := listenCheck $d .HP.Port}}
    {{- if $hc}}
    healthcheck:
      # Probe the real internal listen port(s) via /proc/net (tool-independent);
      # see listenHealthCheck for why netstat/ss and .HP.Port were both wrong.
      test: ["CMD-SHELL", "{{$hc}}"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    {{- end}}
    {{- end}}
{{end}}

{{define "dbsecurity"}}
    # Security hardening - Resource limits (database service)
    deploy:
      resources:
        limits:
          cpus: '{{divf .GlobalLimits.MaxCPUPercent 100}}'
          memory: {{.GlobalLimits.MaxMemoryMB}}M
          {{with dbPids .GlobalLimits.MaxPids}}pids: {{.}}{{end}}
        reservations:
          cpus: '0.05'
          memory: 64M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: {{.Config.Security.ResourceLimits.RestartAttempts}}
        window: 120s

    # Security hardening - Container security
    {{if .Config.Security.NoNewPrivileges}}security_opt:
      - no-new-privileges:true{{end}}
    {{if .Config.Security.DropCapabilities}}cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - SETUID
      - SETGID{{end}}

    # No user override: the database image runs as its own user; forcing a
    # different uid breaks its data-directory ownership. CHOWN is required:
    # both the ClickHouse and TimescaleDB entrypoints chown their data dir on
    # first start and exit immediately without it. DAC_OVERRIDE lets the
    # entrypoint work inside the instance's private (0750) data dir, which the
    # host user owns, instead of that dir having to be world-writable. The
    # database is not attacker-facing (internal network + 127.0.0.1 only).

    # Hostname isolation
    hostname: "{{.Name}}-host"

    # Memory and OOM settings
    mem_swappiness: 0
    oom_kill_disable: false

    # Logging configuration
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "qpot.instance,qpot.id"
        env: "QPOT_ID,QPOT_INSTANCE"
{{end}}

{{define "security"}}
    # Security hardening - Resource limits
    {{$cpuLimit := .GlobalLimits.MaxCPUPercent}}
    {{$memLimit := .GlobalLimits.MaxMemoryMB}}
    {{$pidLimit := .GlobalLimits.MaxPids}}
    {{/* An unset (zero) custom value keeps the global limit: rendering
         cpus '0' / memory 0M would mean NO cap on an attacker-facing box. */}}
    {{if .HP.Resources.UseCustomLimits}}
    {{if .HP.Resources.MaxCPUPercent}}{{$cpuLimit = .HP.Resources.MaxCPUPercent}}{{end}}
    {{if .HP.Resources.MaxMemoryMB}}{{$memLimit = .HP.Resources.MaxMemoryMB}}{{end}}
    {{if .HP.Resources.MaxPids}}{{$pidLimit = .HP.Resources.MaxPids}}{{end}}
    {{end}}
    deploy:
      resources:
        limits:
          cpus: '{{divf $cpuLimit 100}}'
          memory: {{$memLimit}}M
          {{if $pidLimit}}pids: {{$pidLimit}}{{end}}
        reservations:
          cpus: '0.05'
          memory: 32M
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: {{.Config.Security.ResourceLimits.RestartAttempts}}
        window: 120s

    # Security hardening - Container security
    {{if .Config.Security.ReadOnlyFilesystem}}read_only: true{{end}}
    {{if .Config.Security.NoNewPrivileges}}security_opt:
      - no-new-privileges:true{{end}}
    {{- $dep := deployFor .Name}}
    {{if .Config.Security.DropCapabilities}}cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      {{if or $dep.NeedsNetBind (and .HP.Port (lt .HP.Port 1024))}}- NET_BIND_SERVICE{{end}}{{range $dep.ExtraCaps}}
      - {{.}}{{end}}{{end}}

    # No user override: each honeypot image already runs as its own non-root
    # user (e.g. cowrie=2000). Forcing a different uid breaks the image's file
    # ownership and tmpfs uid assumptions (cowrie's /tmp/cowrie is uid 2000).

    # Hostname isolation
    hostname: {{if hostnameSafe .FakeHostname}}"{{hostnameSafe .FakeHostname}}"{{else if .Name}}"{{.Name}}-host"{{else}}"qpot-host"{{end}}

    # Temporary filesystems. A single tmpfs: block combines the read-only-root
    # scratch mounts with any image-specific tmpfs the deployment profile
    # requires (e.g. cowrie's /tmp/cowrie), so there is never a duplicate key.
    {{- $dt := deployFor .Name}}
    {{- $tmpfs := mergedTmpfs .Config.Security.ReadOnlyFilesystem $dt}}
    {{- if $tmpfs}}
    tmpfs:
    {{- range $t := $tmpfs}}
      - {{$t}}
    {{- end}}
    {{- end}}

    # Memory and OOM settings
    mem_swappiness: 0
    oom_kill_disable: false

    # Logging configuration
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "qpot.instance,qpot.honeypot"
{{end}}
`

	// Pre-assign collision-free host ports and subnets for the whole stack
	// before rendering, so no two honeypots clash on a host port or a /24.
	hostPortMap := g.buildHostPortMap()
	subnetMap := g.buildSubnetMap()

	funcMap := template.FuncMap{
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("invalid dict call")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},
		"divf": func(a, b float64) float64 {
			return a / b
		},
		"dbPids": dbPidsLimit,
		"add": func(a, b int) int {
			return a + b
		},
		"lt": func(a, b int) bool {
			return a < b
		},
		"GetHoneypotImage": GetHoneypotImage,
		"subnetFor":        subnetForNetwork,
		"bridgeName":       bridgeName,
		"macFor":           macForSeed,
		"deployFor":        deployProfileFor,
		// listenCheck builds the container healthcheck command, probing the actual
		// INTERNAL listen ports from the deploy profile (not the host/config port)
		// via /proc/net so it needs no netstat/ss. See listenHealthCheck.
		"listenCheck": listenHealthCheck,
		// HiFi SSH proxy helpers (see sshproxy.go): whether the ssh-proxy honeypot
		// is enabled, the real-OpenSSH backend companion services to render, and
		// the broker's QPOT_SSHPROXY_BACKENDS value.
		"sshProxyEnabled":    sshProxyEnabled,
		"sshProxyBackends":   sshProxyBackends,
		"sshBackendCSV":      sshBackendCSV,
		"sshBackendHostname": sshBackendHostname,
		// hostnameSafe reduces an operator-set fake hostname to valid hostname
		// characters before it is interpolated into the YAML `hostname:` field /
		// FAKE_HOSTNAME env, so a stray quote/newline can never break the compose.
		"hostnameSafe": sanitizeHostname,
		"envEntry":     composeEnvEntry,
		// hostPort resolves the collision-free host port assigned to a
		// (honeypot, container port) pair. Built once per Generate() so the
		// whole stack shares one consistent, unique assignment.
		"hostPort": func(honeypot string, port int) int {
			if p, ok := hostPortMap[portKey(honeypot, port)]; ok {
				return p
			}
			// Fall back to the raw hash if a pair was somehow not pre-assigned.
			return g.Config.AllocatePortFor(honeypot, port)
		},
		// netSubnet resolves the collision-free /24 assigned to a honeypot's
		// network.
		"netSubnet": func(honeypot string) string {
			if s, ok := subnetMap[honeypot]; ok {
				return s
			}
			return subnetForNetwork(g.Config.InstanceName, honeypot)
		},
		// mergedTmpfs combines the read-only-root scratch mounts with the
		// per-honeypot profile's tmpfs, deduplicated by target path. A profile
		// that needs /tmp owned by a specific uid (e.g. log4pot) would otherwise
		// collide with the default "/tmp" mount and make compose reject the file
		// ("target /tmp already mounted"). Profile entries win on conflict.
		"mergedTmpfs": func(readonly bool, d honeypotDeploy) []string {
			target := func(entry string) string {
				if i := strings.IndexByte(entry, ':'); i >= 0 {
					return entry[:i]
				}
				return entry
			}
			seen := map[string]bool{}
			var out []string
			for _, t := range d.Tmpfs {
				if seen[target(t)] {
					continue
				}
				seen[target(t)] = true
				out = append(out, t)
			}
			if readonly {
				for _, t := range []string{
					"/tmp:noexec,nosuid,size=100m,mode=1777",
					"/var/tmp:noexec,nosuid,size=50m,mode=1777",
					"/run:noexec,nosuid,size=10m,mode=1777",
				} {
					if seen[target(t)] {
						continue
					}
					seen[target(t)] = true
					out = append(out, t)
				}
			}
			return out
		},
		"int": func(v interface{}) int {
			switch i := v.(type) {
			case int:
				return i
			case int8:
				return int(i)
			case int16:
				return int(i)
			case int32:
				return int(i)
			case int64:
				return int(i)
			case uint:
				return int(i)
			case uint8:
				return int(i)
			case uint16:
				return int(i)
			case uint32:
				return int(i)
			case uint64:
				return int(i)
			default:
				return 0
			}
		},
	}

	t := template.Must(template.New("compose").Funcs(funcMap).Parse(tmpl))

	var buf bytes.Buffer
	if err := t.Execute(&buf, g); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// EnabledSensors returns the Vector transform names for the T-Pot NSM sensors
// that are enabled (Suricata IDS, p0f, fatt). These transforms map sensor logs
// onto the shared events schema and feed the same downstream (geoip + sink) as
// honeypot logs, bypassing the stealth probe-filter. Used by the Vector
// template to wire inputs without duplicating per-sensor branches.
func (g *ComposeGenerator) EnabledSensors() []string {
	var s []string
	if g.Config.Collector.IngestSuricata {
		s = append(s, "suricata_events")
	}
	if g.Config.Collector.IngestP0f {
		s = append(s, "p0f_events")
	}
	if g.Config.Collector.IngestFatt {
		s = append(s, "fatt_events")
	}
	return s
}

// GenerateVectorConfig generates Vector configuration for log collection
func (g *ComposeGenerator) GenerateVectorConfig() (string, error) {
	config := `# Vector configuration for QPot
# QPot ID: {{.Config.QPotID}}
# Auto-generated

data_dir: "/var/lib/vector"

api:
  enabled: true
  address: "127.0.0.1:8686"
{{if .Config.Collector.GeoIPDBPath}}
enrichment_tables:
  qpot_geoip:
    type: "geoip"
    path: "{{.Config.Collector.GeoIPDBPath}}"
{{end}}
sources:
{{- range $name, $hp := .Config.Honeypots}}
{{- if $hp.Enabled}}
  {{$name}}_logs:
    type: file
    include:
      - "/data/honeypots/{{$name}}/logs/**/*.log"
      - "/data/honeypots/{{$name}}/logs/**/*.json"
    # cowrie's TTY recordings are binary; never tail them as log lines.
    exclude:
      - "/data/honeypots/{{$name}}/logs/tty/**"
    read_from: end
    multiline:
      mode: halt_before
      start_pattern: '^\{'
      condition_pattern: '^\{'
      timeout_ms: 1000
{{end}}{{end}}
{{- if .Config.Collector.IngestSuricata}}
  # T-Pot's Suricata network IDS writes one EVE JSON object per line. Harmless
  # when Suricata is not deployed (the glob simply matches nothing).
  suricata_eve:
    type: file
    include:
      - "/data/suricata/log/eve.json"
      - "/data/suricata/log/*.json"
    read_from: end
{{- end}}
{{- if .Config.Collector.IngestP0f}}
  # p0f passive OS fingerprinting (one JSON object per line).
  p0f_log:
    type: file
    include:
      - "/data/p0f/log/p0f.json"
    read_from: end
{{- end}}
{{- if .Config.Collector.IngestFatt}}
  # fatt network fingerprinting (JA3/HASSH; one JSON object per line).
  fatt_log:
    type: file
    include:
      - "/data/fatt/log/fatt.log"
      - "/data/fatt/log/*.json"
    read_from: end
{{- end}}

transforms:
  add_qpot_metadata:
    type: remap
    inputs:
{{- range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
      - {{$name}}_logs{{end}}{{end}}
    source: |
      # Remember where the line came from BEFORE merging the honeypot's JSON:
      # a log object carrying its own "file" key must not be able to redirect
      # the per-event honeypot attribution below.
      src_file = string(.file) ?? ""
      raw = string(.message) ?? ""

      # Parse the honeypot's JSON payload FIRST so its fields are present;
      # our own metadata is stamped afterwards so an attacker-controlled log
      # line can never clobber qpot_id / timestamp / honeypot.
      is_json = false
      if starts_with(strip_whitespace(raw), "{") {
        parsed, perr = parse_json(raw)
        if perr == null && is_object(parsed) {
          . = merge(., object!(parsed))
          is_json = true
        }
      }

      # Derive the honeypot name from the source file path
      # (/data/honeypots/<name>/logs/...). This is the only place the per-event
      # honeypot can be recovered, and the DB requires it (NOT NULL).
      hp = "unknown"
      m, merr = parse_regex(src_file, r'/honeypots/(?P<hp>[^/]+)/')
      if merr == null {
        hp = string(m.hp) ?? "unknown"
      }
      .honeypot = hp

      # Every honeypot QPot ships writes one JSON object per line; their
      # plain-text .log files are operational chatter that duplicates the JSON
      # (or, for cowrie's TTY recordings, binary). Only endlessh logs attacks
      # as text, so parse its ACCEPT/CLOSE lines and drop all other non-JSON
      # input instead of storing it as a placeholder 0.0.0.0 event.
      if !is_json {
        if hp != "endlessh" {
          abort
        }
        em, eerr = parse_regex(raw, r'\b(?P<action>ACCEPT|CLOSE) host=(?P<host>\S+) port=(?P<port>\d+)')
        if eerr != null {
          abort
        }
        .src_ip = em.host
        .src_port = em.port
        .eventid = "endlessh.connection." + downcase(string(em.action) ?? "event")
        .protocol = "ssh"
      }

      # Source IP from the common honeypot field names. Validated so a
      # malformed value can never poison an insert (inet / String columns);
      # IPv4-mapped IPv6 is unwrapped so the same attacker groups together.
      sip = ""
      if is_string(.src_ip) {
        sip = string!(.src_ip)
      } else if is_string(.source_ip) {
        sip = string!(.source_ip)
      }
      sip = replace(strip_whitespace(sip), r'^::ffff:', "")
      if !(ip_cidr_contains("0.0.0.0/0", sip) ?? false) && !(ip_cidr_contains("::/0", sip) ?? false) {
        sip = "0.0.0.0"
      }
      .source_ip = sip

      # Ports: cowrie/conpot/dionaea use dst_port, adbhoney dest_port (as a
      # string), heralding source_port/destination_port.
      sp = to_int(.src_port) ?? 0
      if sp == 0 {
        sp = to_int(.source_port) ?? 0
      }
      dp = to_int(.dst_port) ?? 0
      if dp == 0 {
        dp = to_int(.dest_port) ?? 0
      }
      if dp == 0 {
        dp = to_int(.destination_port) ?? 0
      }
      if sp < 0 || sp > 65535 {
        sp = 0
      }
      if dp < 0 || dp > 65535 {
        dp = 0
      }
      .source_port = sp
      .dest_port = dp

      # Protocol: cowrie/heralding "protocol", dionaea "connection.protocol",
      # conpot "data_type".
      proto = ""
      if is_string(.protocol) {
        proto = string!(.protocol)
      }
      if proto == "" {
        proto = to_string(.connection.protocol) ?? ""
      }
      if proto == "" {
        proto = to_string(.data_type) ?? ""
      }
      .protocol = downcase(proto)

      # Event type. cowrie/adbhoney/ssh-proxy name their events; for the
      # honeypots that do not, derive a dotted name the ATT&CK rules can match
      # (…connect…, …login.failed, …command, …probe).
      et = ""
      if is_string(.eventid) {
        et = string!(.eventid)
      }
      if et == "" && hp == "dionaea" {
        et = "dionaea.connection." + (to_string(.connection.type) ?? "event")
      }
      if et == "" && hp == "conpot" {
        orig = to_string(.event_type) ?? ""
        dt = downcase(to_string(.data_type) ?? "")
        if dt == "" {
          dt = "unknown"
        }
        if orig != "" {
          et = "conpot." + dt + "." + orig
        } else if includes(["modbus", "s7comm", "bacnet", "enip", "ipmi", "iec104", "guardian_ast", "kamstrup_protocol", "kamstrup_management_protocol"], dt) {
          et = "conpot." + dt + ".command"
        } else {
          et = "conpot." + dt + ".probe"
        }
      }
      if et == "" && hp == "heralding" {
        if (to_int(.num_auth_attempts) ?? 0) > 0 {
          et = "heralding.login.failed"
        } else {
          et = "heralding.session.connect"
        }
      }
      if et == "" && is_string(.event_type) {
        et = string!(.event_type)
      }
      if et == "" {
        et = "unknown"
      }
      .event_type = downcase(et)

      # Login attempts: cowrie and adbhoney log the username and password;
      # heralding records a list of attempts per session (keep the latest).
      user = ""
      pass = ""
      if is_string(.username) {
        user = string!(.username)
      }
      if is_string(.password) {
        pass = string!(.password)
      }
      if user == "" && pass == "" {
        user = to_string(.auth_attempts[-1].username) ?? ""
        pass = to_string(.auth_attempts[-1].password) ?? ""
      }
      .username = user
      .password = pass

      # Attacker input: cowrie/adbhoney log commands as "input".
      cmd = ""
      if is_string(.input) {
        cmd = string!(.input)
      } else if is_string(.command) {
        cmd = string!(.command)
      }
      .command = cmd

      # Payload: download URL (cowrie/adbhoney), raw request (conpot).
      pl = ""
      if is_string(.url) {
        pl = string!(.url)
      } else if is_string(.request) {
        pl = string!(.request)
      } else if is_string(.payload) {
        pl = string!(.payload)
      }
      .payload = pl

      # metadata is Map(String, String) / JSONB: rebuild it from a fixed set
      # of string-coerced keys so an odd honeypot field type can never make the
      # whole batch fail to insert.
      md = {}
      for_each(["session", "session_id", "sensor", "dst_ip", "dest_ip", "destination_ip", "version", "hassh", "shasum", "outfile", "filename", "duration", "num_auth_attempts", "backend", "reason"]) -> |_i, k| {
        v = get(., [k]) ?? null
        if v != null {
          sv = to_string(v) ?? ""
          if sv != "" {
            md = set!(md, [k], sv)
          }
        }
      }
      .metadata = md

      # Classification is the intelligence worker's job, and event_id is the
      # database's row identity; never trust a log line that claims either.
      del(.event_id)
      del(.technique_id)
      del(.technique_name)
      del(.tactic_id)
      del(.tactic_name)
      del(.kill_chain_stage)
      del(.confidence)
      del(.classified)
      del(.country)
      del(.city)
      del(.asn)

      # Stamp QPot metadata LAST. The timestamp is formatted as ClickHouse's
      # DateTime64 'basic' input format ("YYYY-MM-DD HH:MM:SS.fff"); a raw
      # RFC3339 value (with T/Z) is rejected by the JSONEachRow parser (400).
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{if .Config.Collector.IngestSuricata}}
  # Map Suricata EVE alerts onto the shared events schema so they appear in the
  # dashboards / attack map alongside honeypot hits. Only "alert" events are
  # kept; the high-volume flow/stats/dns/http records are dropped.
  suricata_events:
    type: remap
    inputs:
      - suricata_eve
    source: |
      if is_string(.message) && starts_with(strip_whitespace(string!(.message)), "{") {
        parsed, perr = parse_json(string!(.message))
        if perr == null {
          . = merge(., object(parsed) ?? {})
        }
      }
      # Keep only IDS alerts; drop flow/stats/dns/http/tls noise.
      if (to_string(.event_type) ?? "") != "alert" {
        abort
      }
      .honeypot = "suricata"
      .source_ip = to_string(.src_ip) ?? "0.0.0.0"
      .source_port = to_int(.src_port) ?? 0
      .dest_port = to_int(.dest_port) ?? 0
      .protocol = downcase(to_string(.proto) ?? "")
      .event_type = "alert"
      # Surface the signature so it is visible/searchable; richer detail goes to
      # the metadata map (a real column in the events table).
      .command = to_string(.alert.signature) ?? ""
      .metadata = {
        "signature": to_string(.alert.signature) ?? "",
        "category": to_string(.alert.category) ?? "",
        "severity": to_string(.alert.severity) ?? "",
        "sensor": "suricata"
      }
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{end}}
{{if .Config.Collector.IngestP0f}}
  # Map p0f passive OS fingerprints onto the events schema. honeypot="p0f";
  # the detected OS goes in command (visible) + metadata.
  p0f_events:
    type: remap
    inputs:
      - p0f_log
    source: |
      if is_string(.message) && starts_with(strip_whitespace(string!(.message)), "{") {
        parsed, perr = parse_json(string!(.message))
        if perr == null {
          . = merge(., object(parsed) ?? {})
        }
      }
      .honeypot = "p0f"
      .source_ip = to_string(.client_ip) ?? "0.0.0.0"
      .source_port = to_int(.client_port) ?? 0
      .dest_port = to_int(.server_port) ?? 0
      .event_type = "os_fingerprint"
      .command = to_string(.os) ?? ""
      .metadata = {
        "os": to_string(.os) ?? "",
        "dist": to_string(.dist) ?? "",
        "link": to_string(.link) ?? "",
        "raw_sig": to_string(.raw_sig) ?? "",
        "sensor": "p0f"
      }
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{end}}
{{if .Config.Collector.IngestFatt}}
  # Map fatt network fingerprints onto the events schema. honeypot="fatt";
  # JA3/HASSH fingerprints go in metadata, a representative one in command.
  fatt_events:
    type: remap
    inputs:
      - fatt_log
    source: |
      if is_string(.message) && starts_with(strip_whitespace(string!(.message)), "{") {
        parsed, perr = parse_json(string!(.message))
        if perr == null {
          . = merge(., object(parsed) ?? {})
        }
      }
      .honeypot = "fatt"
      .source_ip = to_string(.sourceIp) ?? "0.0.0.0"
      .source_port = to_int(.sourcePort) ?? 0
      .dest_port = to_int(.destinationPort) ?? 0
      .protocol = downcase(to_string(.protocol) ?? "")
      .event_type = "fingerprint"
      ja3 = to_string(.ja3) ?? ""
      hassh = to_string(.hassh) ?? ""
      .command = if ja3 != "" { ja3 } else { hassh }
      .metadata = {
        "ja3": ja3,
        "ja3s": to_string(.ja3s) ?? "",
        "hassh": hassh,
        "hasshServer": to_string(.hasshServer) ?? "",
        "sensor": "fatt"
      }
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{end}}
{{if .Config.Collector.GeoIPDBPath}}
  enrich_geoip:
    type: remap
    inputs:
      - add_qpot_metadata
{{- range $.EnabledSensors}}
      - {{.}}
{{- end}}
    source: |
      # GeoIP enrichment using the MaxMind GeoLite2 enrichment table
      if exists(.source_ip) && .source_ip != "0.0.0.0" && .source_ip != "127.0.0.1" {
        enriched, err = get_enrichment_table_record("qpot_geoip", {"ip": .source_ip})
        if err == null {
          .country = enriched.country.iso_code
          .city = enriched.city.names.en
          .asn = to_string(enriched.autonomous_system.autonomous_system_number)
        } else {
          .country = "unknown"
          .city = "unknown"
          .asn = "unknown"
        }
      }
{{end}}
  filter_stealth:
    type: filter
    inputs:
      # Feeds from enrich_geoip when GeoIP is configured, else directly from
      # add_qpot_metadata (GeoIP is optional so Vector can start without an mmdb).
      # When GeoIP is off, the NSM sensor transforms join here directly; when it
      # is on, they arrive already enriched via enrich_geoip.
      - {{if .Config.Collector.GeoIPDBPath}}enrich_geoip{{else}}add_qpot_metadata{{end}}
{{- if not .Config.Collector.GeoIPDBPath}}{{range $.EnabledSensors}}
      - {{.}}
{{- end}}{{end}}
    condition: |
      # Drop events whose message contains a known scanner signature (stealth).
      # Substring match via contains() — match_any expects regexes, and
      # contains avoids regex-escaping the operator-supplied probe strings.
      # NSM sensor events (Suricata/p0f/fatt) are never stealth-filtered:
      # dropping an IDS alert or a fingerprint because its JSON mentions a
      # scanner signature would discard real sensor data.
      {{- if .Config.Stealth.BlockCommonProbes}}
      sensor = to_string(.honeypot) ?? ""
      if sensor == "suricata" || sensor == "p0f" || sensor == "fatt" {
        true
      } else {
        msg = downcase(string(.message) ?? "")
        !({{range $i, $probe := .Config.Stealth.BlockedProbes}}{{if $i}} || {{end}}contains(msg, {{vrlStr $probe}}){{end}})
      }
      {{- else}}
      true
      {{- end}}

{{- if eq .Config.Database.Type "timescaledb"}}
  # payload is BYTEA: hand it over hex-encoded, otherwise any backslash in
  # attacker input is an "invalid input syntax for type bytea" that drops the
  # whole batch. The timestamp is UTC; say so for TIMESTAMPTZ.
  pg_prepare:
    type: remap
    inputs:
      - filter_stealth
    source: |
      .payload = "\\x" + encode_base16(string(.payload) ?? "")
      .timestamp = (string(.timestamp) ?? format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")) + "+00"
{{- end}}

sinks:
{{if eq .Config.Database.Type "clickhouse"}}
  clickhouse:
    type: clickhouse
    inputs:
      - filter_stealth
    endpoint: "http://database:8123"
    database: {{.Config.Database.Database}}
    table: events
    # The enriched event carries fields that are not columns in the events
    # table (qpot_id, the honeypot's own eventid/session/etc.). Without this,
    # ClickHouse rejects the whole insert on the first unknown column and all
    # events are dropped. qpot_id is re-attached by the API at read time.
    skip_unknown_fields: true
    auth:
      strategy: basic
      user: {{.Config.Database.Username}}
      password: "{{.Config.Database.Password}}"
    batch:
      max_bytes: 1049000
      timeout_secs: 5
    request:
      retry_attempts: 3
{{else if eq .Config.Database.Type "timescaledb"}}
  timescaledb:
    type: postgres
    inputs:
      - pg_prepare
    endpoint: "postgres://{{.Config.Database.Username}}:{{.Config.Database.Password}}@database:5432/{{.Config.Database.Database}}"
    # events_ingest is an auto-updatable view of only the collector-supplied
    # columns: the sink writes NULL for every column it does not have, which
    # on the events table itself breaks id NOT NULL and every DEFAULT.
    # Fields that are not view columns (qpot_id, the honeypot's raw keys) are
    # ignored by jsonb_populate_recordset.
    table: events_ingest
    batch:
      max_bytes: 1049000
      timeout_secs: 5
{{end}}

  # Console output for debugging
  console:
    type: console
    inputs:
      - filter_stealth
    encoding:
      codec: json
      except_fields:
        - password
        - payload

  # File backup of logs
  file_backup:
    type: file
    inputs:
      - filter_stealth
    path: "/data/backup/logs/%Y/%m/%d/{{"{{"}} honeypot {{"}}"}}.log"
    encoding:
      codec: json
`

	t := template.Must(template.New("vector").Funcs(template.FuncMap{
		"vrlStr": vrlStringLiteral,
	}).Parse(config))

	var buf bytes.Buffer
	if err := t.Execute(&buf, g); err != nil {
		return "", fmt.Errorf("failed to execute vector template: %w", err)
	}

	return buf.String(), nil
}

// GenerateTPOTConfig generates TPOT-compatible configuration files
func (g *ComposeGenerator) GenerateTPOTConfig(honeypot string) (map[string]string, error) {
	configs := make(map[string]string)

	hp, ok := g.Config.Honeypots[honeypot]
	if !ok {
		return configs, fmt.Errorf("honeypot not found: %s", honeypot)
	}

	switch honeypot {
	case "cowrie":
		configs["cowrie.cfg"] = g.generateCowrieConfig(hp)
		configs["userdb.txt"] = g.generateCowrieUserDB()
	case "conpot":
		configs["conpot.cfg"] = g.generateConpotConfig(hp)
	}

	return configs, nil
}

// generateCowrieUserDB builds a per-instance Cowrie userdb.txt from a realistic
// system persona (see credentials.go).
//
// Research basis (cryptax "Customizing Cowrie"; Cowrie #1102; SANS ISC / F5 Labs
// credential studies): the most-cited Cowrie tell is its default userdb
// (phil/richard/pi:raspberry accept any password). QPot never emits those.
// Instead each instance is assigned a believable persona (corporate Ubuntu, IoT
// camera, DB server, ...) — explicitly via stealth.credential_template, else
// auto-selected per instance from the seed — and only that persona's exact
// credentials succeed. Cowrie reads this from etc/userdb.txt.
func (g *ComposeGenerator) generateCowrieUserDB() string {
	seed := deceptionSeed(g.Config)
	explicit := ""
	if hp, ok := g.Config.Honeypots["cowrie"]; ok {
		explicit = hp.Stealth.CredentialTemplate
	}
	return renderCowrieUserDB(selectCredentialTemplate(explicit, seed))
}

// generateCowrieHoneyfs returns the per-instance honeyfs files (etc/passwd,
// group, hostname, os-release, issue) keyed by their path under honeyfs/,
// consistent with this instance's credential persona, distro profile, and
// hostname. See honeyfs.go for the research basis.
func (g *ComposeGenerator) generateCowrieHoneyfs() map[string]string {
	seed := deceptionSeed(g.Config)
	hp := g.Config.Honeypots["cowrie"]
	persona := selectCredentialTemplate(hp.Stealth.CredentialTemplate, seed)
	hostname := hp.Stealth.FakeHostname
	if hostname == "" {
		// Coherent with the persona's role (a db-server box gets a db-style
		// name, not an unrelated one) so /etc/hostname, /etc/hosts and the shell
		// prompt match the accounts in /etc/passwd.
		hostname = hostnameForPersona(persona, seed)
	}
	return generateHoneyfs(persona, cowrieProfile(hp, seed), hostname, seed)
}

// cowrieProfile is the instance's distro profile with the operator's
// stealth.fake_kernel applied. Every Cowrie artifact (cowrie.cfg's uname,
// /proc/version, /proc/sys/kernel/osrelease, the MOTD) must be built from this
// one profile; overriding only cowrie.cfg made `uname -r` contradict them.
func cowrieProfile(hp config.HoneypotConfig, seed string) distroProfile {
	p := profileForSeed(seed)
	if k := sanitizeConfigValue(hp.Stealth.FakeKernel); k != "" {
		p.KernelVersion = k
	}
	return p
}

// generateCowrieFsPatch returns the Python script that, run at container start,
// builds the persona home directories AND the per-instance system files
// (machine-id, shadow, lsb-release, /proc/sys/kernel/*, ...) in Cowrie's fake
// filesystem, and removes any stock home absent from /etc/passwd (see
// cowriefs.go / honeyfs.go). The persona, distro profile, hostname and uids all
// mirror generateCowrieHoneyfs/generateCowrieConfig so every artifact stays
// consistent.
func (g *ComposeGenerator) generateCowrieFsPatch() string {
	seed := deceptionSeed(g.Config)
	hp := g.Config.Honeypots["cowrie"]
	persona := selectCredentialTemplate(hp.Stealth.CredentialTemplate, seed)
	profile := cowrieProfile(hp, seed)
	hostname := hp.Stealth.FakeHostname
	if hostname == "" {
		hostname = hostnameForPersona(persona, seed)
	}
	files := append(cowrieHomeFiles(persona, seed),
		embeddedSystemFiles(persona, profile, hostname, seed)...)
	files = append(files, embeddedNetworkFiles(persona, profile, seed)...)
	stampFileTimes(files, profile, seed, time.Now())
	return cowrieFsPatchScript(files, personaHomeNames(persona, seed))
}

// generateCowrieConfig generates TPOT-compatible Cowrie config.
//
// The system identity (hostname, advertised SSH version, kernel/uname fields)
// is derived per-instance from a stable seed (the QPot ID) so it is unique to
// this deployment and internally consistent, rather than the static defaults
// every T-Pot Cowrie shares (which are themselves a fingerprint). Explicit
// stealth overrides take precedence. See deception.go for the research basis.
func (g *ComposeGenerator) generateCowrieConfig(hp config.HoneypotConfig) string {
	seed := deceptionSeed(g.Config)
	profile := cowrieProfile(hp, seed)

	hostname := hp.Stealth.FakeHostname
	if hostname == "" {
		// Derive a hostname coherent with the credential persona Cowrie will
		// enforce (see generateCowrieUserDB), so the prompt the attacker sees
		// matches the accounts that actually work - not an unrelated name from a
		// separate salt (the old "db-prod" + voip-pbx tell).
		persona := selectCredentialTemplate(hp.Stealth.CredentialTemplate, seed)
		hostname = hostnameForPersona(persona, seed)
	}

	kernel := profile.KernelVersion

	// A non-empty BannerString explicitly overrides the advertised SSH
	// version; otherwise use the per-instance profile's version (never the
	// static T-Pot default). RandomizeSSHVersion remains honored as an
	// explicit opt-in but per-instance derivation is the safe default.
	sshVersion := hp.Stealth.BannerString
	if sshVersion == "" {
		sshVersion = profile.SSHVersion
	}

	// These values are interpolated into a single line each of an INI-style
	// config. Strip control characters/newlines (and cap length) so a stealth
	// value can't inject extra config directives or break the file.
	hostname = sanitizeConfigValue(hostname)
	kernel = sanitizeConfigValue(kernel)
	sshVersion = sanitizeConfigValue(sshVersion)

	// logtype must be "plain" (or "rotating"): Cowrie's jsonlog output raises
	// ValueError on any other value, so with "json" Cowrie never wrote
	// log/cowrie.json and no Cowrie event ever reached the collector.
	return fmt.Sprintf(`[honeypot]
hostname = %s
log_path = log
logtype = plain
download_path = dl
share_path = share/cowrie
state_path = /tmp/cowrie/data
contents_path = honeyfs
ttylog = true
ttylog_path = log/tty
# Cowrie's default 180s (3 min) idle timeout disconnects an attacker who pauses
# to think or paste - a tell (real sshd does not kick idle sessions by default,
# ClientAliveInterval=0) AND it cuts data collection short. 1800s (30 min) is
# long enough to be invisible and to capture more of the session, while still
# bounding resources. authentication_timeout stays at 120s = OpenSSH's default
# LoginGraceTime, so the pre-auth window matches a real server.
interactive_timeout = 1800
authentication_timeout = 120
backend = shell
timezone = UTC
# Enforce the generated credential persona (etc/userdb.txt). The T-Pot image
# defaults to AuthRandom (accept after a random number of tries), which ignores
# userdb and makes credential behavior inconsistent - a honeypot tell and it
# means our personas would not actually be enforced. etc_path pins where
# UserDB reads userdb.txt from (the mounted etc dir).
auth_class = UserDB
etc_path = etc

[shell]
# Path to the pickled fake filesystem. QPot patches the image's base pickle at
# container start to add the persona's home directories (see cowriefs.go) and
# writes the result to the writable tmpfs /tmp/cowrie/fs.pickle, so point Cowrie
# there. The startup script always produces this file (the unchanged base pickle
# on any patch error), so the path is guaranteed populated before twistd starts;
# a missing/wrong path would make Cowrie fail to load the fs and kill the shell
# on every login - a broken honeypot the port-only healthcheck would not catch.
filesystem = /tmp/cowrie/fs.pickle
kernel_version = %s
kernel_build_string = %s
hardware_platform = %s
operating_system = %s
ssh_version = %s

[ssh]
enabled = true
# Advertise the per-instance OpenSSH banner. This is the single most-scanned
# fingerprint (Shodan/zgrab key on the SSH version string), so it MUST be the
# derived identity, not Cowrie's hardcoded default
# ("SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"), which every stock Cowrie advertises.
# The [shell] ssh_version above only changes the in-shell 'ssh -V' output; this
# [ssh] version is what a remote scanner actually sees during version exchange.
version = SSH-2.0-%s
# Normalize the SSH algorithm negotiation so the KEXINIT looks like a real modern
# OpenSSH instead of stock Cowrie. Cowrie's default lists are themselves a
# fingerprint: they advertise legacy blowfish-cbc / cast128-cbc / 3des-cbc (which
# OpenSSH has not offered by default since 7.0), a MALFORMED "hmac-sha2-56" MAC
# name (a dead giveaway - no real server sends that), and list compression with
# zlib before none. Restricting to the modern CTR ciphers + SHA-2 MACs that
# Cowrie's Twisted-conch transport actually implements (a strict subset of
# Cowrie's own supported set, so this never breaks negotiation) both removes those
# tells and shifts the server's HASSH off the well-known, widely-blocklisted
# stock-Cowrie value. NOTE: this normalizes the cipher/MAC/compression components
# of the KEXINIT; the key-exchange list and the Python transport's deeper
# packet-level behavior still differ from OpenSSH, so this RAISES the bar against
# HASSH / algorithm-list fingerprinting but does not fully defeat single-packet
# protocol fingerprinting - only HiFi proxy mode does (see doc/ssh-hifi-proxy.md).
ciphers = aes128-ctr,aes192-ctr,aes256-ctr
macs = hmac-sha2-256,hmac-sha2-512,hmac-sha1
compression = none,zlib@openssh.com
# Persist the SSH host keys in the writable, per-instance etc/ mount. Cowrie's
# default key paths are relative to its working dir, which QPot mounts read-only,
# so on first start key generation (and therefore the entire SSH service) died
# with "Read-only file system: 'ssh_host_rsa_key.pub'" and only telnet came up.
# Writing them under etc/ also keeps the host-key fingerprint STABLE across
# restarts - a host key that changes every restart is itself a honeypot tell.
rsa_public_key = etc/ssh_host_rsa_key.pub
rsa_private_key = etc/ssh_host_rsa_key
ecdsa_public_key = etc/ssh_host_ecdsa_key.pub
ecdsa_private_key = etc/ssh_host_ecdsa_key
ed25519_public_key = etc/ssh_host_ed25519_key.pub
ed25519_private_key = etc/ssh_host_ed25519_key
# Listen on the standard privileged ports (the deployment profile maps host
# ports here and grants NET_BIND_SERVICE). A real server runs SSH on 22 /
# Telnet on 23, so this is also more convincing than the 2222/2223 default.
listen_endpoints = tcp:22:interface=0.0.0.0
sftp_enabled = true
forwarding = false
auth_keyboard_interactive_enabled = false

[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = log/cowrie.json
`, hostname, kernel, profile.KernelBuildString, profile.HardwarePlatform, profile.OperatingSystem, sshVersion, sshVersion)
}

// generateConpotConfig generates TPOT-compatible Conpot config
func (g *ComposeGenerator) generateConpotConfig(hp config.HoneypotConfig) string {
	seed := deceptionSeed(g.Config)
	// A per-instance, non-self-identifying sensor_id. The stock "qpot-conpot"
	// both announced the platform and flagged the box as a honeypot; this looks
	// like an ordinary industrial asset tag and is unique per deployment.
	sensorID := sanitizeConfigValue(conpotSensorIDForSeed(seed))
	return `[common]
 sensor_id = ` + sensorID + `
 device = default

[session]
 timeout = 30

[daemon]
; local uids
 uid = 0
 gid = 0

[json]
 enabled = true
 filename = conpot.json
 device = default

[sqlite]
 enabled = false

[syslog]
 enabled = false
 device = default

[tfmt]
 device = default

[taxii]
 enabled = false
 device = default

[hibp]
 enabled = false
 api_key = 
`
}

// GetHoneypotImage returns the Docker image for a honeypot
func GetHoneypotImage(name string) string {
	// Map of honeypot names to their images (reuse TPOT images)
	images := map[string]string{
		"cowrie":         "ghcr.io/telekom-security/cowrie:24.04.1",
		"dionaea":        "ghcr.io/telekom-security/dionaea:24.04.1",
		"conpot":         "ghcr.io/telekom-security/conpot:24.04.1",
		"tanner":         "ghcr.io/telekom-security/tanner:24.04.1",
		"adbhoney":       "ghcr.io/telekom-security/adbhoney:24.04.1",
		"endlessh":       "ghcr.io/telekom-security/endlessh:24.04.1",
		"heralding":      "ghcr.io/telekom-security/heralding:24.04.1",
		"honeyaml":       "ghcr.io/telekom-security/honeyaml:24.04.1",
		"elasticpot":     "ghcr.io/telekom-security/elasticpot:24.04.1",
		"ciscoasa":       "ghcr.io/telekom-security/ciscoasa:24.04.1",
		"citrixhoneypot": "ghcr.io/telekom-security/citrixhoneypot:24.04.1",
		"ddospot":        "ghcr.io/telekom-security/ddospot:24.04.1",
		"ipphoney":       "ghcr.io/telekom-security/ipphoney:24.04.1",
		"mailoney":       "ghcr.io/telekom-security/mailoney:24.04.1",
		"medpot":         "ghcr.io/telekom-security/medpot:24.04.1",
		"dicompot":       "ghcr.io/telekom-security/dicompot:24.04.1",
		"redishoneypot":  "ghcr.io/telekom-security/redishoneypot:24.04.1",
		// Newer / 2024-2026 honeypots vendored under docker/.
		"beelzebub":  "ghcr.io/telekom-security/beelzebub:24.04.1",  // LLM SSH/HTTP/TCP
		"galah":      "ghcr.io/telekom-security/galah:24.04.1",      // LLM web
		"go-pot":     "ghcr.io/telekom-security/go-pot:24.04.1",     // HTTP tarpit
		"h0neytr4p":  "ghcr.io/telekom-security/h0neytr4p:24.04.1",  // web
		"hellpot":    "ghcr.io/telekom-security/hellpot:24.04.1",    // HTTP tarpit
		"log4pot":    "ghcr.io/telekom-security/log4pot:24.04.1",    // Log4Shell
		"miniprint":  "ghcr.io/telekom-security/miniprint:24.04.1",  // printer (JetDirect)
		"sentrypeer": "ghcr.io/telekom-security/sentrypeer:24.04.1", // SIP/VoIP
		"wordpot":    "ghcr.io/telekom-security/wordpot:24.04.1",    // WordPress
		// High-interaction SSH proxy (HiFi): the QPot-built L4 broker and the
		// real-OpenSSH backend. See docker/ssh-proxy and docker/ssh-backend.
		"ssh-proxy":   "ghcr.io/yurillab/qpot-ssh-proxy:latest",
		"ssh-backend": "ghcr.io/yurillab/qpot-ssh-backend:latest",
	}

	if img, ok := images[name]; ok {
		return img
	}

	return fmt.Sprintf("qpot/%s:latest", name)
}

// ValidateHoneypot checks if a honeypot is supported
func (g *ComposeGenerator) ValidateHoneypot(name string) error {
	supported := []string{
		"cowrie", "dionaea", "conpot", "tanner", "adbhoney",
		"endlessh", "heralding", "honeyaml", "elasticpot",
		"ciscoasa", "citrixhoneypot", "ddospot", "ipphoney",
		"mailoney", "medpot", "dicompot", "redishoneypot",
		"beelzebub", "galah", "go-pot", "h0neytr4p", "hellpot",
		"log4pot", "miniprint", "sentrypeer", "wordpot",
		"ssh-proxy",
	}

	for _, s := range supported {
		if s == name {
			return nil
		}
	}

	return fmt.Errorf("unsupported honeypot: %s (supported: %s)",
		name, strings.Join(supported, ", "))
}

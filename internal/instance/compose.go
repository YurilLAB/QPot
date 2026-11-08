// Package instance handles Docker Compose generation
package instance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/refrigeration"
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
// yamlInterpolatedStr renders s as a double-quoted YAML scalar (JSON string
// syntax is valid YAML) with '$' doubled, because both docker compose and
// Vector expand $VAR / ${VAR} in their files. Used for operator-supplied
// values such as the database user, password and name, which may contain
// YAML-significant characters (": ", "#", leading "!" or "&", quotes) or '$'.
func yamlInterpolatedStr(s string) string {
	b, _ := json.Marshal(s)
	return strings.ReplaceAll(string(b), "$", "$$")
}

// shellQuote single-quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// pgReadyCommand is the TimescaleDB healthcheck command line.
func pgReadyCommand(user, db string) string {
	return yamlInterpolatedStr("pg_isready -U " + shellQuote(user) + " -d " + shellQuote(db))
}

// postgresDSN builds the collector's connection URL with the credentials and
// database name properly escaped ('@', '/', '#', ':' etc. in a password used to
// break the URL).
func postgresDSN(user, password, db string) string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: "database:5432", Path: "/" + db}
	return yamlInterpolatedStr(u.String())
}

func vrlStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		// Drop C0 controls (incl. CR/LF/TAB), DEL, and C1 controls (0x80-0x9f).
		// YAML rejects these inside the block scalar that holds the VRL filter,
		// as it does U+FFFE and U+FFFF; libyaml-based parsers end the line at
		// U+2028 and U+2029, and a BOM inside a document is not reliably kept.
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || r == 0xfeff || r == 0xfffe || r == 0xffff {
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
	if g.Config.WebUI.Enabled && g.Config.WebUI.Port > 0 {
		used[g.Config.WebUI.Port] = true
	}
	for p := range g.ReservedPorts {
		used[p] = true
	}
	if g.Config.Ports.AutoAllocate {
		for _, infra := range []int{9000, 8123, 5432} {
			used[g.Config.AllocatePort(infra)] = true
		}
		used[g.databaseHostPort()] = true
	}

	names := make([]string, 0, len(g.Config.Honeypots))
	for name, hp := range g.Config.Honeypots {
		if hp.Enabled {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	containerPorts := func(name string) []int {
		tcp, udp := deployPorts(g.Config, name)
		ports := append(append([]int{}, tcp...), udp...)
		if len(ports) == 0 {
			ports = []int{g.Config.Honeypots[name].Port}
		}
		return ports
	}

	assign := make(map[string]int)
	// A pair keeps the host port it has in the compose file in use (KeepPorts)
	// before anything new is placed: a change to one honeypot's ports (a
	// Conpot template, a honeypot enabled) otherwise moved another's, which
	// kept running on its old port until recreated, and the honeypot that now
	// wanted that port could not start.
	if g.Config.Ports.AutoAllocate {
		for _, name := range names {
			for _, p := range containerPorts(name) {
				key := portKey(name, p)
				kept, ok := g.KeepPorts[key]
				if _, done := assign[key]; done || !ok || used[kept] || kept < base || kept >= base+rangeSize {
					continue
				}
				used[kept] = true
				assign[key] = kept
			}
		}
	}
	for _, name := range names {
		for _, p := range containerPorts(name) {
			key := portKey(name, p)
			if _, ok := assign[key]; ok {
				continue // kept, or TCP+UDP on the same number sharing one host port
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

// databaseHostPort is the host port the database is published on: the one
// the compose file in use gives it (KeepPorts), else the instance's default,
// moved up past the ports other instances publish (ReservedPorts). The
// default alone is a hash of the instance name, so a sibling whose name
// hashed alike, or whose honeypot sat on it, made the second `qpot up` fail
// to bind it. config.DatabaseHostPort reads the port back from the file.
func (g *ComposeGenerator) databaseHostPort() int {
	p := g.Config.DefaultDatabaseHostPort()
	if !g.Config.Ports.AutoAllocate {
		return p
	}
	if kept := g.KeepPorts[portKey("database", g.Config.DatabaseContainerPort())]; kept > 0 && !g.ReservedPorts[kept] {
		return kept
	}
	for g.ReservedPorts[p] && p < 65535 {
		p++
	}
	return p
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
	// KeepPorts are the host ports of the compose file in use, by portKey
	// (see ownHostPorts): pairs that still exist keep them.
	KeepPorts map[string]int
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
	if tannerEnabled(g.Config) {
		names = append(names, "tanner_backend")
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
	if d.NoShell {
		return "" // no shell to run it; the host probes the published ports
	}
	ports := d.Ports
	if len(d.HealthPorts) > 0 {
		ports = d.HealthPorts
	}
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
	if hp, ok := g.Config.GetHoneypotConfig("refrigeration"); ok && hp.Enabled {
		if err := CheckSetting("refrigeration", "site_profile", refrigerationSiteProfile(g.Config)); err != nil {
			return "", err
		}
	}
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
{{end}}{{if tannerEnabled .Config}}
  # tanner's server, API, PHP sandbox (phpox executes attacker-supplied PHP)
  # and redis sit here with no default gateway: nothing in the stack can make
  # outbound connections. Only snare also joins tanner_net to serve attackers.
  tanner_backend:
    internal: true
    ipam:
      config:
        - subnet: {{netSubnet "tanner_backend"}}
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
    image: {{clickhouseImage}}
    container_name: {{.Config.InstanceName}}_db
    restart: unless-stopped
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    environment:
      CLICKHOUSE_DB: {{yamlStr .Config.Database.Database}}
      CLICKHOUSE_USER: {{yamlStr .Config.Database.Username}}
      CLICKHOUSE_PASSWORD: {{yamlStr .Config.Database.Password}}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - {{.Config.GetDatabasePath}}:/var/lib/clickhouse
      - {{.Config.DataPath}}/clickhouse-config:/etc/clickhouse-server/conf.d
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "127.0.0.1:{{databaseHostPort}}:9000"
    networks:
      - qpot_internal
      - qpot_dbhost
    {{template "dbsecurity" dict "Config" $.Config "GlobalLimits" $.Config.Security.ResourceLimits "Name" "database"}}
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8123/ping"]
      interval: 10s
      timeout: 5s
      retries: 3
      # First boot initialises the data directory and restarts the server;
      # on a busy host that outlasts 3 x 10s. Failures during start_period do
      # not count, so dependants (the collector) wait instead of failing.
      start_period: 2m
{{else if eq .Config.Database.Type "timescaledb"}}database:
    image: {{timescaleImage}}
    container_name: {{.Config.InstanceName}}_db
    restart: unless-stopped
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    environment:
      POSTGRES_DB: {{yamlStr .Config.Database.Database}}
      POSTGRES_USER: {{yamlStr .Config.Database.Username}}
      POSTGRES_PASSWORD: {{yamlStr .Config.Database.Password}}
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - {{.Config.GetDatabasePath}}:/var/lib/postgresql/data
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "127.0.0.1:{{databaseHostPort}}:5432"
    networks:
      - qpot_internal
      - qpot_dbhost
    {{template "dbsecurity" dict "Config" $.Config "GlobalLimits" $.Config.Security.ResourceLimits "Name" "database"}}
    healthcheck:
      test: ["CMD-SHELL", {{pgReadyCmd .Config.Database.Username .Config.Database.Database}}]
      interval: 10s
      timeout: 5s
      retries: 3
      # First boot initialises the data directory and restarts the server;
      # on a busy host that outlasts 3 x 10s. Failures during start_period do
      # not count, so dependants (the collector) wait instead of failing.
      start_period: 2m
{{end}}

  # Log collector (Vector) with QPot ID tagging
  collector:
    image: {{collectorImage}}
    container_name: {{.Config.InstanceName}}_collector
    restart: unless-stopped
{{- if or (eq .Config.Database.Type "clickhouse") (eq .Config.Database.Type "timescaledb")}}
    # Start once the database accepts connections: before that the sink's
    # healthcheck fails and early events are dropped.
    depends_on:
      database:
        condition: service_healthy
{{- end}}
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
      # Only the folders the collector reads, read-only, and its writable
      # backup folder; never the whole instance folder (see collectorMounts).
{{- range collectorMounts .Config}}
      - {{.Host}}:{{.Container}}{{if .ReadOnly}}:ro{{end}}
{{- end}}
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    networks:
      - qpot_internal
    cap_add:
      - DAC_READ_SEARCH
{{- $eg := egressGuard .Config}}
{{- if $eg.Enabled}}

  # Egress guard (cmd/qpot-netguard): an nftables table in the host's network
  # namespace that stops the honeypot bridges below from opening connections
  # to private, loopback, link-local (cloud metadata), CGNAT and multicast
  # addresses and to the docker host ({{$eg.Mode}} mode; "all" blocks every
  # outbound connection). Replies to attackers and DNS to the host's resolvers
  # still pass. It needs the host's network namespace and CAP_NET_ADMIN, and
  # nothing else; it publishes no port and joins no QPot network. Honeypots
  # start only once its check passes, and it re-applies the table on an
  # interval. Turn it off with security.network_isolation.allow_private_egress.
  netguard:
    image: {{$eg.Image}}
    container_name: {{.Config.InstanceName}}_netguard
    restart: unless-stopped
    entrypoint: ["/qpot-netguard"]
    command: ["run"]
    user: "0:0"
    network_mode: host
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    labels:
      qpot.instance: "{{.Config.InstanceName}}"
    environment:
      QPOT_NETGUARD_TABLE: "{{$eg.Table}}"
      QPOT_NETGUARD_IFACES: "{{$eg.Ifaces}}"
      QPOT_NETGUARD_MODE: "{{$eg.Mode}}"
    healthcheck:
      test: ["CMD", "/qpot-netguard", "check"]
      interval: 15s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "1m"
        max-file: "2"
{{- end}}

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
{{if tannerEnabled .Config}}{{range $c := tannerCompanions}}
  # tanner stack companion ({{$c.Role}}); see the tanner deploy profile.
  {{$c.Service}}:
    image: {{$c.Image}}
    container_name: {{$.Config.InstanceName}}_{{$c.Service}}
    restart: on-failure:{{$.Config.Security.ResourceLimits.RestartAttempts}}
    tty: true
    {{- if $c.Public}}
    {{- $eg := egressGuard $.Config}}
    {{- if $eg.Enabled}}
    # Not before the egress guard's table is in place.
    depends_on:
      netguard:
        condition: service_healthy
    {{- end}}
    {{- end}}
    {{- if $c.Command}}
    command: {{$c.Command}}
    {{- end}}
    {{- if $.Sandbox.ContainerRuntime}}
    runtime: {{$.Sandbox.ContainerRuntime}}
    {{- end}}
    {{- if $c.Public}}
    ports:
      - "{{hostPort "tanner" 80}}:80"
    {{- end}}
    networks:
      - tanner_backend
    {{- if $c.Public}}
      - tanner_net
    {{- end}}
    {{- if $c.Logs}}
    volumes:
      - {{$.Config.DataPath}}/honeypots/tanner/logs:/var/log/tanner
    {{- end}}
    {{- if $c.Tmpfs}}
    tmpfs:
      - {{$c.Tmpfs}}
    {{- end}}
    {{- if $c.ReadOnly}}
    read_only: true
    {{- end}}
    labels:
      qpot.instance: "{{$.Config.InstanceName}}"
      qpot.honeypot: "tanner"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    deploy:
      resources:
        limits:
          cpus: '{{divf $.Config.Security.ResourceLimits.MaxCPUPercent 100}}'
          memory: {{$.Config.Security.ResourceLimits.MaxMemoryMB}}M
          {{if $.Config.Security.ResourceLimits.MaxPids}}pids: {{$.Config.Security.ResourceLimits.MaxPids}}{{end}}
    mem_swappiness: 0
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
    {{- $d := deployFor .Name}}
    image: {{GetHoneypotImage .Name}}
    {{- if $d.LocalBuild}}
    build:
      context: {{yamlStr (refrigerationBuildPath $.Config)}}
      dockerfile: Dockerfile
    pull_policy: build
    {{- end}}
    container_name: {{$.Config.InstanceName}}_{{.Name}}
    restart: on-failure:{{$.Config.Security.ResourceLimits.RestartAttempts}}
    {{- $eg := egressGuard $.Config}}
    {{- if $eg.Enabled}}
    # Not before the egress guard's table is in place.
    depends_on:
      netguard:
        condition: service_healthy
    {{- end}}
    {{- if $.Config.Security.NetworkIsolation.RandomizeMAC}}
    # Stable, locally-administered MAC per (instance, honeypot) so containers do
    # not all share Docker's default vendor prefix / a predictable address.
    mac_address: {{macFor $.Config.InstanceName .Name}}
    {{- end}}
    {{if $.Sandbox.ContainerRuntime}}# Stronger isolation runtime (gVisor/Kata) for this attacker-facing container
    runtime: {{$.Sandbox.ContainerRuntime}}
    {{end}}
    {{- $hpName := .Name}}
    {{- if eq .Name "conpot"}}
    # Preserve the image launcher while avoiding duplicate proxy env names
    # rejected by its case-insensitive ConfigParser.
    command: ["/bin/sh", "-c", {{yamlStr (conpotStart)}}]
    {{- end}}
    {{- if not $d.Internal}}
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
    {{- end}}
    volumes:
      # The QPot ID (the API credential) is deliberately NOT mounted or passed
      # to honeypot containers — they run attacker-controlled workloads, so a
      # honeypot RCE must not yield the management-API credential. Log tagging is
      # done by the Vector collector. Mounts below come from the per-honeypot
      # deployment profile (deploy.go), derived from T-Pot's reference composes
      # and verified by running the images.
    {{- range $v := $d.Volumes}}
      - {{$.Config.DataPath}}/honeypots/{{$.Name}}/{{$v.HostSubdir}}:{{$v.ContainerPath}}{{if $v.ReadOnly}}:ro{{end}}
    {{- end}}
    networks:
      # Only its own network: the collector reads the honeypot's logs from the
      # bind mounts above, so nothing on qpot_internal (the database, the
      # collector) is reachable from a container that runs attacker input.
      - {{.Name}}_net
    {{- if eq .Name "ssh-proxy"}}
      # The broker also joins the egress-locked backend network so it can reach
      # the real-OpenSSH backends (and nothing else can).
      - ssh-proxy_backend
    {{- end}}
    {{- if eq .Name "tanner"}}
      # The tanner server talks to its api/phpox/redis companions only there.
      - tanner_backend
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
      # host-side labels above. The stealth knobs (FAKE_OS, BANNER_STRING,
      # RANDOMIZE_SSH_VERSION, ...) went the same way: no image reads them, so
      # all they did was spell out "honeypot" in /proc/1/environ. Only values an
      # image actually reads remain.
      - LOG_LEVEL=info
      {{- if eq .Name "cowrie"}}
      # The persona the image's launcher renders Cowrie as (see deception.go),
      # and how many days it keeps the identity it drew across restarts.
      - COWRIE_PERSONA={{cowriePersona $.Config}}
      - COWRIE_PERSONA_ROTATION={{cowriePersonaRotation $.Config}}
      {{- end}}
      {{- if eq .Name "ssh-proxy"}}
      # HiFi broker: the operator-fixed backend pool (never attacker-derived, so
      # no SSRF) and the logical name used in the broker's session events.
      - QPOT_SSHPROXY_NAME=ssh-proxy
      - QPOT_SSHPROXY_BACKENDS={{sshBackendCSV $.Config}}
      - QPOT_SSHPROXY_GENERATIONS={{sshProxyGenerationsPath}}
      {{- end}}
      {{- range $k, $v := $d.Env}}
      - {{$k}}={{$v}}
      {{- end}}
      {{- range $k, $env := $d.LLMEnv}}{{with index $.HP.CustomConfig $k}}
      - {{envEntry $env .}}
      {{- end}}{{end}}
    {{template "security" dict "Config" $.Config "HP" .HP "GlobalLimits" $.Config.Security.ResourceLimits "Name" .Name "FakeHostname" .HP.Stealth.FakeHostname}}
    {{- if $d.NoShell}}
    # The image has no shell, so no in-container check can run (an image
    # HEALTHCHECK would fail forever); qpot setup/doctor probe the published
    # ports from the host instead.
    healthcheck:
      disable: true
    {{- else if ne .Name "ssh-proxy"}}
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
      - SETGID
      # The ClickHouse entrypoint starts a temporary server as the clickhouse
      # user to initialise a fresh data dir and then stops it from root; with
      # every capability dropped that kill is refused, init fails and the
      # container restarts (and is reported unhealthy) on first boot.
      - KILL{{end}}

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
    {{- if not $dep.NoCapabilities}}
    cap_add:
      - SETUID
      - SETGID
      {{if or $dep.NeedsNetBind (and .HP.Port (lt .HP.Port 1024))}}- NET_BIND_SERVICE{{end}}{{range $dep.ExtraCaps}}
      - {{.}}{{end}}{{end}}{{end}}

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
	if g.Config.WebUI.Enabled && g.Config.WebUI.Port > 0 {
		for key, port := range hostPortMap {
			if port == g.Config.WebUI.Port {
				name, _, _ := strings.Cut(key, "\x00")
				return "", fmt.Errorf("honeypot %s would publish the management web port %d; enable ports.auto_allocate or change web_ui.port", name, port)
			}
		}
	}
	subnetMap := g.buildSubnetMap()
	dbHostPort := g.databaseHostPort()

	funcMap := template.FuncMap{
		"yamlStr":                 yamlInterpolatedStr,
		"conpotStart":             conpotStartScript,
		"databaseHostPort":        func() int { return dbHostPort },
		"sshProxyGenerationsPath": func() string { return sshProxyGenerationsPath },
		"pgReadyCmd":              pgReadyCommand,
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
		"GetHoneypotImage":       GetHoneypotImage,
		"clickhouseImage":        func() string { return ClickHouseImage },
		"timescaleImage":         func() string { return TimescaleDBImage },
		"collectorImage":         func() string { return CollectorImage },
		"collectorMounts":        collectorMounts,
		"refrigerationBuildPath": refrigerationBuildPath,
		"subnetFor":              subnetForNetwork,
		"bridgeName":             bridgeName,
		"macFor":                 macForSeed,
		"deployFor":              func(name string) honeypotDeploy { return deployProfile(g.Config, name) },
		"egressGuard":            egressGuardFor,
		// listenCheck builds the container healthcheck command, probing the actual
		// INTERNAL listen ports from the deploy profile (not the host/config port)
		// via /proc/net so it needs no netstat/ss. See listenHealthCheck.
		"listenCheck": listenHealthCheck,
		// HiFi SSH proxy helpers (see sshproxy.go): whether the ssh-proxy honeypot
		// is enabled, the real-OpenSSH backend companion services to render, and
		// the broker's QPOT_SSHPROXY_BACKENDS value.
		"sshProxyEnabled":    sshProxyEnabled,
		"tannerEnabled":      tannerEnabled,
		"tannerCompanions":   tannerCompanions,
		"sshProxyBackends":   sshProxyBackends,
		"sshBackendCSV":      sshBackendCSV,
		"sshBackendHostname": sshBackendHostname,
		// Cowrie's persona and identity lifetime (see deception.go).
		"cowriePersona":         cowriePersona,
		"cowriePersonaRotation": cowriePersonaRotation,
		// hostnameSafe reduces an operator-set fake hostname to valid hostname
		// characters before it is interpolated into the YAML `hostname:` field,
		// so a stray quote/newline can never break the compose.
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

// HoneypotsEnabled reports whether any honeypot is enabled, i.e. whether the
// add_qpot_metadata transform has inputs.
func (g *ComposeGenerator) HoneypotsEnabled() bool {
	return len(g.Config.GetEnabledHoneypots()) > 0
}

// StealthInputs lists what feeds filter_stealth: enrich_geoip when GeoIP is
// configured, else the honeypot transform (if any honeypot is enabled) plus
// the NSM sensor transforms.
func (g *ComposeGenerator) StealthInputs() []string {
	if g.Config.Collector.GeoIPDBPath != "" {
		return []string{"enrich_geoip"}
	}
	return g.pipelineInputs()
}

// pipelineInputs are the event transforms: honeypots (if any) and sensors.
func (g *ComposeGenerator) pipelineInputs() []string {
	var in []string
	if g.HoneypotsEnabled() {
		in = append(in, "add_qpot_metadata")
	}
	return append(in, g.EnabledSensors()...)
}

// GeoIPInputs lists what feeds enrich_geoip.
func (g *ComposeGenerator) GeoIPInputs() []string { return g.pipelineInputs() }

// idleVectorConfig is used when there is nothing to collect (no honeypot and
// no sensor enabled). Vector refuses a config without sources, and a
// transform without inputs, so this keeps the collector running idle instead
// of crash-looping.
const idleVectorConfig = `# Vector configuration for QPot
# Auto-generated: no honeypot or sensor is enabled, nothing to collect.
data_dir: "/var/lib/vector"
api:
  enabled: true
  address: "127.0.0.1:8686"
sources:
  idle_metrics:
    type: internal_metrics
sinks:
  idle_sink:
    type: blackhole
    inputs:
      - idle_metrics
`

// GenerateVectorConfig generates Vector configuration for log collection
func (g *ComposeGenerator) GenerateVectorConfig() (string, error) {
	if len(g.pipelineInputs()) == 0 {
		return idleVectorConfig, nil
	}
	config := `# Vector configuration for QPot
# QPot ID: {{.Config.QPotID}}
# Auto-generated

data_dir: "/var/lib/vector"

api:
  enabled: true
  address: "127.0.0.1:8686"
{{if .Config.Collector.GeoIPDBPath}}
enrichment_tables:
  # "mmdb" reads any MaxMind-format database (GeoLite2 City/Country,
  # DB-IP Lite) and returns its raw record; Vector's "geoip" type rejects
  # DB-IP files and flattens the record into different field names.
  qpot_geoip:
    type: "mmdb"
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
{{- if .HoneypotsEnabled}}
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

      # Honeypots that name the attacker's address differently (field names
      # as in T-Pot's own Logstash pipeline) are mapped onto src_ip/src_port.
      if hp == "tanner" {
        .src_ip = .peer.ip
        .src_port = .peer.port
        .protocol = "http"
        .url = .path
        if is_string(.method) {
          .eventid = "tanner.http." + downcase(string!(.method))
        }
      } else if hp == "dicompot" {
        .src_ip = .IP
        .src_port = .Port
        .input = .Command
      } else if hp == "ddospot" {
        # A reflection attack's "target" is the (spoofed) source of the
        # requests, i.e. the address the packets came from.
        .src_ip = .target_ip
        .src_port = .target_port
        .protocol = .proto
        pot = to_string(.pot) ?? ""
        dev = to_string(.event) ?? ""
        if pot == "" {
          pot = "udp"
        }
        if dev == "" {
          dev = "request"
        }
        .eventid = "ddospot." + pot + "." + dev
        .payload = .dns_name
      } else if hp == "hellpot" {
        .src_ip = .REMOTE_ADDR
        .url = .URL
        .protocol = "http"
      } else if hp == "log4pot" {
        .src_ip = .client
        .src_port = .port
        .dest_port = .server_port
        .protocol = "http"
      } else if hp == "citrixhoneypot" {
        cm, cerr = parse_regex(to_string(.message) ?? "", r'^\((?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+)\): (?P<rest>.*)$')
        if cerr == null {
          .src_ip = cm.ip
          .src_port = cm.port
          .payload = cm.rest
          .protocol = "https"
          .eventid = "citrixhoneypot.http.request"
        }
      } else if hp == "galah" {
        .url = get(., ["request.requestURI"]) ?? null
        .protocol = "http"
      } else if hp == "mailoney" {
        mev = to_string(get(., ["event.type"]) ?? null) ?? ""
        if mev == "" {
          mev = "session"
        }
        .eventid = "mailoney." + mev
        .input = .smtp_input
        .protocol = "smtp"
      } else if hp == "redishoneypot" && is_string(.command) {
        .input = strip_whitespace(string!(.command) + " " + (to_string(.args_text) ?? ""))
      } else if hp == "sentrypeer" {
        .protocol = "sip"
        if is_string(.sip_method) {
          .eventid = "sentrypeer.sip." + downcase(string!(.sip_method))
        }
      } else if hp == "go-pot" || hp == "honeyaml" || hp == "wordpot" {
        if is_string(.method) {
          .eventid = hp + ".http." + downcase(string!(.method))
        }
        q = to_string(.qs) ?? to_string(.query_string) ?? to_string(.query) ?? ""
        if is_string(.path) {
          .url = string!(.path)
          if q != "" {
            .url = string!(.path) + "?" + q
          }
        }
        .protocol = "http"
      } else if hp == "beelzebub" || hp == "h0neytr4p" {
        .url = .request_uri
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
      # A line with no attacker address at all is a startup banner, error or
      # state record (log4pot "start", hellpot "Listening", wordpot's profile
      # state, dicompot's connection-finished line), not an attack.
      if sip == "" {
        abort
      }
      # "ip:port" in one field (sentrypeer, older redishoneypot).
      if !(ip_cidr_contains("0.0.0.0/0", sip) ?? false) && !(ip_cidr_contains("::/0", sip) ?? false) {
        am, aerr = parse_regex(sip, r'^\[?(?P<ip>[0-9a-fA-F:.]+?)\]?:(?P<port>\d{1,5})$')
        if aerr == null {
          sip = replace(string!(am.ip), r'^::ffff:', "")
          if (to_int(.src_port) ?? 0) == 0 {
            .src_port = am.port
          }
        }
      }
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
      # Honeypots that do not log the port they listen on (as T-Pot adds it).
      if dp == 0 {
        dp = to_int(get({"tanner": 80, "hellpot": 80, "endlessh": 22, "citrixhoneypot": 443, "medpot": 2575, "dicompot": 11112, "sentrypeer": 5060, "redishoneypot": 6379, "mailoney": 25, "refrigeration": 8080}, [hp]) ?? 0) ?? 0
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
      # current conpot "protocol", legacy conpot "data_type".
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
      # Conpot's current image logs protocol plus nested data, whereas older
      # logs use data_type. Connection events retain their original names.
      conpot_fc = -1
      conpot_unit = -1
      conpot_operation = ""
      if et == "" && hp == "conpot" {
        orig = downcase(to_string(.event_type) ?? "")
        orig = replace(orig, r'[^a-z0-9_.]+', "_")
        orig = truncate(replace(orig, r'^_+|_+$', ""), 64)
        dt = .protocol
        if dt == "" {
          dt = "unknown"
        }
        if dt == "modbus" {
          if is_integer(.data.function_code) {
            conpot_fc = to_int(.data.function_code) ?? -1
          }
          if conpot_fc < 0 || conpot_fc > 127 { conpot_fc = -1 }
          if is_integer(.data.slave_id) {
            conpot_unit = to_int(.data.slave_id) ?? -1
          }
          if conpot_unit < 0 || conpot_unit > 255 { conpot_unit = -1 }
          if orig == "" || orig == "request" {
            # A read is not an unauthorized control command. Diagnostics and
            # unknown function codes remain requests rather than guessed writes.
            if includes([1, 2, 3, 4, 7, 11, 12, 17, 20, 24, 43], conpot_fc) {
              orig = "read"
              conpot_operation = "read"
            } else if includes([5, 6, 15, 16, 21, 22, 23], conpot_fc) {
              orig = "command"
              conpot_operation = "write"
            } else {
              orig = "request"
            }
          }
        } else if dt == "dnp3" && orig == "request" && upcase(to_string(.request) ?? "") == "READ" {
          orig = "read"
          conpot_operation = "read"
        }
        if orig != "" {
          et = "conpot." + dt + "." + orig
        } else if .request != null && includes(["s7comm", "bacnet", "enip", "ipmi", "iec104", "guardian_ast", "kamstrup_protocol", "kamstrup_management_protocol", "ads", "opcua", "opc_ua", "hart_ip", "hart", "knx", "iccp", "dnp3"], dt) {
          et = "conpot." + dt + ".request"
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
      if hp == "refrigeration" {
        # Native events describe the emulator's observations and outcomes.
        # A successful write changes simulated state only; it is not evidence
        # of a physical process change or an attributed attack campaign.
        native_event = to_string(.event_type) ?? ""
        if includes(["refrigeration.auth.failed", "refrigeration.auth.success", "refrigeration.read", "refrigeration.write.attempt", "refrigeration.write.success", "refrigeration.write.denied", "refrigeration.malformed", "refrigeration.exploit.attempt", "refrigeration.export", "refrigeration.alarm", "refrigeration.overload"], native_event) {
          et = native_event
        } else {
          et = "refrigeration.request"
        }
      }
      # Otherwise name it after the honeypot's own event/message field,
      # prefixed with the honeypot (ciscoasa "error" -> ciscoasa.error,
      # beelzebub "New TCP attempt" -> beelzebub.new_tcp_attempt).
      if et == "" {
        for_each(["event_type", "event", "action", "reason", "msg", "message"]) -> |_i, k| {
          v = get(., [k]) ?? null
          # .message is the raw line when the honeypot has no such key.
          if et == "" && is_string(v) && strip_whitespace(string!(v)) != "" && string!(v) != raw {
            slug = replace(downcase(string!(v)), r'[^a-z0-9_.]+', "_")
            slug = replace(slug, r'^_+|_+$', "")
            if slug != "" {
              et = hp + "." + truncate(slug, 64)
            }
          }
        }
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
      if hp == "refrigeration" {
        .username = truncate(user, 256)
        .password = truncate(pass, 256)
      }

      # Attacker input: cowrie/adbhoney log commands as "input".
      cmd = ""
      if is_string(.input) {
        cmd = string!(.input)
      } else if is_string(.command) {
        cmd = string!(.command)
      }
      .command = cmd
      if hp == "refrigeration" { .command = "" }

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
      if hp == "refrigeration" { .payload = truncate(pl, 4096) }

      # metadata is Map(String, String) / JSONB: rebuild it from a fixed set
      # of string-coerced keys so an odd honeypot field type can never make the
      # whole batch fail to insert. fingerprint and key are the public key a
      # cowrie login offered (a stolen canary key trips on them), realm what
      # a typed line answered (ssh's prompts, aws configure).
      md = {}
      for_each(["session", "session_id", "sensor", "dst_ip", "dest_ip", "destination_ip", "version", "hassh", "shasum", "outfile", "filename", "duration", "num_auth_attempts", "backend", "reason", "fingerprint", "key", "realm"]) -> |_i, k| {
        v = get(., [k]) ?? null
        if v != null {
          sv = to_string(v) ?? ""
          if sv != "" {
            md = set!(md, [k], sv)
          }
        }
      }
      if hp == "conpot" {
        # Keep the profile from this log event, not today's configured profile:
        # buffered events can belong to the device used before a profile change.
        profile = to_string(.template) ?? ""
        if includes([{{range $i, $id := conpotIDs}}{{if $i}}, {{end}}{{vrlStr $id}}{{end}}], profile) {
          md.device_profile = profile
        }
        if conpot_fc >= 0 { md.function_code = to_string(conpot_fc) }
        if conpot_unit >= 0 { md.unit_id = to_string(conpot_unit) }
        if conpot_operation != "" { md.operation = conpot_operation }
        response = downcase(to_string(.response) ?? "")
        if .protocol == "modbus" && match(response, r'^b\x27[89a-f][0-9a-f][0-9a-f]{2}\x27$') {
          md.exception_code = slice!(response, 4, 6)
        }
      }
      if hp == "refrigeration" {
        # Copy a finite schema, never arbitrary input metadata or response
        # content. Maintenance exports contain decoy credentials, so logging
        # the response would falsely report their reuse as a canary trip.
        md = {}
        for_each(["action", "method", "path", "device_id", "success"]) -> |_i, k| {
          v = get(., [k]) ?? null
          if is_string(v) || is_boolean(v) || is_integer(v) {
            md = set!(md, [k], truncate(to_string(v) ?? "", 256))
          }
        }
        for_each(["profile", "site_profile", "model", "firmware", "role", "reason", "result", "parameter", "value", "previous_value", "outcome"]) -> |_i, k| {
          v = get(., ["metadata", k]) ?? null
          if is_string(v) || is_boolean(v) || is_integer(v) || is_float(v) {
            md = set!(md, [k], truncate(to_string(v) ?? "", 256))
          }
        }
        # HTTP request targets and selected client headers are observations
        # too. Keep the decoded query alongside the exact target so encoded
        # credential reuse can be watched without interpreting it as a CVE.
        if is_string(.metadata.request_uri) {
          md.request_uri = truncate(string!(.metadata.request_uri), 2048)
        }
        if is_string(.metadata.query) {
          md.query = truncate(string!(.metadata.query), 1024)
        }
        if is_string(.metadata.user_agent) {
          md.user_agent = truncate(string!(.metadata.user_agent), 512)
        }
        md.state_scope = "simulated"
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
      del(.categories)
      del(.country)
      del(.city)
      del(.asn)

      # Stamp QPot metadata LAST. The timestamp is formatted as ClickHouse's
      # DateTime64 'basic' input format ("YYYY-MM-DD HH:MM:SS.fff"); a raw
      # RFC3339 value (with T/Z) is rejected by the JSONEachRow parser (400).
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{- end}}
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
{{- range $.GeoIPInputs}}
      - {{.}}
{{- end}}
    source: |
      # GeoIP enrichment from the configured MaxMind-format database
      if exists(.source_ip) && .source_ip != "0.0.0.0" && .source_ip != "127.0.0.1" {
        enriched, err = get_enrichment_table_record("qpot_geoip", {"ip": .source_ip})
        if err == null {
          # A country database has no city; keep the columns strings.
          .country = to_string(enriched.country.iso_code) ?? ""
          .city = to_string(enriched.city.names.en) ?? ""
          .asn = to_string(enriched.autonomous_system_number) ?? ""
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
{{- range $.StealthInputs}}
      - {{.}}
{{- end}}
    condition: |
      # Drop events whose message contains a known scanner signature (stealth).
      # Substring match via contains() — match_any expects regexes, and
      # contains avoids regex-escaping the operator-supplied probe strings.
      # NSM sensor events (Suricata/p0f/fatt) are never stealth-filtered:
      # dropping an IDS alert or a fingerprint because its JSON mentions a
      # scanner signature would discard real sensor data.
      {{- if and .Config.Stealth.BlockCommonProbes .Config.Stealth.BlockedProbes}}
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
    # This endpoint is always the instance's internal Docker service. Docker
    # client proxy defaults must not route event batches outside that network.
    proxy:
      enabled: false
    database: {{yamlStr .Config.Database.Database}}
    table: events
    # The enriched event carries fields that are not columns in the events
    # table (qpot_id, the honeypot's own eventid/session/etc.). Without this,
    # ClickHouse rejects the whole insert on the first unknown column and all
    # events are dropped. qpot_id is re-attached by the API at read time.
    skip_unknown_fields: true
    auth:
      strategy: basic
      user: {{yamlStr .Config.Database.Username}}
      password: {{yamlStr .Config.Database.Password}}
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
    endpoint: {{pgDSN .Config.Database.Username .Config.Database.Password .Config.Database.Database}}
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
		"vrlStr":    vrlStringLiteral,
		"yamlStr":   yamlInterpolatedStr,
		"pgDSN":     postgresDSN,
		"conpotIDs": ConpotTemplateIDs,
	}).Parse(config))

	var buf bytes.Buffer
	if err := t.Execute(&buf, g); err != nil {
		return "", fmt.Errorf("failed to execute vector template: %w", err)
	}

	return buf.String(), nil
}

// collectorMount is one bind mount of the collector (Vector) container.
type collectorMount struct {
	Host, Container string
	ReadOnly        bool
	// Dir is set when Host is a folder QPot must create before starting:
	// Docker would create a missing one owned by root.
	Dir bool
}

// collectorMounts lists the instance folders the collector reads, read-only,
// and its writable backup folder. It never mounts the whole instance folder,
// which also holds the database password, canary tokens and keys: Vector
// parses attacker-written logs and follows the symlinks that a compromised
// honeypot can plant in its own logs folder.
func collectorMounts(cfg *config.Config) []collectorMount {
	mounts := []collectorMount{{Host: cfg.DataPath + "/honeypots", Container: "/data/honeypots", ReadOnly: true, Dir: true}}
	covered := []string{"honeypots", "backup"}
	c := cfg.Collector
	for _, s := range []struct {
		on  bool
		dir string
	}{{c.IngestSuricata, "suricata/log"}, {c.IngestP0f, "p0f/log"}, {c.IngestFatt, "fatt/log"}} {
		if s.on {
			mounts = append(mounts, collectorMount{Host: cfg.DataPath + "/" + s.dir, Container: "/data/" + s.dir, ReadOnly: true, Dir: true})
			covered = append(covered, s.dir)
		}
	}
	// The GeoIP setting is a path inside the collector; under /data/ it names
	// a file in the instance folder (qpot geoip puts it in geoip/).
	if rest, ok := strings.CutPrefix(path.Clean(c.GeoIPDBPath), "/data/"); ok {
		dir := path.Dir(rest)
		inside := false
		for _, cv := range covered {
			if dir == cv || strings.HasPrefix(dir, cv+"/") {
				inside = true
			}
		}
		switch {
		case inside:
		case dir == ".":
			mounts = append(mounts, collectorMount{Host: cfg.DataPath + "/" + rest, Container: "/data/" + rest, ReadOnly: true})
		default:
			mounts = append(mounts, collectorMount{Host: cfg.DataPath + "/" + dir, Container: "/data/" + dir, ReadOnly: true, Dir: true})
		}
	}
	return append(mounts, collectorMount{Host: cfg.DataPath + "/backup", Container: "/data/backup", Dir: true})
}

// The images of the instance's own services, pinned like the honeypot images.
// A moving tag would run versions QPot was never tested with, and a database
// that moves on to a newer image cannot go back to an older one with the same
// data. CI's ClickHouse integration job runs ClickHouseImage (see
// TestCIClickHouseImageMatchesCompose).
const (
	ClickHouseImage  = "clickhouse/clickhouse-server:26.10.3.7@sha256:739e099abd1157390960a59e4532d21781d8fde57e6e4151cb920ea02c30b1ce"
	TimescaleDBImage = "timescale/timescaledb:2.28.3-pg15@sha256:6343bdc87ca132c6b53acb26113a6bad1821d188fa39975a745f32ddd9757634"
	CollectorImage   = "timberio/vector:0.61.0-alpine@sha256:3bb7ed5152910ed51729e256937b1d8a4bf67ff624e9d565e8e5877bffd015c7"
)

// TPotVersion is the T-Pot CE release whose honeypot images QPot runs. It is
// the newest T-Pot build published on ghcr.io/telekom-security (there is no
// T-Pot 25 yet); bump it here when T-Pot publishes a new release.
const TPotVersion = "24.04.2"

// Conpot's mounted protocol patches target this immutable image index. Pin the
// index rather than an architecture-specific manifest to retain amd64 and arm64.
// Updating it requires reviewing the patched modules against the new image.
const (
	conpotImageVersion = "24.04.2"
	conpotImageDigest  = "sha256:be17a238709c78909c7d2e0da55bc3ea66dc3aa46618f0d89b7080f3e7dda3e8"
)

// tpotPinned lists honeypots whose image T-Pot did not rebuild for
// TPotVersion; they stay on the newest tag that exists.
var tpotPinned = map[string]string{
	// No 24.04.2 images for the tanner stack.
	"tanner": "24.04.1",
	"snare":  "24.04.1",
	"phpox":  "24.04.1",
}

// tpotImage returns T-Pot's image for name at TPotVersion (or its pin).
func tpotImage(name string) string {
	if name == "conpot" {
		return "ghcr.io/telekom-security/conpot:" + conpotImageVersion + "@" + conpotImageDigest
	}
	tag := TPotVersion
	if v, ok := tpotPinned[name]; ok {
		tag = v
	}
	return "ghcr.io/telekom-security/" + name + ":" + tag
}

// GetHoneypotImage returns the Docker image for a honeypot
func GetHoneypotImage(name string) string {
	if name == "refrigeration" {
		return refrigeration.BuildImage()
	}
	images := map[string]string{
		"cowrie":         tpotImage("cowrie"),
		"dionaea":        tpotImage("dionaea"),
		"conpot":         tpotImage("conpot"),
		"tanner":         tpotImage("tanner"),
		"adbhoney":       tpotImage("adbhoney"),
		"endlessh":       tpotImage("endlessh"),
		"heralding":      tpotImage("heralding"),
		"honeyaml":       tpotImage("honeyaml"),
		"elasticpot":     tpotImage("elasticpot"),
		"ciscoasa":       tpotImage("ciscoasa"),
		"citrixhoneypot": tpotImage("citrixhoneypot"),
		"ddospot":        tpotImage("ddospot"),
		"ipphoney":       tpotImage("ipphoney"),
		"mailoney":       tpotImage("mailoney"),
		"medpot":         tpotImage("medpot"),
		"dicompot":       tpotImage("dicompot"),
		"redishoneypot":  tpotImage("redishoneypot"),
		"beelzebub":      tpotImage("beelzebub"),
		"galah":          tpotImage("galah"),
		"go-pot":         tpotImage("go-pot"),
		"h0neytr4p":      tpotImage("h0neytr4p"),
		"hellpot":        tpotImage("hellpot"),
		"log4pot":        tpotImage("log4pot"),
		"miniprint":      tpotImage("miniprint"),
		"sentrypeer":     tpotImage("sentrypeer"),
		"wordpot":        tpotImage("wordpot"),
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
		"ssh-proxy", "refrigeration",
	}

	for _, s := range supported {
		if s == name {
			return nil
		}
	}

	return fmt.Errorf("unsupported honeypot: %s (supported: %s)",
		name, strings.Join(supported, ", "))
}

// tannerCompanion is one service of tanner's stack besides the tanner server.
type tannerCompanion struct {
	Service  string // compose service name = the hostname tanner's config uses
	Role     string
	Image    string
	Command  string
	Public   bool // publishes tanner's port (snare, the attacker-facing front end)
	Logs     bool
	Tmpfs    string
	ReadOnly bool
}

// tannerEnabled reports whether the tanner honeypot (and so its stack) runs.
func tannerEnabled(cfg *config.Config) bool {
	hp, ok := cfg.GetHoneypotConfig("tanner")
	return ok && hp.Enabled
}

// tannerCompanions are the services T-Pot runs next to tanner. The names are
// the hostnames baked into the tanner image's config (tanner_api,
// tanner_phpox, tanner_redis) and snare's --tanner argument (tanner).
func tannerCompanions() []tannerCompanion {
	return []tannerCompanion{
		{Service: "snare", Role: "attacker-facing web front end", Image: tpotImage("snare"), Public: true, Tmpfs: "/tmp:size=50m,mode=1777"},
		{Service: "tanner_api", Role: "tanner API", Image: tpotImage("tanner"), Command: "tannerapi", Logs: true, Tmpfs: "/tmp/tanner:uid=2000,gid=2000", ReadOnly: true},
		{Service: "tanner_phpox", Role: "PHP sandbox", Image: tpotImage("phpox"), ReadOnly: true},
		{Service: "tanner_redis", Role: "session store", Image: tpotImage("redis"), ReadOnly: true},
	}
}

// tannerCompanionServices are the companion service names, for start/stop.
func tannerCompanionServices() []string {
	var out []string
	for _, c := range tannerCompanions() {
		out = append(out, c.Service)
	}
	return out
}

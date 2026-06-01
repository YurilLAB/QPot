// Package instance handles Docker Compose generation
package instance

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"strings"
	"text/template"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// ComposeGenerator generates Docker Compose files
type ComposeGenerator struct {
	Config  *config.Config
	Sandbox *security.Sandbox
}

// bridgeName builds the Linux bridge interface name for a honeypot network.
// Linux interface names are capped at 15 chars (IFNAMSIZ), so "br-<honeypot>"
// overflows for names >12 chars (e.g. redishoneypot, citrixhoneypot) and Docker
// rejects the network with "numerical result out of range". When too long, use
// a stable short hash suffix so the name stays <=15 chars and unique.
func bridgeName(honeypot string) string {
	const max = 15
	name := "br-" + honeypot
	if len(name) <= max {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(honeypot))
	return fmt.Sprintf("br-%s%04x", honeypot[:8], h.Sum32()&0xffff)
}

// subnetForNetwork computes a unique, stable /24 subnet for a Docker bridge
// network given an (instanceName, networkName) pair. The result always falls
// in the 172.20.x.y/24 range (RFC 1918) which Docker uses by default.
func subnetForNetwork(instanceName, networkName string) string {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "%s:%s", instanceName, networkName)
	v := h.Sum32()
	x := 20 + int((v>>8)%12) // 20–31
	y := int(v % 256)         // 0–255
	return fmt.Sprintf("172.%d.%d.0/24", x, y)
}

// Generate generates a Docker Compose file
func (g *ComposeGenerator) Generate() (string, error) {
	tmpl := `version: "3.8"

# QPot Instance: {{.Config.InstanceName}}
# QPot ID: {{.Config.QPotID}}
# Auto-generated - Do not edit manually

networks:
  qpot_internal:
    internal: true
{{range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
  {{$name}}_net:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: {{bridgeName $name}}
{{if $.Config.Security.NetworkIsolation.RandomizeMAC}}
    ipam:
      config:
        - subnet: {{subnetFor $.Config.InstanceName $name}}
{{end}}{{end}}{{end}}

volumes:
  qpot_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: {{.Config.DataPath}}
  qpot_db:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: {{.Config.GetDatabasePath}}

secrets:
  qpot_id:
    file: {{.Config.DataPath}}/qpot.id

services:
  # Database - {{.Config.Database.Type}}
  {{if eq .Config.Database.Type "clickhouse"}}database:
    image: clickhouse/clickhouse-server:latest
    container_name: {{.Config.InstanceName}}_db
    restart: unless-stopped
    environment:
      CLICKHOUSE_DB: {{.Config.Database.Database}}
      CLICKHOUSE_USER: {{.Config.Database.Username}}
      CLICKHOUSE_PASSWORD: {{.Config.Database.Password}}
      CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: 1
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - qpot_db:/var/lib/clickhouse
      - {{.Config.DataPath}}/clickhouse-config:/etc/clickhouse-server/conf.d
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "{{.Config.AllocatePort 9000}}:9000"
      - "{{.Config.AllocatePort 8123}}:8123"
    networks:
      - qpot_internal
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
    environment:
      POSTGRES_DB: {{.Config.Database.Database}}
      POSTGRES_USER: {{.Config.Database.Username}}
      POSTGRES_PASSWORD: {{.Config.Database.Password}}
      QPOT_ID: {{.Config.QPotID}}
    volumes:
      - qpot_db:/var/lib/postgresql/data
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "{{.Config.AllocatePort 5432}}:5432"
    networks:
      - qpot_internal
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
    # Point Vector explicitly at the YAML config so parser selection never
    # depends on the image's default config path/extension.
    command: ["--config", "/etc/vector/vector.yaml"]
    environment:
      QPOT_ID: {{.Config.QPotID}}
      QPOT_INSTANCE: {{.Config.InstanceName}}
    volumes:
      - {{.Config.DataPath}}/vector.yaml:/etc/vector/vector.yaml:ro
      - qpot_data:/data:ro
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    networks:
      - qpot_internal
    cap_add:
      - DAC_READ_SEARCH

{{range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
{{template "honeypot" dict "Name" $name "HP" $hp "Config" $.Config "Sandbox" $.Sandbox}}
{{end}}{{end}}

  # Web UI with QPot ID authentication
{{if .Config.WebUI.Enabled}}  webui:
    image: ghcr.io/qpot/webui:latest
    container_name: {{.Config.InstanceName}}_webui
    restart: unless-stopped
    environment:
      QPOT_ID: {{.Config.QPotID}}
      QPOT_INSTANCE: {{.Config.InstanceName}}
      QPOT_DATABASE_TYPE: {{.Config.Database.Type}}
      QPOT_DATABASE_HOST: database
      QPOT_ID_AUTH: "{{.Config.WebUI.QPotIDAuth}}"
    volumes:
      - {{.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
    ports:
      - "{{.Config.WebUI.BindAddr}}:{{.Config.WebUI.Port}}:8080"
    networks:
      - qpot_internal
    depends_on:
      database:
        condition: service_healthy
    secrets:
      - qpot_id
{{end}}

{{define "honeypot"}}
  # Honeypot: {{.Name}}
  {{.Name}}:
    image: {{GetHoneypotImage .Name}}
    container_name: {{$.Config.InstanceName}}_{{.Name}}
    restart: on-failure:{{$.Config.Security.ResourceLimits.RestartAttempts}}
    {{if $.Sandbox.ContainerRuntime}}# Stronger isolation runtime (gVisor/Kata) for this attacker-facing container
    runtime: {{$.Sandbox.ContainerRuntime}}
    {{end}}
    {{- $d := deployFor .Name}}
    ports:
    {{- if $d.Ports}}
    {{- range $p := $d.Ports}}
      - "{{$.Config.AllocatePort $p}}:{{$p}}"
    {{- end}}
    {{- else}}
      - "{{$.Config.AllocatePort .HP.Port}}:{{.HP.Port}}"
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
    environment:
      - HONEYPOT_NAME={{.Name}}
      - LOG_LEVEL=info
      - QPOT_INSTANCE={{$.Config.InstanceName}}
      {{if .HP.Sandbox}}- SANDBOX_MODE=1{{end}}
      {{if .HP.Stealth.Enabled}}- STEALTH_MODE=1{{end}}
      {{if .HP.Stealth.FakeHostname}}- FAKE_HOSTNAME={{.HP.Stealth.FakeHostname}}{{end}}
      {{if .HP.Stealth.FakeOS}}- FAKE_OS={{.HP.Stealth.FakeOS}}{{end}}
      {{if .HP.Stealth.FakeKernel}}- FAKE_KERNEL={{.HP.Stealth.FakeKernel}}{{end}}
      {{if .HP.Stealth.BannerString}}- BANNER_STRING={{.HP.Stealth.BannerString}}{{end}}
      {{if .HP.Stealth.RandomizeSSHVersion}}- RANDOMIZE_SSH_VERSION=1{{end}}
      {{if .HP.Stealth.AddArtificialDelay}}- ARTIFICIAL_DELAY={{.HP.Stealth.DelayRangeMs}}{{end}}
      # TPOT-compatible environment variables
      - TPOT_HONEYPOT={{.Name}}
      - TPOT_INSTANCE={{$.Config.InstanceName}}
    {{template "security" dict "Config" $.Config "HP" .HP "GlobalLimits" $.Config.Security.ResourceLimits "Name" .Name "FakeHostname" .HP.Stealth.FakeHostname}}
    healthcheck:
      test: ["CMD-SHELL", "netstat -tln 2>/dev/null | grep -q ':{{.HP.Port}}' || ss -tln | grep -q ':{{.HP.Port}}'"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
{{end}}

{{define "dbsecurity"}}
    # Security hardening - Resource limits (database service)
    deploy:
      resources:
        limits:
          cpus: '{{divf .GlobalLimits.MaxCPUPercent 100}}'
          memory: {{.GlobalLimits.MaxMemoryMB}}M
          {{if .GlobalLimits.MaxPids}}pids: {{.GlobalLimits.MaxPids}}{{end}}
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
      - SETUID
      - SETGID{{end}}

    # No user override: the database image runs as its own user; forcing a
    # different uid breaks its data-directory ownership.

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
    {{if .HP.Resources.UseCustomLimits}}
    {{$cpuLimit = .HP.Resources.MaxCPUPercent}}
    {{$memLimit = .HP.Resources.MaxMemoryMB}}
    {{$pidLimit = .HP.Resources.MaxPids}}
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
      {{if or $dep.NeedsNetBind (and .HP.Port (lt .HP.Port 1024))}}- NET_BIND_SERVICE{{end}}{{end}}

    # No user override: each honeypot image already runs as its own non-root
    # user (e.g. cowrie=2000). Forcing a different uid breaks the image's file
    # ownership and tmpfs uid assumptions (cowrie's /tmp/cowrie is uid 2000).

    # Hostname isolation
    hostname: {{if .FakeHostname}}"{{.FakeHostname}}"{{else if .Name}}"{{.Name}}-host"{{else}}"qpot-host"{{end}}

    # Temporary filesystems. A single tmpfs: block combines the read-only-root
    # scratch mounts with any image-specific tmpfs the deployment profile
    # requires (e.g. cowrie's /tmp/cowrie), so there is never a duplicate key.
    {{- $dt := deployFor .Name}}
    {{- if or .Config.Security.ReadOnlyFilesystem $dt.Tmpfs}}
    tmpfs:
    {{- if .Config.Security.ReadOnlyFilesystem}}
      - /tmp:noexec,nosuid,size=100m,mode=1777
      - /var/tmp:noexec,nosuid,size=50m,mode=1777
      - /run:noexec,nosuid,size=10m,mode=1777
    {{- end}}
    {{- range $t := $dt.Tmpfs}}
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
        env: "QPOT_INSTANCE,HONEYPOT_NAME"
{{end}}
`

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
		"add": func(a, b int) int {
			return a + b
		},
		"lt": func(a, b int) bool {
			return a < b
		},
		"GetHoneypotImage": GetHoneypotImage,
		"subnetFor": subnetForNetwork,
		"bridgeName": bridgeName,
		"deployFor": deployProfileFor,
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
    read_from: end
    multiline:
      mode: halt_before
      start_pattern: '^\{'
      condition_pattern: '^\{'
      timeout_ms: 1000
{{end}}{{end}}

transforms:
  add_qpot_metadata:
    type: remap
    inputs:
{{- range $name, $hp := .Config.Honeypots}}{{if $hp.Enabled}}
      - {{$name}}_logs{{end}}{{end}}
    source: |
      # Parse the honeypot's JSON payload FIRST so its fields are present;
      # our own metadata is stamped afterwards so an attacker-controlled log
      # line can never clobber qpot_id / timestamp / honeypot.
      if is_string(.message) && starts_with(strip_whitespace(string!(.message)), "{") {
        parsed, perr = parse_json(string!(.message))
        if perr == null {
          . = merge(., object(parsed) ?? {})
        }
      }

      # Derive the honeypot name from the source file path
      # (/data/honeypots/<name>/logs/...). This is the only place the per-event
      # honeypot can be recovered, and the DB requires it (NOT NULL).
      .honeypot = "unknown"
      if exists(.file) {
        m, merr = parse_regex(string(.file) ?? "", r'/honeypots/(?P<hp>[^/]+)/')
        if merr == null {
          .honeypot = m.hp
        }
      }

      # Normalise source IP from the common honeypot field names. to_string is
      # fallible on an unknown-typed field, so coalesce to a default.
      if exists(.src_ip) {
        .source_ip = to_string(.src_ip) ?? "0.0.0.0"
      } else if !exists(.source_ip) {
        .source_ip = "0.0.0.0"
      }

      # Normalise event type (cowrie uses "eventid"); the column is otherwise
      # empty and all GROUP BY event_type aggregations would be blank.
      if exists(.eventid) {
        .event_type = to_string(.eventid) ?? "unknown"
      } else if !exists(.event_type) {
        .event_type = "unknown"
      }

      # Stamp QPot metadata LAST. The timestamp is formatted as ClickHouse's
      # DateTime64 'basic' input format ("YYYY-MM-DD HH:MM:SS.fff"); a raw
      # RFC3339 value (with T/Z) is rejected by the JSONEachRow parser (400).
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = format_timestamp!(now(), "%Y-%m-%d %H:%M:%S%.3f")
{{if .Config.Collector.GeoIPDBPath}}
  enrich_geoip:
    type: remap
    inputs:
      - add_qpot_metadata
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
      - {{if .Config.Collector.GeoIPDBPath}}enrich_geoip{{else}}add_qpot_metadata{{end}}
    condition: |
      # Drop events whose message contains a known scanner signature (stealth).
      # Substring match via contains() — match_any expects regexes, and
      # contains avoids regex-escaping the operator-supplied probe strings.
      {{- if .Config.Stealth.BlockCommonProbes}}
      msg = downcase(string(.message) ?? "")
      !({{range $i, $probe := .Config.Stealth.BlockedProbes}}{{if $i}} || {{end}}contains(msg, "{{$probe}}"){{end}})
      {{- else}}
      true
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
      - filter_stealth
    endpoint: "postgres://{{.Config.Database.Username}}:{{.Config.Database.Password}}@database:5432/{{.Config.Database.Database}}"
    table: events
    encoding:
      # Only columns that actually exist in the events table. qpot_id /
      # qpot_instance are intentionally excluded — there are no such columns
      # (the API attaches qpot_id at read time); including them broke the
      # INSERT.
      only_fields:
        - timestamp
        - honeypot
        - source_ip
        - source_port
        - dest_port
        - protocol
        - event_type
        - username
        - password
        - command
        - payload
        - metadata
        - country
        - city
        - asn
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

	t := template.Must(template.New("vector").Parse(config))

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
	seed := g.Config.QPotID
	if seed == "" {
		seed = g.Config.InstanceName
	}
	explicit := ""
	if hp, ok := g.Config.Honeypots["cowrie"]; ok {
		explicit = hp.Stealth.CredentialTemplate
	}
	return renderCowrieUserDB(selectCredentialTemplate(explicit, seed))
}

// generateCowrieConfig generates TPOT-compatible Cowrie config.
//
// The system identity (hostname, advertised SSH version, kernel/uname fields)
// is derived per-instance from a stable seed (the QPot ID) so it is unique to
// this deployment and internally consistent, rather than the static defaults
// every T-Pot Cowrie shares (which are themselves a fingerprint). Explicit
// stealth overrides take precedence. See deception.go for the research basis.
func (g *ComposeGenerator) generateCowrieConfig(hp config.HoneypotConfig) string {
	seed := g.Config.QPotID
	if seed == "" {
		seed = g.Config.InstanceName
	}
	profile := profileForSeed(seed)

	hostname := hp.Stealth.FakeHostname
	if hostname == "" {
		hostname = hostnameForSeed(seed)
	}

	kernel := hp.Stealth.FakeKernel
	if kernel == "" {
		kernel = profile.KernelVersion
	}

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

	return fmt.Sprintf(`[honeypot]
hostname = %s
log_path = log
logtype = json
download_path = dl
share_path = share/cowrie
state_path = /tmp/cowrie/data
contents_path = honeyfs
ttylog = true
ttylog_path = log/tty
interactive_timeout = 180
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
filesystem = share/cowrie/fs.pickle
kernel_version = %s
kernel_build_string = %s
hardware_platform = %s
operating_system = %s
ssh_version = %s

[ssh]
enabled = true
# Listen on the standard privileged ports (the deployment profile maps host
# ports here and grants NET_BIND_SERVICE). A real server runs SSH on 22 /
# Telnet on 23, so this is also more convincing than the 2222/2223 default.
listen_endpoints = tcp:22:interface=0.0.0.0
sftp_enabled = true
forwarding = false
auth_keyboard_interactive_enabled = true

[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = log/cowrie.json
`, hostname, kernel, profile.KernelBuildString, profile.HardwarePlatform, profile.OperatingSystem, sshVersion)
}

// generateConpotConfig generates TPOT-compatible Conpot config
func (g *ComposeGenerator) generateConpotConfig(hp config.HoneypotConfig) string {
	return `[common]
 sensor_id = qpot-conpot
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
		"cowrie":     "ghcr.io/telekom-security/cowrie:24.04.1",
		"dionaea":    "ghcr.io/telekom-security/dionaea:24.04.1",
		"conpot":     "ghcr.io/telekom-security/conpot:24.04.1",
		"tanner":     "ghcr.io/telekom-security/tanner:24.04.1",
		"adbhoney":   "ghcr.io/telekom-security/adbhoney:24.04.1",
		"endlessh":   "ghcr.io/telekom-security/endlessh:24.04.1",
		"heralding":  "ghcr.io/telekom-security/heralding:24.04.1",
		"honeyaml":   "mmta/honeyaml:latest",
		"elasticpot": "ghcr.io/telekom-security/elasticpot:24.04.1",
		"ciscoasa":   "ghcr.io/telekom-security/ciscoasa:24.04.1",
		"citrixhoneypot": "ghcr.io/telekom-security/citrixhoneypot:24.04.1",
		"ddospot":    "ghcr.io/telekom-security/ddospot:24.04.1",
		"ipphoney":   "ghcr.io/telekom-security/ipphoney:24.04.1",
		"mailoney":   "ghcr.io/telekom-security/mailoney:24.04.1",
		"medpot":     "ghcr.io/telekom-security/medpot:24.04.1",
		"redishoneypot": "ghcr.io/telekom-security/redishoneypot:24.04.1",
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
		"mailoney", "medpot", "redishoneypot",
	}

	for _, s := range supported {
		if s == name {
			return nil
		}
	}

	return fmt.Errorf("unsupported honeypot: %s (supported: %s)",
		name, strings.Join(supported, ", "))
}

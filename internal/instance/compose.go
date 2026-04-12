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
      com.docker.network.bridge.name: br-{{$name}}
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
    environment:
      QPOT_ID: {{.Config.QPotID}}
      QPOT_INSTANCE: {{.Config.InstanceName}}
    volumes:
      - {{.Config.DataPath}}/vector.toml:/etc/vector/vector.toml:ro
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
    ports:
      - "{{$.Config.AllocatePort .HP.Port}}:{{.HP.Port}}"
    volumes:
      - {{$.Config.DataPath}}/honeypots/{{.Name}}/logs:/var/log/honeypot
      - {{$.Config.DataPath}}/honeypots/{{.Name}}/data:/data
      - {{$.Config.DataPath}}/qpot.id:/run/secrets/qpot_id:ro
      {{if eq .Name "cowrie"}}- {{$.Config.DataPath}}/honeypots/{{.Name}}/cowrie.cfg:/opt/cowrie/cowrie.cfg:ro{{end}}
      {{if eq .Name "conpot"}}- {{$.Config.DataPath}}/honeypots/{{.Name}}/conpot.cfg:/opt/conpot/conpot.cfg:ro{{end}}
    networks:
      - qpot_internal
      - {{.Name}}_net
    environment:
      - HONEYPOT_NAME={{.Name}}
      - LOG_LEVEL=info
      - QPOT_ID={{$.Config.QPotID}}
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
    secrets:
      - qpot_id
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

    # User namespace
    user: "1000:1000"

    # PID namespace for process isolation
    pid: "private"

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
    {{if .Config.Security.DropCapabilities}}cap_drop:
      - ALL
    cap_add:
      - SETUID
      - SETGID
      {{if and .HP.Port (lt .HP.Port 1024)}}- NET_BIND_SERVICE{{end}}{{end}}

    # User namespace
    user: "1000:1000"

    # PID namespace for process isolation
    pid: "private"

    # Hostname isolation
    hostname: {{if .FakeHostname}}"{{.FakeHostname}}"{{else if .Name}}"{{.Name}}-host"{{else}}"qpot-host"{{end}}

    # Temporary filesystems for read-only containers
    {{if .Config.Security.ReadOnlyFilesystem}}tmpfs:
      - /tmp:noexec,nosuid,size=100m,mode=1777
      - /var/tmp:noexec,nosuid,size=50m,mode=1777
      - /run:noexec,nosuid,size=10m,mode=1777{{end}}

    # Memory and OOM settings
    mem_swappiness: 0
    oom_kill_disable: false

    # Device restrictions
    device_read_bps:
      - path: /dev/null
        rate: 1mb
    device_write_bps:
      - path: /dev/null
        rate: 1mb

    # Logging configuration
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "qpot.instance,qpot.honeypot,qpot.id"
        env: "QPOT_ID,QPOT_INSTANCE,HONEYPOT_NAME"
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

enrichment_tables:
  qpot_geoip:
    type: "geoip"
    path: "/usr/share/GeoIP/GeoLite2-City.mmdb"

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
      .qpot_id = "{{.Config.QPotID}}"
      .qpot_instance = "{{.Config.InstanceName}}"
      .timestamp = now()
      
      # Parse JSON logs if present
      if is_string(.message) && starts_with(strip_whitespace(.message), "{") {
        parsed = parse_json!(.message)
        . = merge(., parsed)
      }
      
      # Extract source IP if present
      if exists(.src_ip) {
        .source_ip = .src_ip
      } else if exists(.source_ip) {
        # Already present
      } else {
        .source_ip = "0.0.0.0"
      }

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

  filter_stealth:
    type: filter
    inputs:
      - enrich_geoip
    condition: |
      # Filter out common scanner signatures if stealth mode enabled
      {{if .Config.Stealth.BlockCommonProbes}}
      !match_any(.message, [{{range $i, $probe := .Config.Stealth.BlockedProbes}}{{if $i}}, {{end}}"{{$probe}}"{{end}}])
      {{else}}
      true
      {{end}}

sinks:
{{if eq .Config.Database.Type "clickhouse"}}
  clickhouse:
    type: clickhouse
    inputs:
      - filter_stealth
    endpoint: "http://database:8123"
    database: {{.Config.Database.Database}}
    table: events
    auth:
      strategy: basic
      user: {{.Config.Database.Username}}
      password: {{.Config.Database.Password}}
    encoding:
      timestamp_format: unix
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
      only_fields:
        - qpot_id
        - qpot_instance
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
	case "conpot":
		configs["conpot.cfg"] = g.generateConpotConfig(hp)
	}
	
	return configs, nil
}

// generateCowrieConfig generates TPOT-compatible Cowrie config
func (g *ComposeGenerator) generateCowrieConfig(hp config.HoneypotConfig) string {
	hostname := hp.Stealth.FakeHostname
	if hostname == "" {
		hostname = "server"
	}
	
	os := hp.Stealth.FakeOS
	if os == "" {
		os = "Ubuntu 22.04.3 LTS"
	}
	
	kernel := hp.Stealth.FakeKernel
	if kernel == "" {
		kernel = "5.15.0-91-generic"
	}
	
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

[shell]
filesystem = share/cowrie/fs.pickle
kernel_version = %s
kernel_build_string = #91-Ubuntu SMP
hardware_platform = x86_64
operating_system = GNU/Linux
ssh_version = OpenSSH_8.9p1 Ubuntu-3ubuntu0.10

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
sftp_enabled = true
forwarding = false
auth_keyboard_interactive_enabled = true

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = log/cowrie.json
`, hostname, kernel)
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

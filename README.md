<p align="center">
  <img src="https://raw.githubusercontent.com/YurilLAB/QPot/main/doc/qpot_wallpaper.png" alt="QPot Wallpaper" width="800">
</p>

<h1 align="center">QPot</h1>
<p align="center">
  <strong>Advanced Honeypot Platform</strong><br>
  <em>Developed by Yuril Security Team</em><br>
</p>

<p align="center">
  <a href="https://github.com/YurilLAB/QPot/releases"><img src="https://img.shields.io/github/v/release/YurilLAB/QPot?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.23+-00ADD8.svg?style=flat-square" alt="Go Version"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/Docker-Required-2496ED.svg?style=flat-square" alt="Docker"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square" alt="License"></a>
</p>

---

## Overview

**QPot** is an enterprise-grade honeypot platform developed by YurilLAB. Built on the solid foundation of T-Pot CE, QPot adds modern security features, enhanced sandboxing, and seamless integration with the Yuril Security ecosystem.

> **Part of the Yuril Security Suite**  
> QPot works alongside [YurilAntivirus](https://github.com/YurilLAB/YurilSecurity/tree/main/YurilAntivirus) and [YurilTracking](https://github.com/YurilLAB/YurilSecurity/tree/main/YurilTracking) to provide comprehensive threat detection and response capabilities.

---

## Why QPot?

### Comparison with T-Pot

| Feature | T-Pot | QPot |
|---------|-------|------|
| Attack Map | Yes | Yes - Enhanced with QPot ID |
| Kibana Dashboard | Yes | Yes - With ClickHouse support |
| Honeypots | ~28 | 26 - Same proven images (see coverage below) |
| Per-Honeypot Resources | No | Yes - CPU/Mem/PID limits |
| gVisor/Kata Sandboxing | No | Yes - Applied to honeypot containers when available |
| ClickHouse Database | No | Yes - High-performance analytics |
| QPot ID Tracking | No | Yes - Instance identification |
| Per-Instance Identity | No (identical everywhere) | Yes - Unique SSH version/hostname/kernel per instance |
| Credential Personas | No (default phil/richard tell) | Yes - 22 realistic personas, UserDB-enforced |
| Consistent Fake Filesystem | No (stock, identical) | Yes - /etc/passwd, os-release, /proc/version, /proc/cpuinfo, /etc/timezone match the persona/kernel |
| Stealth Mode | No | Yes - Anti-fingerprinting |
| Yuril Integration | No | Yes - Native ecosystem support |
| Database Migrations | No | Yes - Versioned schema management |
| Data Retention Policies | No | Yes - Automated S3 archival |
| Read Replicas | No | Yes - High availability |
| Cluster Management | No | Yes - Multi-instance with password auth |
| Threat Intel (ATT&CK) | No | Yes - Auto MITRE ATT&CK classification |
| IOC Tracking | No | Yes - Automated IOC extraction & dedup |
| TTP Session Analysis | No | Yes - Behavioral campaign fingerprinting |
| Alert Webhooks | No | Yes - Slack/Discord/generic thresholds |
| Attack-Response Hooks | No | Yes - shell hooks on threshold (firewall/SOAR), debounced |
| Kibana Dashboards | Yes (ELK) | Yes - over ClickHouse, **auto-provisioned** (zero setup) |
| Attack Map | Yes | Yes - over ClickHouse (country-centroid geo) |
| NSM Sensor Ingest | Yes (Logstash→ES) | Yes - Suricata/p0f/fatt via Vector→ClickHouse |
| IOC Export | No | Yes - blocklist API **and MISP threat-intel export** |
| GeoIP Enrichment | No | Yes - Optional MaxMind via Vector (`collector.geoip_db_path`) |
| Startup Diagnostics | No | Yes - Per-honeypot start/fail report with the failure reason |
| CI / Supply Chain | No | Yes - GitHub Actions: build, gofmt, vet, race tests, govulncheck, fuzz smoke |

### Honeypot Coverage

QPot ships **26 honeypots**, all using the same upstream images T-Pot uses
(preferring the rate-limit-free `ghcr.io/telekom-security/*` mirror). Run
`qpot honeypot list` to see them with ports, risk level, and enable state:

`adbhoney`, `beelzebub`, `ciscoasa`, `citrixhoneypot`, `conpot`, `cowrie`,
`ddospot`, `dicompot`, `dionaea`, `elasticpot`, `endlessh`, `galah`, `go-pot`,
`h0neytr4p`, `hellpot`, `heralding`, `honeyaml`, `ipphoney`, `log4pot`,
`mailoney`, `medpot`, `miniprint`, `redishoneypot`, `sentrypeer`, `tanner`,
`wordpot`.

**Deliberately not included:** `glutton` and `honeytrap`. Both require
`network_mode: host` plus the `NET_ADMIN` capability (they use TPROXY/transparent
interception to catch traffic on every port). That directly contradicts QPot's
two core safety guarantees — per-honeypot network isolation (each honeypot gets
its own bridge network) and capability dropping (`cap_drop: ALL`, only
`NET_BIND_SERVICE` added back). Rather than silently weaken the isolation model,
QPot omits them; the broad protocol coverage they provide is largely covered by
`dionaea`, `heralding`, and `cowrie`.

**Analysis / sensor stack.** T-Pot bundles host-level sensors and a visualization
stack (Suricata, p0f, Fatt, Spiderfoot, Ewsposter, the ELK stack, the attack
map, nginx). QPot ships its own integrated pipeline — **Vector** for collection,
**ClickHouse** for storage, an **in-process Web UI** (served by the `qpot`
binary), built-in **MITRE ATT&CK** classification, **IOC/TTP** extraction, and
**Yuril Security Suite** integration — *and* keeps the native T-Pot experience
working on top of it so users lose nothing:

- **Kibana** runs against QPot's ClickHouse via the bundled **ClickHouse-Kibana
  connector** (`docker/clickhouse-kibana/`), which speaks the Elasticsearch API
  Kibana needs (version, `_field_caps`, `_mapping`, `_search` with
  aggregations, and a writable `.kibana` saved-object store). It **auto-seeds a
  data view and a "QPot Overview" dashboard on first boot**, so Kibana opens
  straight into attack dashboards with no setup.
- **Attack map** works against the same connector (`docker-compose.attack-map.yml`),
  with country-centroid geo so events plot from QPot's country data.
- **NSM sensors** are ingested by Vector into the same events store, so they
  appear in the dashboards / attack map alongside honeypot hits (each default
  on, a no-op when the sensor isn't deployed):
  - **Suricata** network-IDS alerts (`collector.ingest_suricata`) — with a
    "Top Network Alerts" panel.
  - **p0f** passive OS fingerprints (`collector.ingest_p0f`) — "Attacker OS" panel.
  - **fatt** JA3/HASSH network fingerprints (`collector.ingest_fatt`) — "Top
    Client Fingerprints" panel.
  - **Connection enrichment**: the connector joins each honeypot connection
    with the attacker's p0f OS and fatt JA3 for the same source IP (read-time,
    by `source_ip`), exposed as `qpot_enrichment.os` / `qpot_enrichment.ja3` in
    Discover / the attack map (toggle with `QPOT_ENRICH`).
- **nginx** portal, **Spiderfoot**, **CyberChef** and **Elasticvue** are wired
  through the QPot nginx config (`docker/nginx/dist/conf/qpot.conf`).

The connector covers Discover, index patterns and aggregation visualizations;
it is not a full Elasticsearch (ES|QL/ML are out of scope). The vendored
upstream sources remain under `docker/` for reference.

### Key Advantages

**Defense in Depth**  
Every honeypot runs in its own sandbox. QPot detects and uses gVisor (`runsc`), Kata Containers (`kata-runtime`), or Firejail (`firejail`) when installed and falls back to the default container runtime otherwise. Resource limits (CPU, memory, PIDs, file descriptors) cap the blast radius of a container escape or resource-exhaustion attack.

**Modern Data Architecture**  
Optional ClickHouse backend provides columnar storage for fast analytics, while the ClickHouse-Kibana connector maintains compatibility with existing Kibana dashboards.

**Unique Instance Tracking**  
Every QPot deployment receives a unique QPot ID (`qp_*`) for multi-instance management, threat correlation, and integration with YurilTracking.

**Stealth Operations**  
Built-in anti-fingerprinting makes honeypots slower and harder to detect, so an
attacker stays engaged longer and yields more intelligence. Each instance derives
a unique, internally-consistent system identity from its QPot ID — per-instance
distro/SSH banner/kernel, one of 22 credential personas (UserDB-enforced), and a
matching fake filesystem (`/etc/passwd`, `os-release`, `/proc/version`,
`/proc/cpuinfo`, `/etc/timezone`, …) so post-login recon tells one coherent
story. A realistic session idle timeout, randomized response delays, stable SSH
host keys, and MAC address randomization round it out. See
[Deception & Anti-Fingerprinting](#deception--anti-fingerprinting)
for the full mechanism and honest limitations.

---

## Architecture

```
+-------------------------------------------------------------+
|                        QPot Platform                        |
|                                                             |
|  +------------------------------------------------------+   |
|  |            Nginx Reverse Proxy (64297)               |   |
|  |  +----------+----------+----------+-------------+    |   |
|  |  | Landing  |  Attack  |  Kibana  |  QPot API   |    |   |
|  |  |  Page    |   Map    | Analytics|   Server    |    |   |
|  |  +----------+----------+----------+-------------+    |   |
|  +------------------------------------------------------+   |
|                            |                                |
|  +-------------------------+-----------------------------+  |
|  |                         |                             |  |
|  v                         v                             v  |
|  ClickHouse           Honeypots                     Web UI  |
|  (Analytics)        (Docker Containers)            (React)  |
|                                                             |
|  +------------------------------------------------------+   |
|  |                   Security Features                  |   |
|  |  - gVisor/Kata sandboxing  - Read-only filesystems   |   |
|  |  - Resource limits         - Custom seccomp profiles |   |
|  |  - Network isolation       - MAC randomization       |   |
|  |  - Stealth/deception       - No privileged containers|   |
|  +------------------------------------------------------+   |
+-------------------------------------------------------------+
```

---

## Quick Start

### Installation

**One-line install (Linux / macOS):**

```bash
curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex
```

Both installers check for Docker / Docker Compose, install the `qpot` binary
(downloading a release if available, otherwise **building from source** with Go),
add it to your `PATH`, and create a default instance. The Linux script also
prints distro-specific Docker hints (Arch/Debian/Fedora/Rocky/openSUSE).

**From source (any platform with Go 1.25+):**

```bash
# Clone the repository
git clone https://github.com/YurilLAB/QPot.git
cd QPot

# Build the QPot CLI
go build -o qpot ./cmd/qpot

# Or use Make
make build
```

**Full multi-distro server install (T-Pot-style, Ansible):** for a dedicated
sensor host, `sudo ./install.sh` runs the Ansible playbook across AlmaLinux,
Arch, Debian, EndeavourOS, Fedora, Manjaro, openSUSE Tumbleweed, RHEL, Rocky,
Raspbian, and Ubuntu, then prompts for the install type (Hive / Sensor / LLM /
Mini / Mobile / Tarpit).

### Create and Start Instance

```bash
# Create a new instance (generates unique QPot ID)
./qpot instance create production
# Output: [OK] Created QPot instance 'production'
#         QPot ID: qp_e2imzc43lisklwokb7vlspi7

# Start the instance
./qpot up --instance production
```

### Access Dashboard

| Service | URL | Description |
|---------|-----|-------------|
| QPot Dashboard | http://localhost:8080 | Built-in web UI (QPot ID auth), served in-process by the `qpot` binary |
| QPot API | http://localhost:8080/api | Management & intelligence API (same listener, QPot ID auth) |

> Unlike T-Pot, QPot does not run a separate nginx/Kibana/attack-map stack on
> port 64297 — the dashboard, attack feed, and API are all served by the `qpot`
> process itself on the Web UI port (default `8080`).

The built-in **QPot Dashboard** (authenticated with your QPot ID) is organized
into tabs:

- **Dashboard** — live status/stats, per-honeypot enable/disable controls, a
  real-time attacker **activity feed**, and a **Threat Intelligence** panel
  (top MITRE ATT&CK techniques, recent IOCs, active TTP campaigns).
- **Pairing / Networking** — manage the honeypot **group**: paired nodes, each
  node's online status / uptime / total requests, and the group size and total
  activity (see Cluster Management below).
- **Security** — the security posture (sandbox runtime, auth, database) and
  per-honeypot isolation.

It auto-refreshes and all attacker-controlled fields are escaped against XSS.

---

## QPot ID System

Every QPot instance receives a unique identifier for tracking and integration:

```bash
# View QPot ID
./qpot id --instance production
# QPot ID: qp_e2imzc43lisklwokb7vlspi7

# The QPot ID is displayed in:
# - GUI popup on startup
# - Web UI header (click to copy)
# - Attack map interface
# - API responses
```

### Integration with YurilTracking

QPot instances can feed threat data directly into YurilTracking for centralized analysis:

```yaml
# qpot.yml
integrations:
  yuril_tracking:
    enabled: true
    endpoint: https://tracking.yuril.local/api/v1/events
    api_key: ${YURIL_API_KEY}
    qpot_id: ${QPOT_ID}
```

---

## Configuration

### Per-Honeypot Resource Limits

```yaml
honeypots:
  cowrie:
    enabled: true
    resources:
      use_custom_limits: true
      max_cpu_percent: 30
      max_memory_mb: 256
      max_pids: 50
      max_file_descriptors: 1024
```

### Database Backend Options

**ClickHouse (Recommended)**
```yaml
database:
  type: clickhouse
  host: localhost
  port: 9000
  database: qpot
```

**TimescaleDB**
```yaml
database:
  type: timescaledb
  host: localhost
  port: 5432
```

**Elasticsearch (Legacy)**
```yaml
database:
  type: elasticsearch
  host: localhost
  port: 9200
```

### Deception & Anti-Fingerprinting

A stock T-Pot deployment ships **globally identical** honeypot identity strings —
every instance advertises the same Cowrie hostname, the same SSH version, the
same `userdb` (including the well-known `phil`/`richard` accounts), and the same
fake filesystem. Those constants *are* the fingerprint. QPot makes each
deployment look like a distinct, internally-consistent real system, derived
deterministically from the instance's unique QPot ID:

- **Per-instance identity** — a realistic, self-consistent distro profile (SSH
  version + kernel + `uname` fields) and hostname are chosen per instance, so no
  two QPot deployments (and no QPot-vs-T-Pot) share a signature.
- **Credential personas** — 22 research-backed login personas (corporate Ubuntu,
  IoT camera, DB server, edge router, VoIP/PBX, CCTV/NVR, cloud-default,
  abandoned VPS, jump bastion, Proxmox host, GitLab CI, monitoring stack,
  Raspberry Pi, FTP fileserver, …), each with believable accounts and
  weak-but-real passwords drawn from SANS ISC / F5 Labs brute-force corpora. One
  persona is auto-selected per instance (or pinned via `credential_template`).
  The default `phil`/`richard` tell is removed and `auth_class = UserDB` is
  enforced, so only a persona's exact credentials succeed (no "any password
  works").
- **Consistent fake filesystem** — Cowrie's `/etc/passwd`, `/etc/group`,
  `/etc/os-release`, `/etc/hostname`, `/etc/hosts`, `/etc/issue`, `/etc/motd`,
  `/etc/timezone`, `/proc/version`, and `/proc/cpuinfo` are generated from the
  *same* persona + distro seed, so post-login recon (`cat /etc/passwd`,
  `cat /etc/os-release`, `cat /proc/cpuinfo`, `uname -a`, `hostname`) tells one
  coherent, deployment-unique story — agreeing with the login persona and the
  advertised SSH banner. This closes the dominant "logged-in user is absent from
  /etc/passwd" tell, the stock-Debian-`motd`-on-every-box tell, and the
  globally-identical-`/proc` fingerprint. `/proc/cpuinfo` reports a realistic,
  per-instance server CPU (varied Xeon/EPYC model) but is deliberately pinned to
  **2 logical CPUs** so it never contradicts Cowrie's hard-coded `nproc`/`free`
  builtins (a core-count mismatch would itself be a tell). Only paths Cowrie
  actually serves from its fake filesystem are overridden — writing a path absent
  from the image (e.g. `/etc/machine-id`) would create a *new* "No such file"
  tell, so those are intentionally left alone.
- **Realistic session timeout** — Cowrie's stock 180s (3-minute) idle timeout
  kicks any attacker who pauses to think or paste; a real `sshd` does not
  disconnect idle sessions by default. QPot raises `interactive_timeout` to 1800s
  (30 min) so the session looks like a normal server and captures more attacker
  activity, while `authentication_timeout` stays at 120s to match OpenSSH's
  default `LoginGraceTime`.
- **Real advertised SSH banner** — the per-instance OpenSSH version is set as the
  actual protocol banner (`[ssh] version`), not just the in-shell `ssh -V`
  string, so Shodan/zgrab see the derived identity rather than Cowrie's hardcoded
  default `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`.
- **Stable SSH host keys** — Cowrie's RSA/ECDSA/ed25519 host keys are generated
  once and persisted per instance, so the host-key fingerprint stays constant
  across restarts (a host key that rotates every restart is itself a tell).
- **No self-identifying configs or containers** — generated configs and honeypot
  container environments never embed `qpot`/`tpot`/`honeypot` tokens. Conpot's
  `sensor_id` looks like an ordinary ICS asset tag (e.g. `RTU-95f0`), and no
  honeypot container exposes `HONEYPOT_NAME`/`TPOT_HONEYPOT`/`STEALTH_MODE` env
  vars — an attacker with in-container code execution who runs `env` sees nothing
  identifying. QPot's own per-honeypot metadata lives in host-side docker labels
  (invisible from inside the container).
- **gVisor / Kata** isolation runtime is actually applied to honeypot containers
  when available; response timing can be jittered.

```yaml
honeypots:
  cowrie:
    stealth:
      enabled: true
      # All identity fields are optional. Left unset, QPot derives a unique,
      # internally-consistent identity + credential persona per instance.
      credential_template: "web-hosting"   # optional: pin a persona
      fake_hostname: ""                      # optional override
      randomize_ssh_version: true
      add_artificial_delay: true
      delay_range_ms: 50
```

- **Normalized SSH algorithm negotiation** — Cowrie's default `KEXINIT` is itself
  a fingerprint: stock Cowrie advertises legacy `blowfish-cbc`/`cast128-cbc`
  ciphers (which OpenSSH hasn't offered by default since 7.0), a *malformed*
  `hmac-sha2-56` MAC name no real server sends, and `zlib`-first compression —
  and that exact list is the well-known, widely-blocklisted "stock Cowrie" HASSH.
  QPot overrides the cipher/MAC/compression lists with a modern, OpenSSH-like set
  (`aes*-ctr` / `hmac-sha2-*` / `none,zlib@openssh.com`), restricted to what
  Cowrie's transport actually implements so negotiation never breaks. *Verified
  live against the real Cowrie 24.04 image:* the server now offers exactly that
  set, removing the obvious tells and moving its HASSH off the blocklisted value.

> **Honest limitation:** config-level deception defeats keyword/Shodan/script
> detection and default-config tells (the bulk of real-world automated
> fingerprinting), and the algorithm normalization above removes the most obvious
> `KEXINIT`/HASSH tells. But it does **not** fully defeat single-packet protocol
> fingerprinting (Vetterl & Clayton, WOOT'18): the **key-exchange** and
> **host-key-algorithm** lists and the deeper packet-level behavior are baked into
> Cowrie's Python (Twisted/`conch`) transport and are not config-controllable, so
> a determined fingerprinter can still tell a normalized Cowrie from real OpenSSH.
> That class is closed **entirely** only by **high-interaction SSH proxy ("HiFi")
> mode** (below), which terminates the attacker's handshake at a real OpenSSH
> daemon — nothing of ours speaks SSH on the wire.

### High-Interaction SSH Proxy (HiFi mode)

To close the protocol-fingerprinting gap *entirely*, QPot can front a pool of
**real OpenSSH backends** with a transparent Layer-4 broker
(`internal/proxy` + `cmd/qpot-sshproxy`, images under `docker/ssh-proxy` and
`docker/ssh-backend`). The broker speaks **no SSH** — it splices opaque TCP bytes
— so the attacker's SSH handshake terminates at genuine OpenSSH and there is no
emulated Python transport to fingerprint. Unlike Cowrie's own "proxy mode" (where
the attacker still handshakes against Cowrie's Python transport), this leaves
nothing of ours on the protocol path.

Because the backend is genuine code execution, it is wrapped in defense-in-depth:
an **egress-locked `internal:true` network** (no outbound — it can never pivot,
scan, mine, or DDoS), a stronger isolation runtime (Kata gives a real guest
kernel and is best for realism; gVisor isolates strongly but is itself
fingerprintable from inside — see the doc), a minimal capability set, resource
caps, per-session **reset**, and full PTY session recording. The broker itself
runs distroless/non-root with **no docker access** and cannot be turned into an
SSRF primitive (backends come only from config). Admission control (per-IP rate +
per-IP/global concurrency caps) bounds load on the finite backend pool.

Enable it with a single command — QPot renders the whole two-service stack
(broker + N egress-locked real-OpenSSH backends, default 2 via
`custom_config["backends"]`), wires the broker to the pool, and starts/stops the
backends together with the broker:

```sh
qpot honeypot enable ssh-proxy   # then: qpot up  (build the docker/ssh-* images first)
```

See **[doc/ssh-hifi-proxy.md](doc/ssh-hifi-proxy.md)** for the architecture, the
full security audit (findings + mitigations), and honest limitations. The broker
and the compose wiring are tested under `-race` and fuzzed (splice transparency,
admission control, `BACKEND_USERS` sanitization, and broker-config round-trip).

### Database Migrations

QPot supports versioned schema migrations for ClickHouse and TimescaleDB:

```yaml
database:
  type: clickhouse
  auto_migrate: true  # Automatically apply migrations on startup
  target_version: 0   # 0 = latest, or specify specific version
```

View migration status:
```bash
./qpot db migrate status
./qpot db migrate up      # Apply pending migrations
./qpot db migrate down    # Rollback one migration
```

### Data Retention Policies

Automated data lifecycle management with hot/warm/cold tiers:

```yaml
database:
  retention_policies:
    - id: default
      name: "90-Day Retention"
      enabled: true
      hot_retention: 2160h      # Keep in hot storage for 90 days
      warm_retention: 4320h     # Move to warm storage for 180 days
      cold_retention: 8760h     # Archive for 365 days
      archive_type: s3          # s3, gcs, or filesystem
      archive_config:
        endpoint: s3.amazonaws.com
        region: us-east-1
        bucket: qpot-archives
        prefix: honeypot-data/
        access_key_id: ${AWS_ACCESS_KEY_ID}
        secret_access_key: ${AWS_SECRET_ACCESS_KEY}
      compression: gzip
      schedule: "0 2 * * *"     # Run daily at 2 AM
```

### Connection Pooling & Read Replicas

Advanced database connection management:

```yaml
database:
  pool:
    max_open_conns: 25
    max_idle_conns: 10
    conn_max_lifetime: 1h
    conn_max_idle_time: 30m
    health_check_interval: 5m
    acquire_timeout: 30s
  
  read_replicas:
    - name: replica-1
      host: 10.0.0.5
      port: 9000
      priority: 1
      weight: 50
      region: us-east-1
    - name: replica-2
      host: 10.0.0.6
      port: 9000
      priority: 2
      weight: 50
      region: us-west-2
```

---

## Threat Intelligence

QPot includes a built-in threat intelligence engine that automatically classifies attacks against the MITRE ATT&CK framework, extracts IOCs, and builds behavioral TTP sessions.

### MITRE ATT&CK Auto-Classification

Every honeypot event is automatically mapped to an ATT&CK technique the moment it arrives. QPot fetches the latest ATT&CK Enterprise knowledge base from MITRE on startup, caches it locally, and falls back to an embedded technique set if offline.

**Dynamic Rule Generation** - QPot analyzes the full ATT&CK dataset to automatically generate classification rules based on:
- Detection strategies from MITRE's `x_mitre_detection` field
- Data sources and platforms
- Keyword extraction from technique names and descriptions
- Cross-platform applicability filtering (non-Windows techniques prioritized)

Rules are merged intelligently via a deduplication system: static built-in rules take precedence by technique ID, and dynamic rules automatically fill gaps for techniques not explicitly covered. This means new ATT&CK techniques are handled without any code changes as long as QPot can reach MITRE's dataset.

**Confidence Scoring** - Every classification includes a confidence score (0.0–1.0) based on rule specificity and data richness:
- `1.0` — Static built-in rules with hand-curated patterns
- `0.6` — Dynamically generated rules derived from ATT&CK data
- Rules are evaluated by priority; first match wins

```
SSH brute force     → T1110.001 - Password Guessing      (Credential Access)
Password spraying   → T1110.003 - Password Spraying      (Credential Access)
wget/curl in shell  → T1105    - Ingress Tool Transfer   (Command & Control)
uname / id / whoami → T1082    - System Info Discovery   (Discovery)
crontab / systemctl → T1053    - Scheduled Task/Job      (Persistence)
sudo / chmod 777    → T1548    - Abuse Elevation Control (Priv. Escalation)
Conpot Modbus probe → T0840    - Network Scanning        (ICS Discovery)
```

Classification runs in real-time on incoming events. A background worker runs every 15 minutes to backfill any events that were stored before classification was active.

### IOC Extraction

QPot automatically extracts and deduplicates indicators of compromise from every event:

- **IP addresses** — public source IPs (RFC1918/loopback filtered)
- **Credential pairs** — username:password combinations attempted
- **URLs** — download URLs from `wget`/`curl` commands
- **File hashes** — MD5, SHA1, SHA256, **SHA512** from captured payloads
- **Crypto wallets** — Bitcoin (base58check-validated) and Ethereum addresses
  dropped by coinminers/ransomware
- **Commands** — shell commands executed in honeypot sessions
- **User agents** — HTTP client fingerprints
- **Domains** — extracted from URLs in commands

Indicators are **refanged before extraction** — defanged notations common in
threat-intel and attacker notes (`hxxp://`, `1.2.3[.]4`, `evil[dot]com`,
`user[at]host`) are normalized first, so IOCs embedded in dropped scripts or
pasted C2 are still captured. The stored command IOC keeps the original text.

### TTP Session Tracking

QPot builds attack campaign sessions using **behavioral fingerprinting**, not naive IP+time-window grouping. Sessions are defined by:

- **Credential set similarity** — same username lists across different IPs = same campaign
- **Tool signatures** — identical download domains, user agents, payload hashes
- **Command pattern overlap** — same shell command sequences
- **Port/service targeting** — same sequence of services probed

Sessions stay open until 30 minutes of inactivity. Shared infrastructure (AWS, GCP, Azure, Tor) is flagged but never assumed to represent a single attacker.

### Intelligence API

| Endpoint | Description |
|----------|-------------|
| `GET /api/techniques` | ATT&CK techniques observed, with event counts |
| `GET /api/iocs` | Extracted IOCs, filterable by type and honeypot |
| `GET /api/ttps` | Active and completed TTP campaign sessions |
| `GET /api/intelligence` | Intelligence summary (techniques, IOC counts, active sessions) |
| `GET /api/ioc` | Unique attacker IP list for firewall blocklist generation |
| `GET /api/iocs/export?format=misp` | Extracted IOCs as an importable MISP event (TIP/SIEM sharing) |

### Intelligence Configuration

```yaml
intelligence:
  enabled: true
  fetch_attck: true              # Fetch latest from MITRE GitHub on startup
  attck_data_path: "./data"      # Local cache path for ATT&CK data
  worker_interval: 15m           # Backfill worker interval
  worker_batch_size: 500         # Events per backfill run
  inactivity_window: 30m         # TTP session inactivity before closing
```

---

## Alerting & Attack-Response Hooks

QPot can fire webhook alerts to Slack, Discord, or any HTTP endpoint when attack
volume crosses a threshold, and/or run local **attack-response hooks** (any
shell command — firewall rule, lockdown script, SOAR runbook).

```yaml
alerts:
  enabled: true
  webhook_url: https://hooks.slack.com/services/...   # optional
  threshold: 100       # Events per minute to trigger
  cooldown: 5m         # Debounce: at most one alert per window (0 = every minute)
  honeypots:           # Leave empty to alert on all
    - cowrie
    - dionaea

# Run user-defined commands when the threshold trips. Fires from the same loop
# as webhooks and works with no webhook configured.
response:
  enabled: true
  on_attack_detected:
    - name: block-top-attacker
      command: 'iptables -A INPUT -s "$QPOT_TOP_SOURCE_IP" -j DROP'
      timeout: 10s     # per-action (default 10s, hard cap 5m)
```

**Debounce (`cooldown`)** prevents alert fatigue: during a sustained attack the
webhook/hooks fire at most once per window instead of every minute.

Hooks receive a stable set of environment variables describing the trigger
(passed as env, never interpolated into the command, so attacker-influenced
values can't inject shell):

| Variable | Meaning |
|----------|---------|
| `QPOT_ID`, `QPOT_INSTANCE` | instance identity |
| `QPOT_TOTAL_EVENTS`, `QPOT_UNIQUE_IPS` | counts in the trigger window |
| `QPOT_THRESHOLD` | the configured threshold that tripped |
| `QPOT_TIMESTAMP` | RFC3339 trigger time (matches the webhook) |
| `QPOT_TOP_SOURCE_IP`, `QPOT_TOP_HONEYPOT` | most active attacker / most-hit honeypot |

Each hook runs under its own timeout and process group (so a forking hook is
killed cleanly at the deadline), with output captured and bounded in the log.

---

## Security Features

| Feature | Implementation | 
|---------|---------------|
| Sandboxing | gVisor, Kata Containers, Firejail (auto-detected)| 
| Resource Limits | CPU, Memory, PIDs, FDs| 
| Filesystem | Read-only root, tmpfs overlays| 
| Capabilities | Drop ALL, minimal add| 
| Seccomp | Custom profiles per honeypot| 
| Network | Isolated per-honeypot networks (per-instance bridge names) | 
| MAC Address | Randomized per container| 
| Hostname | Unique per instance| 
| No credential leak | QPot ID is never mounted or set as env on honeypot containers | 
| Web UI headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy` | 
| Cluster API auth | bcrypt password on join/gossip/intel/leave **and** the read-only `/nodes` & `/status` endpoints | 
| Startup reporting | per-honeypot start/fail status with the failure reason logged | 

---

## CLI Reference

```bash
# Instance management
qpot instance create <name>      # Create new instance with QPot ID
qpot instance list               # List all instances
qpot instance remove <name>      # Remove instance

# Lifecycle
qpot up [--instance <name>]      # Start instance
qpot down [--instance <name>]    # Stop instance
qpot status [--instance <name>]  # Show status

# Honeypot management
qpot honeypot list               # List available honeypots
qpot honeypot enable <name>      # Enable honeypot
qpot honeypot disable <name>     # Disable honeypot

# Docker container management
qpot docker ps                   # List all QPot Docker containers with status
qpot docker logs <container>     # Tail logs for a container (default: 50 lines)
qpot docker restart <container>  # Restart a specific QPot container

# Database
qpot db migrate status           # Show schema version and pending migrations
qpot db migrate up [--to N]      # Apply pending migrations (or migrate to version N)
qpot db migrate down [--yes]     # Roll back the most recent migration

# Yuril Security Suite integration
qpot yuril setup                 # Interactive setup (endpoint, API key, TLS)
qpot yuril test                  # Validate connectivity end-to-end
qpot yuril status                # Show config and live forwarder stats

# Utilities
qpot logs [honeypot]             # View logs
qpot id [--instance <name>]      # Show QPot ID
qpot config [--instance <name>]  # Open instance config in $EDITOR (--print to show path)
```

---

## Cluster Management (Honeypot Groups / Pairing)

QPot lets you **pair multiple honeypot nodes into a managed group** (a cluster)
with password authentication. Members gossip their health and attack stats, and
the **Pairing / Networking** tab in the web dashboard shows every paired
honeypot's online status, uptime, and total requests, plus the group size and
total group activity. Manage groups from the CLI or the UI.

The `cluster` command has `group`, `pair`, and `networking` aliases, so
`qpot group join` / `qpot pair status` work the same as `qpot cluster ...`.

### Initialize a Cluster

Create a new cluster on your central server:

```bash
./qpot cluster init --name production --password "SecurePass123!"

# Output:
# [OK] Cluster initialized successfully
#      Cluster ID:   qc_a1b2c3d4e5f6...
#      Cluster Name: production
#      Node ID:      qn_1234567890ab...
#      Bind Address: 0.0.0.0:7946
#
# [IMPORTANT] Save your Cluster ID and Password!
#             Other nodes will need both to join.
```

### Join a Cluster

Add sensor nodes to the cluster:

```bash
./qpot cluster join \
  --id qc_a1b2c3d4e5f6... \
  --password "SecurePass123!" \
  --seed 192.168.1.10:7946 \
  --node-name sensor-01 \
  --node-addr 192.168.1.20

# Multiple seeds for redundancy:
./qpot cluster join \
  --id qc_a1b2c3d4e5f6... \
  --password "SecurePass123!" \
  --seed 192.168.1.10:7946 \
  --seed 192.168.1.11:7946 \
  --node-name sensor-02
```

### Join Approval (password + host approval)

New clusters require **host approval** in addition to the password
(`require_approval` is on by default). A node that supplies the correct password
is **not** admitted automatically — its request is queued, and `cluster join`
blocks while it polls for the decision. The host reviews pending requests,
seeing the requester's **real source IP** (taken from the connection, not the
request body) and its claimed hostname/instance, then approves or denies:

```bash
# On the host: list requests awaiting approval
./qpot cluster requests --password "SecurePass123!"
# REQUEST ID              HOSTNAME          SOURCE IP         INSTANCE   REQUESTED
# req_8f3a...             sensor-02         192.168.1.21      prod       2026-06-02T...

# Approve (the waiting joiner then completes) or deny:
./qpot cluster approve req_8f3a... --password "SecurePass123!"
./qpot cluster deny    req_8f3a... --password "SecurePass123!"
```

Set `require_approval: false` in the cluster config to restore immediate
admission on correct password.

### Cluster Operations

```bash
# View cluster status
./qpot cluster status

# Output:
# Cluster ID:    qc_a1b2c3d4e5f6...
# Cluster Name:  production
# Status:        running
# 
# Nodes:
#   Total:       5
#   Healthy:     5
#   Suspect:     0
#   Failed:      0
# 
# Events:        1,234,567 total

# List all nodes
./qpot cluster nodes

# Output:
# NODE ID      NAME            ADDRESS          STATUS     EVENTS
# -----------  --------------  ---------------  ---------  --------
# qn_123456..  leader          192.168.1.10:79  healthy    567890
# qn_789abc..  sensor-01       192.168.1.20:79  healthy    333777
# qn_def012..  sensor-02       192.168.1.21:79  healthy    333000

# Leave cluster (run on the node leaving)
./qpot cluster leave
```

### Cluster Features

| Feature | Description |
|---------|-------------|
| Password Auth | All nodes require cluster ID + bcrypt-hashed password to join. Mutation endpoints (leave, gossip, intel) require the cluster password on every request. |
| Automatic Discovery | Nodes discover each other via a custom gossip protocol. |
| Health Monitoring | Failed gossip rounds escalate `healthy` → `suspect` → `failed` based on `suspicion_mult` and `gossip_interval`. |
| Event Aggregation | Each node periodically shares its top source-IP intel with peers; the local manager merges peer reports for a unified attacker view. |
| Encrypted Communication | TLS between cluster members (set `enable_encryption: true` plus `tls_cert_path`/`tls_key_path`; optional `ca_cert_path` for mutual-trust verification). |
| Read Replicas | Database reads distributed across configured replicas (see `read_replicas` in the database config). |

---

## Integration with Yuril Security

QPot ships first-class integration points with the Yuril Security ecosystem.

### Quick setup

```bash
# Interactive: prompts for endpoint, API key (hidden), source label, TLS
qpot yuril setup --instance default

# Validate the integration end-to-end (auth + TLS + reachability)
qpot yuril test --instance default

# Show config and live forwarder stats from the running server
qpot yuril status --instance default
```

`qpot yuril test` submits an empty test batch against the configured
endpoint, distinguishes auth / TLS / network failures in its output, and
returns a non-zero exit code on failure so you can wire it into CI.

### YurilTracking — Outbound IOC Forwarding

Classified IOCs are pushed to a YurilTracking ingest endpoint as soon as the
intelligence worker persists them. The forwarder batches up to 200 indicators
per request, supports bearer-token auth, retries transient failures with
exponential backoff (max 3 retries), refuses to retry 4xx responses (so a
misconfigured request doesn't drown the receiver), and tracks
`batches_sent` / `batches_failed` / `last_success_at` / `last_error` counters
that are visible via `qpot yuril status` and `/api/yuril/health`.

Both directions send and accept an `X-QPot-API-Version` header so the wire
format can evolve safely; mismatched versions return 400 instead of being
silently misinterpreted.

Configure manually (or use `qpot yuril setup`):

```yaml
yuril:
  enabled: true
  endpoint: https://tracking.yuril.local/api/v1/ingest/intel  # replace with your URL
  api_key: ${YURIL_API_KEY}
  source: qpot_honeypot     # producer label sent with every batch
  batch_size: 200
  timeout: 10s
  verify_tls: true
```

Source code: `internal/yuril/forwarder.go`. The wire format mirrors the
`IngestIntelPayload` / `IntelItem` shape defined on the YurilAntivirus side.

### YurilAntivirus — Bidirectional Intel API

QPot exposes two endpoints for pushback from the AV side. Both require the
QPot ID via the `X-QPot-ID` header (or `?qpot_id=` query string) when QPot ID
auth is enabled.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/yuril/health` | GET  | Liveness probe. Returns QPot ID, instance, API version, database reachability, intelligence subsystem state, and live forwarder stats. The response also sets `X-QPot-API-Version`; if the caller sends a mismatched version, it gets a 400 instead of an ambiguous payload. |
| `/api/yuril/intel`  | POST | Push IOCs (ip / domain / url / hash) into QPot's IOC table. Inbound items are tagged `origin=yuril_inbound` so they're auditable. Body capped at 1 MiB. |
| `/api/yuril/query`  | GET  | Look up everything QPot knows about an indicator. Query params: `ip=`, `hash=`, `domain=` (at least one required). Returns recent attacker activity, matching IOCs, and counts. |

Example: when YurilAntivirus quarantines a payload on an endpoint, it can
push the file hash and the C2 domain back to QPot so future honeypot
sessions hitting those indicators are tagged immediately.

```bash
curl -X POST https://qpot.local/api/yuril/intel \
  -H "X-QPot-ID: qp_e2imzc43lisklwokb7vlspi7" \
  -H "Content-Type: application/json" \
  -d '{
    "batch_id": "yav-2024-04-28-001",
    "source": "yuril_av_endpoint",
    "items": [
      {"type": "hash",   "value": "abc123...",       "severity": "high"},
      {"type": "domain", "value": "evil.example.com","severity": "high"}
    ]
  }'
```

### Attack-Response Hooks

QPot can run user-defined shell commands when an alert threshold trips —
this is the real, generic equivalent of the previously-described "lockdown
integration". Hooks fire from the same alert loop that drives webhooks,
get a stable set of environment variables describing the trigger, and run
under a per-action timeout (default 10s, hard cap 5 min).

```yaml
alerts:
  enabled: true
  threshold: 100              # events / minute to trigger

response:
  enabled: true
  on_attack_detected:
    - name: drop-top-attacker
      command: 'iptables -I INPUT -s "$QPOT_TOP_SOURCE_IP" -j DROP'
      timeout: 5s
    - name: notify-yuril-tracking
      command: 'curl -fsS -X POST -H "Content-Type: application/json" \
                -d "{\"qpot_id\":\"$QPOT_ID\",\"events\":$QPOT_TOTAL_EVENTS}" \
                https://tracking.yuril.local/api/v1/qpot/alert'
    - name: trigger-lockdown
      command: '/usr/local/bin/lockdown.sh'
      timeout: 30s
```

Available environment variables: `QPOT_ID`, `QPOT_INSTANCE`, `QPOT_TOTAL_EVENTS`,
`QPOT_TOP_SOURCE_IP`, `QPOT_TOP_HONEYPOT`. Commands run via `sh -c` on
Linux/macOS and `cmd /C` on Windows; output is captured into the structured
log so failed hooks show up next to the alert that fired them.

---

## Deployment Modes

### HIVE (Central Server)

Full installation with web UI, analytics, and sensor management:

```bash
./install.sh -t h -u admin -p 'SecurePass123!'
```

### SENSOR (Distributed)

Lightweight sensor for remote deployment:

```bash
./install.sh -t s
```

### MINI (Resource-Constrained)

Minimal footprint for edge deployments:

```bash
./install.sh -t i -u admin -p 'SecurePass123!'
```

---

## Development

```bash
# Build from source
make build

# Run tests
make test

# Build for all platforms
make build-all

# Create release
make release

# Run locally
make dev
```

---

## Project Structure

```
QPot/
├── cmd/qpot/              # CLI entry point
├── internal/
│   ├── cluster/          # Multi-instance cluster management
│   ├── config/           # Configuration management
│   ├── database/         # Database drivers (CH, TSDB, ES)
│   │   ├── migration.go         # Schema migrations
│   │   ├── retention.go         # Data retention & archival
│   │   └── pool.go              # Connection pooling
│   ├── intelligence/     # Threat intelligence engine
│   │   ├── attck.go             # MITRE ATT&CK loader (fetch + embedded fallback)
│   │   ├── rules.go             # Classification rules (16 built-in)
│   │   ├── classifier.go        # Real-time event classifier
│   │   ├── ioc.go               # IOC extractor
│   │   ├── ttp.go               # Behavioral TTP session builder
│   │   └── worker.go            # Background backfill worker
│   ├── security/         # Sandboxing and isolation
│   ├── instance/         # Instance lifecycle
│   └── server/           # API server
├── docker/
│   ├── attack-map/       # QPot-branded attack map
│   ├── clickhouse-kibana/# ES-compatible CH connector
│   └── nginx/            # Reverse proxy config
├── web/                  # Web UI
├── docs/                 # Documentation
└── scripts/              # Install/update scripts
```

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Acknowledgments

QPot builds upon the excellent work of:

- **[T-Pot CE](https://github.com/telekom-security/tpotce)** by Deutsche Telekom Security - The foundation honeypot platform
- **The Honeynet Project** - Honeypot research and development

QPot adds enterprise features, enhanced security, and integration with the Yuril Security ecosystem.

---

## Support

- **Issues**: [GitHub Issues](https://github.com/YurilLAB/QPot/issues)
- **Support**: Contact via GitHub

---

## Contributors

- **Yuril** - Project lead and primary developer

---

<p align="center">
  <strong>Built by Yuril Security</strong><br>
  <em>Australian-made cybersecurity</em>
</p>

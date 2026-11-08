# Data and threat intelligence

- [How events are collected](#how-events-are-collected)
- [Databases](#databases)
- [The intelligence worker](#the-intelligence-worker)
- [Attack categories](#attack-categories)
- [Worker recovery and health](#worker-recovery-and-health)
- [API](#api)
- [Optional extras](#optional-extras)

## How events are collected

Vector collects every honeypot's JSON log and normalises it:

- source IP and ports, protocol and event type;
- credentials, commands and download URLs.

Each honeypot's own field names are mapped as T-Pot's Logstash pipeline does.
Vector then adds the attacker's country from the GeoIP database and writes the
event to the instance's database. Lines without an attacker address (startup
banners, errors) are dropped. Data is kept for 90 days.

## Databases

| Backend | Notes |
|---|---|
| `clickhouse` | Default. Runs as the instance's `database` container. |
| `timescaledb` | Supported alternative (`database.type: timescaledb`). |

## The intelligence worker

The worker runs every 15 minutes by default; `intelligence.worker_interval`
changes that. It does three things:

- **Classifies** each event with MITRE ATT&CK. It uses 16 curated rules plus
  rules generated from the ATT&CK dataset (fetched from MITRE, with an embedded
  fallback when offline), each with a confidence score. For example, `uname -a`
  maps to T1082, `wget …` to T1105, failed logins to T1110 and Modbus probes to
  T0840.
- **Extracts IOCs:**
  - public attacker IPs and credential pairs;
  - URLs and domains;
  - file hashes, including downloaded payloads;
  - crypto wallets, commands and user agents.

  Defanged indicators such as `hxxp://` or `1.2.3[.]4` are restored first.
- **Groups campaigns**, also called TTP sessions, by shared credentials,
  tooling, commands and targeted services rather than by IP alone.

## Attack categories

Beside the ATT&CK technique, each event is also given plain-language **attack
categories**, so a dashboard or log shows "Path traversal" or "Cryptomining"
rather than only a technique ID. An event can have several, most specific
first; an event that matches nothing has none. A known-vulnerability exploit
is followed by its CVE when one is known, for example
`exploit-attempt, CVE-2021-44228`.

The categories are read from what the honeypot actually recorded — a shell
command, a web request, a Redis command, a connection — and only where that
field means what the category assumes, so accuracy is preferred over coverage:
a near-miss gets no category rather than a wrong one.

The categories are:

- **Scanning and probing** — port scans, banner grabs, crawlers and
  vulnerability scanners looking around.
- **Login guessing** — password guessing, spraying and credential stuffing on
  any service.
- **Known-vulnerability exploit** — an exploit for a named vulnerability
  (Log4Shell, Citrix, Cisco ASA, EternalBlue, router and IoT RCEs), with its
  CVE when known.
- **Path traversal / file read** — `../` and encoded variants, `/etc/passwd`,
  local file inclusion.
- **Remote file inclusion** — pulling in a remote file, or a `php://` or
  `data://` wrapper.
- **SQL injection**, **Cross-site scripting**, **Command injection** (OS
  commands through a web or service parameter) and **Code / template
  injection** (SSTI, OGNL, JNDI, PHP eval, deserialization).
- **Server-side request forgery** — including cloud metadata probing.
- **Secret and config hunting** — `.env`, `.git`, wp-config backups,
  `phpinfo`, actuator, credentials files.
- **File upload** — web-shell uploads, HTTP PUT, SCP/SFTP/FTP/ADB pushes.
- **Web shell use** — requests to a known web shell or a `cmd=` style shell.
- **Host reconnaissance** — looking around after login (`uname`, `whoami`,
  CPU, memory, network, directory listings).
- **Malware / tool download** — `wget`/`curl`/`tftp`/`busybox` fetches and
  `echo` droppers.
- **Privilege escalation attempt** — `sudo`/`su` abuse, SUID hunting, kernel
  and polkit exploits, compiling exploits.
- **Persistence** — SSH keys, cron, services, new users, password changes,
  shell profiles.
- **Credential theft** — reading `/etc/shadow`, SSH keys, cloud credentials,
  history files.
- **Covering tracks** — clearing history and logs, disabling firewalls and
  security tools, killing rival malware.
- **Cryptomining** — miner downloads and configs, mining-pool connections.
- **Botnet loader** — Mirai/Gafgyt-style IoT loaders and busybox probes.
- **Spreading** — scanning or logging in to other machines from the honeypot.
- **Proxy and relay abuse** — SSH port forwarding, open-proxy checks, SMTP
  relaying.
- **Destructive actions** — wiping, `rm -rf /`, fork bombs, ransom notes, DoS
  tools.
- **Industrial control attack** — Modbus/S7/BACnet reads, writes and commands.
- **DDoS amplification** — UDP reflection probes.
- **Database abuse** — Redis `CONFIG SET`/`SLAVEOF`/`MODULE LOAD`,
  Elasticsearch script queries, MSSQL `xp_cmdshell`.
- **VoIP abuse** — SIP scanning, registration guessing, toll fraud.

Events classified before categories existed stay without them; only events
the worker classifies from now on carry categories. The web UI shows the
category label wherever the technique is shown, and the Events view has an
"Attack type" filter.

## Worker recovery and health

Before it marks source events as classified, the worker saves a database
checkpoint and persists its IOC totals and active TTP sessions. Interrupted
batches replay without adding their observations twice.

Run one intelligence worker per database:

- A local OS-account lock prevents duplicate workers on one host.
- Separate hosts, accounts or database-host aliases still need coordinated
  ownership.
- Keep the `qpot/intelligence-locks` state under your OS user configuration
  directory: it reserves revisions across interrupted saves.
- Before moving ownership to another host or account, transfer that state or
  verify that all earlier database requests have finished. Stopping the old
  process alone does not settle requests already in flight.

Canary notifications remain at-least-once across crashes and use their own
direct IOC path. Recovery failures have `QP-INTEL-` codes, which
`qpot doctor --explain` explains.

The authenticated intelligence summary reports the worker's state:

- `worker_status`: `disabled`, `not_started`, `running`, `retrying` or
  `stopped`.
- `worker_healthy`: running without a recorded error.
- On failure, `worker_error_code` and a catalogue-only `worker_error_remedy`,
  without database error details.

A retrying worker keeps its normal cadence. A stopped worker needs the control
plane restarted once its cause is fixed.

## API

| Endpoint | Description |
|---|---|
| `GET /api/techniques` | Observed ATT&CK techniques with counts |
| `GET /api/categories` | Attack categories with their labels and recent counts |
| `GET /api/iocs` | IOCs, filterable by type and honeypot |
| `GET /api/iocs/export?format=misp` | IOCs as a MISP event |
| `GET /api/ioc` | Attacker IP blocklist |
| `GET /api/ttps` | Campaign sessions |
| `GET /api/intelligence` | Summary |

The full API reference is in [api.md](api.md).

## Optional extras

- Events from Suricata, p0f and fatt sensors, turned on with the
  `collector.ingest_` settings.
- A MaxMind-format GeoIP database instead of DB-IP, set with
  `collector.geoip_db_path`.
- Kibana on top of ClickHouse, through the bundled connector in
  [docker/clickhouse-kibana](../docker/clickhouse-kibana/README.md).

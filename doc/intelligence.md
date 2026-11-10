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

The worker runs every 5 minutes by default; `intelligence.worker_interval`
changes that (at least 1 minute: each run that finds new events writes their
tags to the database). A config saved with the earlier 15-minute default moves
to 5 minutes when it is loaded. It does three things:

- **Classifies** each event with a MITRE ATT&CK technique. The event's attack
  categories (below) come first; the technique is then the most specific one
  the recorded evidence supports. For example, `sudo` abuse maps to T1548.003,
  a cron job to T1053.003, a key added to `authorized_keys` to T1098.004,
  `uname -a` to T1082, a `wget` fetch to T1105, failed logins to T1110, a
  Modbus read to T0801 and a write to a controller to T1692.001 (Command
  Message). Every category has a technique, and the rules use current ATT&CK
  IDs (v18), never revoked ones such as T1562.001. Rules generated from the
  ATT&CK dataset (fetched from MITRE, with an embedded fallback when offline)
  cover other commands; a shell command that matches nothing more specific
  gets T1059.004 (Unix Shell) at low confidence. Each technique carries a
  confidence score.
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

Workers acquire an exclusive lease from the database before recovering a
checkpoint or classifying events. The database assigns a monotonically
increasing fencing token and reserves checkpoint revisions globally, so another
host, account or hostname alias cannot independently reuse a revision. The
30-second lease is renewed every 10 seconds, independently of the batch cadence.
Expiry is evaluated by the database rather than the worker's wall clock.

PostgreSQL/TimescaleDB and Elasticsearch use atomic control records. ClickHouse
requires Keeper and strict KeeperMap compare-and-swap operations; its ordinary
ReplacingMergeTree tables cannot provide exclusive ownership. If coordination
is unavailable, the worker stops with `QP-INTEL-008`; event collection and the
rest of the control plane remain available.

QPot's managed ClickHouse deployment configures persistent embedded Keeper in
the database container. Its coordination ports are never published to the host;
keep the database's trusted container networks separate from attacker-facing
networks. External ClickHouse installations must provision Keeper themselves.
The initial ClickHouse implementation supports one physical database catalog
with local MergeTree datasets; it rejects distributed, replicated and view-based
datasets rather than allowing separate catalogs to claim the same work.

PostgreSQL uses the database-wide `qpot_intelligence` coordination schema and
binds it to the actual event and projection tables. Provision that schema once
with an administrator before using a restricted worker role; normal workers
need access to its existing tables, not permission to create schemas. Different
search paths cannot create independent ownership of the same projections.

The lease record also publishes the exact prepared checkpoint before its IOC,
session and event-tag writes. A successor recovers that same durable record.
An already accepted old projection can finish, but uses the same recorded
payload at an older globally reserved revision. A stale owner cannot publish a
different checkpoint, reserve another revision or complete a batch after
takeover. Worker replay requires concrete database event IDs; it never falls
back to tagging other rows by source IP and timestamp.

Loss of ownership or an ambiguous renewal cancels current work, prevents a new
background shutdown drain, and stops the worker with `QP-INTEL-007`. An ordinary
shutdown can make one bounded recovery attempt while its lease is still valid.
Releasing a lease preserves its fencing and revision history. It does not delete
the ownership record. After an ungraceful exit, the expired lease can be acquired
by another updated control plane.

A local OS-account lock remains as additional exclusion. Keep its
`qpot/intelligence-locks` state under the OS user configuration directory: its
checked counter supplies the migration revision floor. Before upgrading to the
lease protocol, stop all older workers and settle their in-flight database
requests. Older binaries do not send fencing tokens and cannot safely run
alongside the upgraded workers. Preserve existing checkpoints and local
reservation files; do not delete ownership state to force a takeover.

Canary notifications remain at-least-once across crashes and use their own
direct IOC path. Recovery failures have `QP-INTEL-` codes, which
`qpot doctor --explain` explains.

The authenticated intelligence summary reports the worker's state:

- `worker_status`: `disabled`, `not_started`, `running`, `retrying` or
  `stopped`.
- `worker_healthy`: running without a recorded error.
- On failure, `worker_error_code` and a catalogue-only `worker_error_remedy`,
  without database error details.

A worker waiting for its first lease is `not_started`, not healthy. A retrying
worker keeps its normal cadence. Ownership loss is `stopped`, including while
an already accepted server request is returning. A stopped worker needs a new
control-plane start once its cause is fixed.

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

## Industrial device events

Conpot events retain the logged device profile in `metadata.device_profile` when
it is a supported template. This describes the device used when the event was
recorded, including queued logs from before a profile change. Modbus events also
retain validated function code, unit ID, operation and exception code when
available. Ordinary reads become `conpot.modbus.read`, attempted control writes
become `conpot.modbus.command`, and unsupported or ambiguous operations remain
requests. A read alone is not labeled an unauthorized control command. Both
current `protocol` logs and older `data_type` logs are accepted.

A bare Conpot connection or ordinary read is retained as telemetry without
claiming a discovery technique. An explicit probe can yield a low-confidence
T0846 Remote System Discovery candidate; it is not proof of a port scan.
T0840 is Network Connection Enumeration, not a catch-all incoming connection
label. Control-write attempts keep the existing T0855 compatibility mapping;
that tag does not prove an accepted command or a physical state change. ATT&CK
v20 reorganizes command-message techniques; existing stored IDs are not silently
rewritten by this update.

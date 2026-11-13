# Data and threat intelligence

- [How events are collected](#how-events-are-collected)
- [Databases](#databases)
- [The intelligence worker](#the-intelligence-worker)
- [Sessions and campaigns](#sessions-and-campaigns)
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
event to the instance's database. An event's `timestamp` is when the collector
read its line; the time the honeypot itself gave it, when its log has one, is
kept in `metadata.observed_at`. Lines without an attacker address (startup
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
- **Builds TTP sessions and campaigns:** one session per attacking source,
  and a campaign fingerprint that links sources only on strong shared
  evidence. See [Sessions and campaigns](#sessions-and-campaigns).

## Sessions and campaigns

A **TTP session** is one activity episode of one source: every event from an
IPv4 address, or from an IPv6 /64, until the source has been quiet for
`intelligence.inactivity_window` (30 minutes by default). What the source ran
and which honeypots it reached do not matter: its events all join the one
session, and two sources never share a session. A source that comes back after
its session closed starts a new session with a new `session_id`. Events
without a usable source address go to one "unknown source" session per
honeypot, which lists no address.

**When the address is Docker's, not the visitor's.** Docker forwards some
connections from its own address: those made from the host itself, and all
of them on Docker Desktop, rootless Docker or a daemon without its
packet-filter rules. The collector marks every event whose source lies
inside one of the instance's own Docker networks (`metadata.source_shared`).
Such an address is not a source. Keyed by it, every visitor would be one
session and one campaign. Instead:

- a marked event that carries the honeypot's own session ID (Cowrie and the
  HiFi proxy give one) belongs to the session of that one connection;
- a marked event without one goes to the honeypot's "unknown source"
  session;
- the session lists no source address and has `shared_infrastructure` set;
- the address is never recorded as an indicator.

`qpot doctor` shows how many of the last day's events were marked. See
[release.md](release.md#source-addresses) for where this happens.

A **campaign** is a set of sessions with the same `campaign_fingerprint`.
Sessions of different sources get the same fingerprint only when they share
strong evidence:

| Evidence | What is compared |
|---|---|
| Payload | The SHA-256 of a file the source downloaded or uploaded (not the empty file). |
| Download host | The host of a URL in a command, a download or a web request. Private addresses and "what is my IP" services do not count. |
| Command sequence | The source's first five distinct shell commands, in order, identical apart from whitespace. |

One common command such as `uname -a` never links two sources, and neither
does a user agent or a credential pair. Links are transitive: if A shares a
host with B and B shares a payload with C, all three are one campaign. The
result does not depend on the order events arrive in. A session with no strong
evidence is a campaign of its own.

A session's `session_id` never changes. Its `campaign_fingerprint` and
`confidence` can: when a later source turns out to share its evidence, the
worker rewrites the stored session. A session that has already closed is not
rewritten, so when two campaigns are found to be one, the closed sessions of
one of them keep the fingerprint they had. The evidence of a closed session
stays linked to its campaign while the campaign has an open session.

The fingerprint is 32 hex characters (128 bits of a SHA-256). Sessions stored
by earlier versions have 8, and are not linked to newer ones.

**Confidence** says how strong the evidence is that the session's events
belong to one campaign. It does not grow with the number of events.

| Situation | Confidence |
|---|---|
| Unknown-source session | 0.1 |
| One source, a cloud address (`shared_infrastructure`) | 0.3 |
| One source | 0.5 |
| Shares a command sequence with another source | remaining doubt × 0.5 |
| Shares a download host with another source | remaining doubt × 0.3 |
| Shares a payload with another source | remaining doubt × 0.2 |
| Also shares a user agent or credential pair inside the campaign | remaining doubt × 0.8 |

Doubt is 1 minus confidence, and the factors multiply. A single source that
shares a download host scores 1 - 0.5 × 0.3 = 0.85; with a shared payload as
well, 0.97, which is capped at 0.95. `shared_infrastructure` is true when any
address of the session is in a known cloud range.

To see which evidence links the sessions of a campaign, and the records that
show it, open the campaign's case ([investigate.md](investigate.md)).

The worker bounds what it keeps per session (32 hosts and payloads, the
earliest seen) and in total (200,000 evidence entries, 100,000 open sessions
after each run). At a limit the events are still counted, but new evidence is
not recorded until sessions close, so those sources are not linked.

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

## Events stored twice

The collector gives every log line an ID derived from the line. When it loses
its place it sends its logs again, and each line arrives as a second row with
the ID it already had. The worker counts such a line once and deletes the
extra row:

- It looks through the unclassified rows a window at a time for IDs it has
  already classified and deletes those rows, wherever they are in time:
  every 30 seconds while it has more than one batch to classify, and before
  each batch once it is finding copies (in a sweep or in a batch). New
  events and second copies take turns: never two such sweeps without a
  batch of classification between them. A worker that keeps up does not
  look ahead: its batch reads every unclassified row there is, copies
  included, so the first copies of a collector that lost its place are
  found in the worker's next pass (`worker_interval`, 5 minutes by
  default).
- When it reads a batch, a row whose ID is already classified, or that
  repeats an earlier row of the batch with a later time, is deleted before
  anything is counted.
- Two rows with the same ID and the same time (the line was read twice before
  either was classified) cannot be told apart by any column. Both are
  tagged, and then the extra one is deleted by where it is stored, so one
  row stays.

A row is a second copy only while the first is there. `qpot db restore`
stores events the events table no longer has, and where the table lost rows
the worker had classified (a part the server set aside after a crash, a
dropped partition) it takes their IDs out of the set of classified IDs
first: the restored rows are then new events, classified again, and not
copies to delete (`TestClickHouseRestoredRowsAreNotSecondCopies`).

The sweep and the last rule are ClickHouse's. On TimescaleDB every row has
its own serial number, so rows with the same ID and time are told apart by
it, and a second copy is removed when the worker reads it, in time order.

On ClickHouse, events are marked classified with lightweight updates: each
batch writes a small patch with the changed values of its own rows, instead
of rewriting the changed columns of every part that holds one of them. An
events table created by an earlier version gets the two table settings this
needs (`enable_block_number_column`, `enable_block_offset_column`) when the
control plane starts; rows stored before keep working. Reads apply the
patches until they are written into the parts: once they hold 2,000 rows,
the worker starts `ALTER TABLE events APPLY PATCHES` in the background, at
most every 30 seconds. A server that refuses the settings is tagged with
mutations as before, which is slower.

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

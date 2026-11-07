# Data and threat intelligence

- [How events are collected](#how-events-are-collected)
- [Databases](#databases)
- [The intelligence worker](#the-intelligence-worker)
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

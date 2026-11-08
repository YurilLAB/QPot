# QPot web API

The web UI and every script talk to the same HTTP API, served by the
instance's control plane (`qpot up`, `qpot up -d` or `qpot serve`) on the web
UI address (`http://127.0.0.1:8080` unless `qpot setup` chose another port).
This page lists every endpoint, what it answers and how it fails.

- [Signing in](#signing-in)
- [Writes and CSRF](#writes-and-csrf)
- [Errors](#errors)
- [What the API never returns](#what-the-api-never-returns)
- [Instance and honeypots](#instance-and-honeypots)
- [Events and statistics](#events-and-statistics)
- [Threat intelligence](#threat-intelligence)
- [Canaries](#canaries)
- [Cluster](#cluster)
- [Health checks and error codes](#health-checks-and-error-codes)
- [Attack map stream](#attack-map-stream)
- [Public paths](#public-paths)
- [Host-only on purpose](#host-only-on-purpose)

## Signing in

Every `/api/` request carries the instance's QPot ID (`qpot id` shows it) in
one header:

```bash
curl -H "X-QPot-ID: qp_..." http://127.0.0.1:8080/api/status
```

| Request | Answer |
|---|---|
| no header | `401 {"error":"QPot ID required"}` |
| an ID of the wrong shape (not `qp_` and 27 characters) | `401 {"error":"Invalid QPot ID format"}` |
| a well-formed ID of another instance | `403 {"error":"QPot ID does not match this instance"}` |

Only the header counts: a QPot ID in the URL is ignored, so it never lands in
a proxy log or the browser history. Downloads (the MISP export, a file
canary) are fetched with the header like any other request.

With `web_ui.qpot_id_auth: false` and a web UI user name and password set, HTTP
Basic authentication is used instead.

The API listens on `127.0.0.1` by default. From another machine use an SSH
tunnel (`ssh -L 8080:127.0.0.1:8080 <host>`).

## Writes and CSRF

`POST`, `PUT` and `PATCH` must send `Content-Type: application/json`
(`; charset=utf-8` is fine). Anything else gets
`415 {"error":"Content-Type must be application/json"}`. A cross-site HTML form
cannot send that type, so this is the API's CSRF guard. `DELETE` takes query
parameters and no body.

Request bodies are capped (each endpoint gives its size); a larger body gets
`400`. The honeypot endpoints also refuse unknown fields and anything after the
JSON object.

## Errors

Errors are JSON:

```json
{"error": "Unknown honeypot.", "code": "QP-INPUT-003"}
```

- `error` is a plain sentence for a person.
- `code` is present when a QPot error code fits. `GET /api/doctor/explain?code=`
  gives its title, cause and fix (the same text as `qpot doctor --explain`).
- A `500` says only `"internal error"`. What went wrong is in the server's log
  (`<instance>/logs/qpot-serve.log`), never in the answer.
- A wrong method gets `405`. The newer endpoints answer
  `{"error":"method not allowed (use GET)"}`; older ones a plain-text body.
- Some errors add fields: `"saved": true` (the change was saved, a later step
  failed) and `"needs": [...]` (settings the request must also send).

## What the API never returns

No answer carries the QPot ID (the caller has it), the database password, the
web UI password, alert webhook URLs, response hook commands, LLM API keys, the
cluster password or keys, a join request's poll secret, or another node's
QPot ID. A test calls every route with all of these planted in the
configuration and fails if any comes back, also when the database's errors
quote its password.

## Instance and honeypots

### GET /api/status

```json
{"instance": "default", "overall": "running", "database": "clickhouse",
 "honeypots": [{"name": "adbhoney", "running": false, "status": "disabled", "port": 5555, "risk": "low"}]}
```

While the instance runs, `honeypots` lists every configured honeypot, sorted
by name (`"status"`: `healthy`, `unhealthy`, `starting`, `stopped` or
`disabled`). When it is stopped, `overall` is `stopped` and `honeypots` is `[]`.

### GET /api/instance

Facts for an "about this instance" page:

```json
{
  "name": "default",
  "version": "v0.9.0",
  "web_ui": {"bind_addr": "127.0.0.1", "port": 8080, "auth": "qpot-id"},
  "status": "running",
  "honeypots": [
    {"name": "cowrie", "enabled": true, "risk": "medium", "description": "SSH/Telnet medium-interaction shell",
     "host_ports": [{"container_port": 22, "host_port": 12345, "protocol": "tcp"}], "has_settings": true}
  ],
  "services": [{"name": "database", "state": "running", "health": "healthy"}],
  "services_error": "",
  "database": {"type": "clickhouse", "connected": true, "healthy": true, "schema_version": 3},
  "geoip": {"configured": true, "present": true, "file": "dbip-country-lite.mmdb",
            "updated": "2026-11-01T03:12:00Z", "age_days": 6, "size_bytes": 4123456,
            "attribution": "IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0",
            "update_command": "qpot geoip update -i default"},
  "attack_map": {"country": "AU"},
  "canary": {"enabled": true, "base_url": "https://canary.example.net"},
  "intelligence": {"enabled": true, "worker_running": true},
  "alerts": {"enabled": false, "webhook_configured": false, "response_hooks": 0},
  "cluster": {"clustered": false}
}
```

- `honeypots`: every honeypot QPot ships, by name. `host_ports` are the ports
  the compose file publishes (`[]` for a honeypot that is off). `has_settings`:
  `/api/honeypots/settings` applies to it.
- `status`: `running` (a container runs), `stopped`, or `unknown` with
  `services_error` saying why (Docker not reachable). `services` is sorted by
  name.
- `database.error` appears only when the database is not healthy, as a plain
  sentence.
- `geoip.file` is a base name. `updated`, `age_days` and `size_bytes` appear
  only when the file is present.
- `web_ui.auth`: `qpot-id`, `basic` or `none`. `canary.base_url`: scheme, host
  and path only.
- Paired: `"cluster": {"clustered": true, "name", "nodes", "healthy", "running", "live"}`
  (see [Cluster](#cluster)).

### GET /api/honeypots

```json
[{"name": "adbhoney", "enabled": false, "running": false, "port": 5555, "risk": "low"}]
```

Sorted by name, read from the configuration file as it is now (changes made
with the CLI show up).

### POST /api/honeypots

Turns a honeypot on or off exactly as `qpot honeypot enable` / `disable` do:
the configuration file is read as it is now, checked, saved, and the
honeypot's container is started or stopped when the instance is running.

Body (at most 4 KiB): `{"name": "cowrie", "enabled": true}`. `enabled` is
required.

```json
{"status": "ok", "name": "cowrie", "enabled": true, "saved": true, "instance_running": true,
 "applied": true, "message": "Turned cowrie on and started it."}
```

When the instance is not running, `applied` is false and the change takes
effect when it starts.

| Status | When |
|---|---|
| 400 `QP-INPUT-003` | unknown honeypot |
| 400 | no `enabled`, or a malformed body |
| 400 `QP-INPUT-012` + `needs` | an LLM honeypot (galah, beelzebub) has no LLM settings yet: set them first with `PUT /api/honeypots/settings` |
| 409 | another honeypot change is still running |
| 502 `QP-INST-008` + `"saved": true` | saved, but the container did not start or stop; the error points at `GET /api/logs?honeypot=<name>` |
| 500 `QP-INST-002` | the configuration file could not be read or saved (nothing changed) |

### GET /api/honeypots/settings

`?name=cowrie` for one honeypot; without it,
`{"honeypots": [<view>, ...]}` for every honeypot that has settings (today
beelzebub, conpot, cowrie, galah and ssh-proxy), sorted by name.

```json
{
  "name": "cowrie",
  "enabled": true,
  "settings": [
    {"key": "persona", "value": "", "set": false, "effective": "debian-bookworm", "type": "choice",
     "allowed": ["ubuntu-jammy", "debian-bookworm"], "secret": false, "required": false, "help": "..."},
    {"key": "persona_rotation", "value": "30", "set": true, "type": "number", "min": 0, "max": 365,
     "secret": false, "required": false, "help": "..."}
  ],
  "missing": []
}
```

- `type`: `choice` (one of `allowed`), `number` (`min` to `max`), `url`
  (http or https), `name` (letters, digits and `. _ : / @ + -`, at most 200),
  `secret` (write-only).
- `effective` (left out when it equals `value`) is what the honeypot runs with
  when the setting is unset.
- A secret's `value` is always `""`; `set` says whether one is stored.
- `missing` lists required settings that are still unset.
- `400 QP-INPUT-003` for an unknown name, `500 QP-INST-002` when the
  configuration file cannot be read.

### PUT /api/honeypots/settings

The same as `qpot honeypot set` (the same Go function). Body (at most 16 KiB,
at most 32 keys):

```json
{"name": "cowrie", "settings": {"persona": "ubuntu-jammy", "bait": "off"}}
```

`""` removes a setting. Every key and value is checked before anything is
saved. The honeypot is then recreated when it is on, has its LLM settings and
the instance runs (the request waits up to 5 minutes for Docker).

```json
{"name": "cowrie", "saved": true, "enabled": true, "instance_running": true, "recreated": true,
 "missing": [], "settings": ["...as GET..."], "message": "Updated cowrie settings and recreated cowrie with them."}
```

| Status | When |
|---|---|
| 400 `QP-INPUT-003` | unknown honeypot |
| 400 `QP-INPUT-012` | a bad key or value; the error names the rule (values are never repeated) |
| 400 `QP-INPUT-012` + `needs` | a change that decides where a stored secret is sent (galah `llm_server_url` or `llm_provider` while `llm_api_key` is stored) must send `llm_api_key` again |
| 400 | malformed body |
| 409 | another honeypot change is still running |
| 502 `QP-INST-008` + `"saved": true` | saved, but the honeypot did not restart with them |
| 500 `QP-INST-002` | the configuration could not be saved |

URL settings (`llm_server_url`, `llm_host`) refuse link-local and cloud
metadata addresses, also behind a host name. A name the server cannot look up
(a container name) is refused with the host command that sets it instead.

### POST /api/honeypots/restart

Body (at most 4 KiB): `{"name": "cowrie"}`. Restarts the honeypot's container
and its companions (ssh-proxy's backends, tanner's).

```json
{"name": "cowrie", "restarted": true}
```

`400 QP-INPUT-003` unknown honeypot; `409` honeypot off, instance not running
(`QP-INST-007`) or another change running; `502 QP-INST-008` Docker failed.

### GET /api/logs

`?honeypot=cowrie&tail=100`: the honeypot's container log, newest last, as
`["line", ...]`. `tail` defaults to 100; more than 5000 gives 5000. At most
10000 lines come back. Without `honeypot`, every container's log. `400` for an
unknown honeypot.

### GET /api/overview

The instance overview (host load, 24-hour activity per honeypot, latest
events, cluster), the same data as `qpot overview`.

## Events and statistics

### GET /api/events

Query parameters, all optional. Repeatable ones may be given several times or
comma-separated, at most 20 values each.

| Parameter | Values |
|---|---|
| `honeypot` | `[a-z0-9][a-z0-9-]{0,63}` (e.g. `cowrie`, `canary`) |
| `source_ip` | IPv4 or IPv6 without a zone; matched in canonical form (`2001:DB8::1` finds `2001:db8::1`) |
| `event_type` | `[A-Za-z0-9_.:-]{1,64}` |
| `category` | an attack category ID (see `GET /api/categories`); keeps events with any of them |
| `country` | two letters |
| `since`, `until` | RFC 3339 or unix seconds; `until` not before `since` |
| `q` | text found (any case) in the user name, password, command or payload (Elasticsearch: not the payload); at most 200 bytes, no control characters |
| `limit` | 1 to 1000, default 100 |
| `offset` | 0 to 100000 |

```json
{"events": [{"timestamp": "...", "honeypot": "cowrie", "source_ip": "198.51.100.7", "...": "..."}],
 "limit": 100, "offset": 0, "has_more": true, "next_offset": 100}
```

Newest first. `payload` is base64. A bad value is refused, not ignored:
`400 {"error":"Bad filter: <parameter>: <why>."}`. `503 QP-INST-005` when the
database is not available. Every value reaches the database as a bound query
parameter (ClickHouse, TimescaleDB) or a JSON value (Elasticsearch), never as
query text.

### GET /api/stats

The last 24 hours:

```json
{"total_events": 18630, "unique_ips": 412,
 "top_countries": [{"country": "CN", "count": 3120}], "top_honeypots": [{"honeypot": "cowrie", "count": 9001}]}
```

### GET /api/pulse

`?range=24h` (default), `1h` or `1m`: the landing page's timeline, already
counted by the database.

| Range | Slots |
|---|---|
| `24h` | 48 of 30 minutes |
| `1h` | 60 of 1 minute |
| `1m` | 30 of 2 seconds |

```json
{"range": "24h", "total": 9120, "previous": 8804,
 "slots": [{"key": 1794048000000, "n": 180}],
 "before": [{"key": 1793961600000, "n": 171}],
 "types": [{"type": "cowrie", "n": 6100, "slots": [{"key": 1794048000000, "n": 120}]}],
 "sources": 233, "honeypots": 9, "latest": 1794133412345,
 "top_sources": [{"ip": "198.51.100.7", "n": 410, "country": "Germany", "rep": ""}],
 "sensors": []}
```

- Slots are aligned to their size (from midnight UTC), so a slot keeps its
  `key` (start, unix milliseconds) from one answer to the next. The range ends
  with the slot that holds the current time.
- `before` is the range just before, slot for slot; `previous` its total.
- `types`: the 7 busiest honeypots in the range with their own slots, by count
  and then name. `honeypots` counts every honeypot with events in the range.
- `sources`: distinct source addresses in the range. `top_sources`: the 12
  busiest, with the country's name when its code is known. `rep` is always
  `""` (QPot has no reputation feed).
- `latest`: the newest event in the range (unix milliseconds), left out when
  there is none. `sensors` is `[]`.
- An answer is reused for 2 seconds per range.
- `400` for another range, `503 QP-INST-005` without a database.

## Threat intelligence

| Endpoint | Answer |
|---|---|
| `GET /api/ioc` | attacker IPs of the last 24 hours, most attacks first: `{"generated", "count", "ioc_list": [{"source_ip", "country", "attack_count", "honeypots", "first_seen", "last_seen"}]}` |
| `GET /api/iocs?type=&honeypot=&limit=` | IOCs (`limit` 1 to 1000) |
| `GET /api/iocs/export?format=misp&type=&honeypot=&limit=` | the IOCs as a MISP event (a download) |
| `GET /api/techniques` | `[{"technique_id", "technique_name", "tactic_name", "count"}]`, most first |
| `GET /api/categories` | `[{"id", "label", "description", "count"}]`, in catalogue order; the plain-language attack categories and how many recent events carry each |
| `GET /api/ttps?limit=` | campaign sessions (`limit` 1 to 500) |
| `GET /api/intelligence` | `{"techniques_observed", "iocs_total", "active_sessions", "worker_enabled", "attck_loaded"}` |

Lists ranked by a count keep one order: equal counts are ordered by name or
address, in every database backend.

## Canaries

| Endpoint | What it does |
|---|---|
| `GET /api/canaries` | `{"canaries": [...]}` |
| `POST /api/canaries` | body (at most 8 KiB) `{"kind": "web" \| "file" \| "aws", "name", "memo"}` makes one |
| `DELETE /api/canaries?id=` | removes one; `409` for a canary planted in a honeypot |
| `GET /api/canaries/trips?limit=` | `{"trips": [...]}` (`limit` 1 to 1000) |
| `GET /api/canaries/artifact?id=` | a file canary's HTML (a download); `400` without `id`, `404` for an unknown one |

## Cluster

### GET /api/cluster

```json
{"clustered": true, "live": true,
 "group": {"id": "qc_...", "name": "lab", "node_count": 2, "healthy_nodes": 2, "...": "..."},
 "nodes": [{"name": "sensor-1", "address": "10.0.0.1:7946", "online": true, "status": "healthy",
            "uptime_seconds": 3600, "total_events": 0, "active_attacks": 0, "is_local": true}]}
```

Standalone: `{"clustered": false, "live": false}`. `nodes` are sorted by name;
`is_local` marks this node.

`live` is true when this control plane runs the cluster, so members and health
are current. It is false when another instance's control plane on this host
runs it: the answer is then `cluster.json` as it was when the server started.

### GET /api/cluster/requests

Join requests waiting for the host's approval. Read-only: approving and
denying stay on the host, and the answer gives the commands.

```json
{"clustered": true, "live": true, "requests": [
  {"request_id": "reqc07431c05c348ee5", "node_name": "sensor-2", "claimed_address": "10.0.0.7",
   "source_ip": "198.51.100.7", "requested_at": "2026-11-07T11:43:30.576Z",
   "approve_command": "qpot cluster approve reqc07431c05c348ee5",
   "deny_command": "qpot cluster deny reqc07431c05c348ee5"}]}
```

- Newest first. `source_ip` is where the request came from; `claimed_address`
  is what the joiner says it is.
- Standalone: `{"clustered": false, "live": false, "requests": []}`.
- When another instance's control plane runs the cluster, `requests` is `[]`,
  `message` says where to look and `runs_on_instance` names that instance when
  known.
- `405` for anything but GET.

## Health checks and error codes

### GET /api/doctor

`qpot doctor`'s checks, read-only: nothing is installed, started or changed,
and nothing runs with sudo.

```json
{"ok": false, "first_fail_code": "QP-INST-008",
 "failure": {"code": "QP-INST-008", "title": "A part of the instance is not running properly.",
             "cause": "...", "fix": "..."},
 "ran_at": "2026-11-07T01:02:03Z", "cached": false,
 "checks": [{"section": "host", "name": "docker", "level": "ok", "detail": "installed", "code": ""},
            {"section": "instance", "name": "honeypot cowrie", "level": "fail", "detail": "exited",
             "code": "QP-INST-008", "title": "A part of the instance is not running properly."}]}
```

- `level`: `ok`, `warn` or `fail`. `failure` (absent when nothing failed) is
  the first failed check's code with its cause and fix, host checks first, as
  `qpot doctor` ends.
- One run at a time; a report is reused for 10 seconds (`"cached": true`). A
  run takes well under a second normally and at most about 90 seconds.
- Secrets in a check's detail are replaced by `[hidden]`.

### GET /api/doctor/explain

`?code=QP-PKG-001` (also `qp-pkg-1` or `PKG 001`, as `qpot doctor --explain`
takes them):

```json
{"code": "QP-PKG-001", "title": "...", "cause": "...", "fix": "...", "category": "PKG",
 "category_name": "Package manager", "exit_status": 14}
```

`400 QP-INPUT-011` without a code, `404 QP-INPUT-011` for an unknown one. The
input is never repeated in the answer.

### GET /api/doctor/codes

Every category and code, in catalogue order:
`{"categories": [{"key", "name", "exit_status"}], "codes": [<as explain>]}`.
[setup-errors.md](setup-errors.md) has the same list.

## Attack map stream

`GET /api/map/stream` is a `text/event-stream` of T-Pot's attack map messages.
It has a limit on viewers (`429` when full). Every `Stats` message
(`{"type": "Stats", "last_1m", "last_1h", "last_24h"}`) also carries the
sensor's place when it is known: `dst_lat`, `dst_long`, `dst_iso_code` and
`dst_country_name`. That place comes from the configured `attack_map`
location or the host's time-zone country, never from a lookup of the host's
public address.

## Public paths

These need no QPot ID: the pages (`/`, `/map/`, `/dashboard`, which ask for the
ID themselves), their static files under `/assets/` and `/map/`,
`/favicon.ico`, and `/c/<token>` (the canary beacon an attacker's tools call).

## Host-only on purpose

| On the host | Why not in the API | The UI shows |
|---|---|---|
| `qpot cluster init / join / leave / approve / deny` | cluster passwords and keys; approving a node is the operator's call | the command to run |
| `qpot setup`, installing Docker | privileged, changes the host | `qpot setup` |
| `qpot instance create / remove / list` | other instances' IDs and data | nothing |
| `qpot db migrate up / down` | can drop data | the schema version |
| `qpot config` (alerts, webhook, response hooks, database) | response hooks run shell commands; webhook URLs carry credentials | a summary |
| `qpot up / down` | the API is served by the control plane itself | the status |

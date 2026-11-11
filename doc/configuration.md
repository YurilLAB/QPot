# Configuration

Each instance keeps its settings in one file, `config.yaml`, in the instance's
folder. `qpot config -i <name> --print` shows where it is.

Most settings never need editing by hand: `qpot setup`, `qpot honeypot set`
and the web UI's dashboard change them for you and check the values first.
Edit the file directly for the less common settings below, then restart the
instance so it picks them up:

```bash
qpot down -i <name>
qpot up -d -i <name>
```

## Commonly changed settings

```yaml
web_ui:
  port: 8080

database:
  type: clickhouse            # or timescaledb

honeypots:
  cowrie:
    enabled: true
    resources:
      use_custom_limits: true
      max_cpu_percent: 30
      max_memory_mb: 256
      max_pids: 50

intelligence:
  worker_interval: 5m            # default 5m; at least 1m

cleanup:                         # see disk-cleanup.md
  enabled: true
  max_age_days: 30               # captured files, rotated logs and backup days
  max_log_mb: 256                # empty a collected log above this
  max_backup_mb: 2048            # the collector's backup folder
  min_free_mb: 512               # disk guard: stop the honeypots below this much free disk space; 0 = off
  resume_free_mb: 1024           # disk guard: start them again at this much; must be greater than min_free_mb

security:
  network_isolation:
    block_outbound: false        # true: honeypots open no outbound connections at all
    allow_private_egress: false  # true: switch the egress guard off (emulators only; not recommended)

stealth:
  block_common_probes: true      # tag events that name a scanner (metadata.scanner)
  blocked_probes: [nmap, masscan, zgrab, censys, shodan]
```

`stealth.block_common_probes` no longer drops anything, despite its name.
Until 1.0.1 an event whose text named one of `blocked_probes` was discarded
before it was stored, so an attacker running `nmap` inside a honeypot left no
event. Now every event is stored and classified; one that names a scanner
gets `metadata.scanner` set to the name that matched, so a query, a dashboard
or an alert rule can leave scanner noise out after the fact.

These `security` settings are mandatory controls and cannot be switched off:
`read_only_filesystem`, `drop_capabilities`, `no_new_privileges` and
`network_isolation.separate_networks`. `false` is ignored with a warning. See
[security.md](security.md) for what each one does and which settings are
refused for which honeypots.

`web_ui.qpot_id_auth: false` without both `web_ui.username` and
`web_ui.password` leaves the API with no login. QPot allows that only on a
loopback `web_ui.bind_addr`.

## Honeypot settings

Each honeypot's own settings, such as the Cowrie persona or the Conpot
device, are changed with `qpot honeypot set`:

```bash
qpot honeypot set cowrie persona=rhel-9
qpot honeypot set cowrie persona_rotation=30
qpot honeypot set cowrie bait=off
qpot honeypot set cowrie persona=debian-bookworm bait_profile=industrial
qpot honeypot set cowrie bait_target=refrigeration
qpot honeypot set cowrie deception=stock      # control arm of a comparison only
qpot honeypot set refrigeration site_profile=plasma
qpot honeypot profiles conpot
qpot honeypot set conpot template=plc_modbus
```

`deception=stock` runs the T-Pot image's Cowrie as shipped: nothing of
QPot's is mounted over its source and no bait is planted. It is the control
arm of the experiment in [effectiveness.md](effectiveness.md#the-controlled-experiment)
and has no other use. The default is `deception=qpot`.

Unknown keys and values outside their allowed range are refused with a plain
explanation. A running honeypot is then recreated in a new container, so the
change takes effect at once. The dashboard's settings dialog offers the same
settings, with the allowed values listed.

Conpot also keeps its resolved automatic choice in
`honeypots.conpot.device_profile` (`id` and `version`). QPot preserves the old
selection while loading and records it on the next save, after the runtime
identity has been loaded. The explicit
`custom_config.template` setting takes precedence; clearing it restores the
saved automatic choice. Unsupported saved IDs, versions and template pins
are rejected with an explanation rather than silently changing devices.

Configuration saves stage and validate a private snapshot, replace the YAML
atomically, then adopt the saved automatic profile. A failed write does not
change the in-memory profile or partially overwrite the earlier settings.

## Other sections

| Section | What it controls | More |
|---|---|---|
| `alerts`, `response` | Webhook alerts and response hooks | [alerts.md](alerts.md) |
| `canary` | Canaries, including the address their beacon links use | [canary.md](canary.md) |
| `cleanup` | How long captured files, logs and backups are kept, their size limits, and the disk guard that stops the honeypots before the disk is full | [disk-cleanup.md](disk-cleanup.md) |
| `collector` | Extra sensor ingest and the GeoIP database | [intelligence.md](intelligence.md) |
| `web_ui` | Address, port and login | [web-ui.md](web-ui.md) |

Cluster settings live separately, in `~/.qpot/cluster/cluster.json`. See
[clustering.md](clustering.md).

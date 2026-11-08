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

security:
  network_isolation:
    block_outbound: false        # true: honeypots open no outbound connections at all
    allow_private_egress: false  # true: switch the egress guard off (not recommended)
```

## Honeypot settings

Each honeypot's own settings, such as the Cowrie persona or the Conpot
device, are changed with `qpot honeypot set`:

```bash
qpot honeypot set cowrie persona=rhel-9
qpot honeypot set cowrie persona_rotation=30
qpot honeypot set cowrie bait=off
qpot honeypot set cowrie persona=debian-bookworm bait_profile=industrial
qpot honeypot set cowrie bait_target=refrigeration
qpot honeypot set refrigeration site_profile=plasma
qpot honeypot profiles conpot
qpot honeypot set conpot template=plc_modbus
```

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
| `cleanup` | How long captured files, logs and backups are kept, and their size limits | [disk-cleanup.md](disk-cleanup.md) |
| `collector` | Extra sensor ingest and the GeoIP database | [intelligence.md](intelligence.md) |
| `web_ui` | Address, port and login | [web-ui.md](web-ui.md) |

Cluster settings live separately, in `~/.qpot/cluster/cluster.json`. See
[clustering.md](clustering.md).

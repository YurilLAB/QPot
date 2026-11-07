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
  worker_interval: 15m

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
qpot honeypot set conpot template=plc_modbus
```

Unknown keys and values outside their allowed range are refused with a plain
explanation. A running honeypot is then recreated in a new container, so the
change takes effect at once. The dashboard's settings dialog offers the same
settings, with the allowed values listed.

## Other sections

| Section | What it controls | More |
|---|---|---|
| `alerts`, `response` | Webhook alerts and response hooks | [alerts.md](alerts.md) |
| `canary` | Canaries, including the address their beacon links use | [canary.md](canary.md) |
| `collector` | Extra sensor ingest and the GeoIP database | [intelligence.md](intelligence.md) |
| `web_ui` | Address, port and login | [web-ui.md](web-ui.md) |

Cluster settings live separately, in `~/.qpot/cluster/cluster.json`. See
[clustering.md](clustering.md).

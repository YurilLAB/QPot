<p align="center">
  <img src="https://raw.githubusercontent.com/YurilLAB/QPot/main/doc/qpot_wallpaper.png" alt="QPot Wallpaper" width="800">
</p>

<h1 align="center">QPot</h1>
<p align="center">
  <strong>Honeypot platform built on T-Pot, made harder to recognise</strong><br>
  <em>Developed by Yuril Security</em>
</p>

<p align="center">
  <a href="https://github.com/YurilLAB/QPot/releases"><img src="https://img.shields.io/github/v/release/YurilLAB/QPot?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8.svg?style=flat-square" alt="Go Version"></a>
  <a href="https://docker.com"><img src="https://img.shields.io/badge/Docker-Required-2496ED.svg?style=flat-square" alt="Docker"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square" alt="License"></a>
</p>

QPot runs the same proven honeypot images as [T-Pot CE](https://github.com/telekom-security/tpotce),
driven by a single `qpot` binary. On top of T-Pot it adds:

- **Per-instance deception** – every deployment gets its own believable identity
  (SSH banner, kernel, hostname, users, filesystem) instead of T-Pot's
  globally identical defaults, plus an optional high-interaction mode backed by
  real OpenSSH.
- **Hardened containers** – per-honeypot networks, dropped capabilities,
  read-only filesystems, resource limits and gVisor/Kata when available.
- **Built-in analysis** – Vector → ClickHouse (or TimescaleDB), automatic
  MITRE ATT&CK tagging, IOC extraction, campaign (TTP) tracking and MISP export.
- **Canaries, alerts and response hooks**, multi-node **clusters**, and a
  built-in **web dashboard / API**.
- **One-command setup** that checks the host, starts everything and verifies it
  is actually healthy.

---

## Quick start

Install the `qpot` binary:

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex

# Or from source (Go 1.26+)
git clone https://github.com/YurilLAB/QPot.git && cd QPot && make build
```

Set up and start an instance:

```bash
qpot setup                          # minimal: cowrie + endlessh
qpot setup --profile standard       # + dionaea, heralding, conpot, adbhoney
qpot setup --profile hifi --service # real-OpenSSH HiFi mode, as a systemd service
qpot doctor                         # re-check health any time (non-zero on failure)
```

`qpot setup` checks Docker, Compose, permissions, memory and disk; creates the
instance with a fresh QPot ID and random database password; makes sure the host
ports are free (a new instance whose web UI port is taken gets the next free
one); starts the containers and the control plane; and waits until the
database, collector, honeypots and this instance's web UI are healthy. The web
UI and database listen on `127.0.0.1` only, and nothing needs sudo.

The manual equivalent:

```bash
qpot instance create production
qpot up -d -i production    # containers + background control plane (qpot serve)
qpot down -i production
```

The **control plane** (web UI/API, intelligence worker, alerts, cluster
membership, HiFi backend recycler) runs inside `qpot up`, or in the background
as `qpot serve` with `-d` (log: `<instance>/logs/qpot-serve.log`).

### Dashboard and API

Served by the `qpot` process on `http://127.0.0.1:8080` (or the port `setup`
chose), authenticated with the instance's **QPot ID** (`qpot id` shows it). From
another machine use an SSH tunnel: `ssh -L 8080:127.0.0.1:8080 <host>`.

The dashboard shows live stats, per-honeypot controls, the attacker activity
feed, ATT&CK techniques / IOCs / campaigns, cluster members and the security
posture.

---

## Honeypots

27 honeypots, using T-Pot's upstream images (`qpot honeypot list` shows ports
and risk levels):

`adbhoney`, `beelzebub`, `ciscoasa`, `citrixhoneypot`, `conpot`, `cowrie`,
`ddospot`, `dicompot`, `dionaea`, `elasticpot`, `endlessh`, `galah`, `go-pot`,
`h0neytr4p`, `hellpot`, `heralding`, `honeyaml`, `ipphoney`, `log4pot`,
`mailoney`, `medpot`, `miniprint`, `redishoneypot`, `sentrypeer`, `ssh-proxy`
(HiFi), `tanner`, `wordpot`.

`glutton` and `honeytrap` are left out on purpose: they need host networking and
`NET_ADMIN`, which would break QPot's per-honeypot isolation.

```bash
qpot honeypot enable dionaea   # starts it right away if the instance is running
```

---

## Deception

![QPot anti-fingerprint demo](doc/qpot-fingerprint-demo.gif)

A stock T-Pot install is recognisable because every install is identical. QPot
derives a distinct, self-consistent identity for each instance:

- **Identity** – a realistic distro profile (SSH banner, kernel, `uname`) and
  hostname per instance; the banner is the real protocol banner, not just
  `ssh -V`.
- **Credential personas** – 30 personas (corporate Ubuntu, IoT camera, DB
  server, Proxmox host, CCTV/NVR, …) with believable users and weak-but-real
  passwords. Only that persona's credentials work; cowrie's well-known
  `phil`/`richard` accounts are gone. Pin one with `credential_template`.
- **Matching filesystem** – `/etc/passwd`, `/etc/shadow`, `os-release`,
  `/proc/cpuinfo`, `/proc/version`, `motd`, shell history, SSH config and
  per-file timestamps all agree with the persona and banner.
- **Protocol** – cowrie's legacy ciphers and malformed MAC (the blocklisted
  "stock cowrie" HASSH) are replaced with an OpenSSH-like set; host keys are
  stable; the idle timeout matches a real `sshd`.
- **No giveaways** – generated configs and container environments contain no
  `qpot`/`tpot`/`honeypot` strings.

**Limitation:** cowrie's key-exchange behaviour is baked into its Python SSH
stack, so a determined packet-level fingerprinter can still tell it from real
OpenSSH. **HiFi mode** closes that gap: a transparent TCP broker (`ssh-proxy`)
passes the attacker straight to real OpenSSH backends on an egress-blocked
network, and each backend is recreated after every session. Enable it with
`qpot setup --profile hifi` or `qpot honeypot enable ssh-proxy`. Details:
[doc/ssh-hifi-proxy.md](doc/ssh-hifi-proxy.md) and
[doc/fingerprint-comparison.md](doc/fingerprint-comparison.md).

```yaml
honeypots:
  cowrie:
    stealth:
      enabled: true
      credential_template: "web-hosting"   # optional; derived per instance if unset
      add_artificial_delay: true
      delay_range_ms: 50
```

---

## Data and threat intelligence

Vector collects every honeypot's JSON log, normalises it (source IP/ports,
protocol, event type, credentials, commands, download URLs) and writes it to
the instance database. Non-JSON log noise is dropped. Data is kept for 90 days.

| Backend | Notes |
|---------|-------|
| `clickhouse` | Default. Runs as the instance's `database` container. |
| `timescaledb` | Supported alternative (`database.type: timescaledb`). |

The intelligence worker (every 15 minutes by default,
`intelligence.worker_interval`) then:

- **Classifies** each event with MITRE ATT&CK – 16 curated rules plus rules
  generated from the ATT&CK dataset (fetched from MITRE, embedded fallback when
  offline), each with a confidence score. Example: `uname -a` → T1082,
  `wget …` → T1105, failed logins → T1110, Modbus probes → T0840.
- **Extracts IOCs** – public attacker IPs, credential pairs, URLs and domains,
  file hashes (including downloaded payloads), crypto wallets, commands and user
  agents. Defanged indicators (`hxxp://`, `1.2.3[.]4`) are refanged first.
- **Groups campaigns (TTP sessions)** by shared credentials, tooling, commands
  and targeted services rather than IP alone.

| Endpoint | Description |
|----------|-------------|
| `GET /api/techniques` | Observed ATT&CK techniques with counts |
| `GET /api/iocs` | IOCs, filterable by type and honeypot |
| `GET /api/iocs/export?format=misp` | IOCs as a MISP event |
| `GET /api/ioc` | Attacker IP blocklist |
| `GET /api/ttps` | Campaign sessions |
| `GET /api/intelligence` | Summary |

Optional extras: Suricata/p0f/fatt sensor ingest (`collector.ingest_*`), MaxMind
GeoIP (`collector.geoip_db_path`), and Kibana / the attack map on top of
ClickHouse via the bundled connector in
[docker/clickhouse-kibana](docker/clickhouse-kibana/README.md).

---

## Canaries

Canaries are decoy artifacts you plant inside your real environment – a fake AWS
key in a CI runner, a document on a file share, a beacon URL in a config file.
Nobody should ever touch them, so a trip is a critical, near-zero-false-positive
alert.

```bash
qpot canary create --kind aws  --name ci-runner --memo "planted in Jenkins"
qpot canary create --kind file --name q4-salaries
qpot canary trips
```

`web`/`file` canaries trip when their beacon URL (`/c/<token>`, set
`canary.base_url` to where this QPot is reachable) is fetched; `aws` canaries
trip when the key shows up in a captured honeypot session. See
[docs/canary.md](docs/canary.md).

---

## Alerts and response hooks

```yaml
alerts:
  enabled: true
  webhook_url: https://hooks.slack.com/services/...   # Slack, Discord or any URL
  threshold: 100      # events per minute
  cooldown: 5m

response:
  enabled: true
  on_attack_detected:
    - name: block-top-attacker
      command: 'iptables -I INPUT -s "$QPOT_TOP_SOURCE_IP" -j DROP'
      timeout: 10s
```

Hooks get `QPOT_ID`, `QPOT_INSTANCE`, `QPOT_TOTAL_EVENTS`, `QPOT_UNIQUE_IPS`,
`QPOT_THRESHOLD`, `QPOT_TIMESTAMP`, `QPOT_TOP_SOURCE_IP` and
`QPOT_TOP_HONEYPOT` as environment variables (never interpolated into the
command) and run with a timeout in their own process group.

---

## Clusters

Pair several QPot nodes into a group that shares health and attacker data:

```bash
qpot cluster init --name production                      # prompts for a password, prints the cluster ID
qpot cluster join --id qc_... --password '...' --seed 10.0.0.10:7946   # on each sensor
qpot cluster requests --password '...'                   # on the host: pending joiners
qpot cluster approve <request-id> --password '...'       # (or deny)
qpot cluster status
```

Joining needs the password **and** the host's approval (`require_approval`,
on by default). Traffic between nodes is TLS-encrypted automatically – the
cluster CA is derived from the cluster ID and password, so there are no
certificates to manage. Membership runs in the control plane, so restart
`qpot up -d` after `init`/`join`. The password is stored in
`~/.qpot/cluster/cluster.secret` (0600) or read from `QPOT_CLUSTER_PASSWORD`.

---

## Security model

| Area | What QPot does |
|------|----------------|
| Isolation | Each honeypot on its own bridge network with a non-overlapping subnet |
| Runtime | gVisor or Kata used for honeypots when installed |
| Containers | `cap_drop: ALL` (minimal add-backs), read-only root with tmpfs, no privileged containers |
| Limits | CPU, memory, PID and file-descriptor limits per honeypot |
| Secrets | QPot ID never given to honeypot containers or written to logs; DB password random per instance |
| Exposure | Web UI, API and database bound to `127.0.0.1` by default |
| Web | CSP, `X-Frame-Options: DENY`, `nosniff`, constant-time auth checks |
| HiFi backends | No outbound network, recreated after every session, read-only host keys |

---

## Configuration

Each instance has a `config.yaml` (`qpot config -i <name> --print` shows the
path). Commonly changed settings:

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
```

---

## CLI

```bash
qpot setup | doctor | up [-d] | serve | down | status   [-i <instance>]
qpot instance create|list|remove <name>
qpot honeypot list|enable|disable <name>
qpot logs [honeypot] [-f]          qpot id          qpot config [--print]
qpot docker ps|logs|restart        qpot db migrate status|up|down
qpot cluster ...                   qpot canary ...  qpot ypanel ...
```

Every command has `--help`; the full reference is
[doc/cli-reference.md](doc/cli-reference.md). Most commands take
`-i/--instance` (default `default`).

**Dedicated sensor hosts:** `sudo ./install.sh` runs the T-Pot-style Ansible
installer (AlmaLinux, Arch, Debian, Fedora, openSUSE, RHEL, Rocky, Ubuntu, …).

**ypanel:** QPot can optionally report to the ypanel operator console; see
[docs/ypanel.md](docs/ypanel.md).

---

## Development

```bash
make build      # build ./qpot
make test       # unit tests
make ci         # fmt, vet, lint, test, security checks
make build-all  # cross-compile
```

```
cmd/qpot/            CLI and control plane
cmd/qpot-sshproxy/   HiFi SSH broker
internal/
  instance/          compose + collector generation, deception, lifecycle
  intelligence/      ATT&CK classifier, IOC extractor, TTP sessions, worker
  database/          ClickHouse, TimescaleDB (and Elasticsearch client)
  server/            web UI and API
  cluster/ canary/ proxy/ security/ config/ ypanel/
docker/              honeypot images, ssh-proxy/ssh-backend, Kibana connector
```

CI runs build, gofmt, vet, staticcheck, race tests, fuzzing, govulncheck,
gosec, gitleaks and a multi-distro smoke test on every push.

---

## License

GPL-3.0 – see [LICENSE](LICENSE). QPot builds on
[T-Pot CE](https://github.com/telekom-security/tpotce) by Deutsche Telekom
Security (GPL-3.0). Issues: [GitHub Issues](https://github.com/YurilLAB/QPot/issues).

<p align="center"><strong>Built by Yuril Security</strong><br><em>Australian-made cybersecurity</em></p>

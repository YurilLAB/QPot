# QPot CLI Reference

Complete reference for the `qpot` command-line interface. Every command,
subcommand, and flag below is generated from the binary's own help output, so
this document stays in lock-step with the code.

- **Binary:** `qpot`
- **Config file:** `~/.qpot/config.yaml` (global) and one `config.yaml` per
  instance under `~/.qpot/instances/<name>/`
- **Built with:** [spf13/cobra](https://github.com/spf13/cobra), so every
  command supports `--help` and shell completion

> **Tip:** Run `qpot <command> --help` (or `qpot <command> <subcommand> --help`)
> at any time. The CLI is self-documenting; this page is the same information,
> organized for reading.

---

## Table of contents

- [Synopsis](#synopsis)
- [Global flags](#global-flags)
- [Command overview](#command-overview)
- [Instance lifecycle](#instance-lifecycle)
  - [`qpot setup`](#qpot-setup)
  - [`qpot doctor`](#qpot-doctor)
  - [`qpot up`](#qpot-up)
  - [`qpot down`](#qpot-down)
  - [`qpot status`](#qpot-status)
- [Instance management — `qpot instance`](#instance-management--qpot-instance)
- [Honeypot management — `qpot honeypot`](#honeypot-management--qpot-honeypot)
- [Logs — `qpot logs`](#logs--qpot-logs)
- [Docker management — `qpot docker`](#docker-management--qpot-docker)
- [Database migrations — `qpot db`](#database-migrations--qpot-db)
- [Cluster / pairing — `qpot cluster`](#cluster--pairing--qpot-cluster)
- [Canaries — `qpot canary`](#canaries--qpot-canary)
- [Overview — `qpot overview`](#overview--qpot-overview)
- [GeoIP — `qpot geoip`](#geoip--qpot-geoip)
- [Configuration — `qpot config`](#configuration--qpot-config)
- [Utilities](#utilities)
  - [`qpot id`](#qpot-id)
  - [`qpot completion`](#qpot-completion)
- [How instances are resolved](#how-instances-are-resolved)
- [Exit codes](#exit-codes)

---

## Synopsis

```text
qpot [command] [subcommand] [flags]
```

Most commands operate on a single **instance** (a self-contained honeypot
deployment with its own config, QPot ID, Docker project, and data directory).
When you omit `--instance`, QPot uses the instance named `default`.

---

## Global flags

These flags are accepted by **every** command:

| Flag | Description |
|------|-------------|
| `--config string` | Path to the global config file (default `$HOME/.qpot/config.yaml`). |
| `-h, --help` | Show help for the command and exit. |
| `-v, --version` | Print the `qpot` version, commit, and build date, then exit. |

```bash
qpot --version
# qpot version 24.04.1 (commit: a1b2c3d, built: 2026-06-03)
```

---

## Command overview

| Command | What it does |
|---------|--------------|
| `qpot setup` | Check the host, create and start an instance, and verify it is healthy. |
| `qpot doctor` | Re-run the health checks for an instance (non-zero exit on failure); `--explain <code>` explains an error code. |
| `qpot up` | Start an instance and all of its enabled honeypots. |
| `qpot serve` | Run only the control plane (what `qpot up -d` starts in the background). |
| `qpot down` | Stop a running instance and its honeypots. |
| `qpot status` | Show the live status of an instance's honeypots and services. |
| `qpot instance` | Create, list, and remove instances. |
| `qpot honeypot` | Enable, disable, list and configure honeypots within an instance. |
| `qpot logs` | View logs from one honeypot or all honeypots. |
| `qpot docker` | Inspect and manage the underlying Docker containers. |
| `qpot db` | Inspect schema versions and run/roll back migrations. |
| `qpot cluster` | Pair multiple nodes into a managed group (aliases: `group`, `pair`, `networking`). |
| `qpot canary` | Mint and manage canaries (honeytokens) — decoy artifacts that alert on monitored interactions. |
| `qpot overview` | Host resources, 24h honeypot activity and recent events, for one or all local instances. |
| `qpot geoip` | Install or refresh the GeoIP database used for countries and the attack map. |
| `qpot config` | Open or print the instance config file. |
| `qpot id` | Show the QPot ID for an instance. |
| `qpot completion` | Generate a shell autocompletion script. |

---

## Instance lifecycle

The commands you will use most. Each one targets a single instance via
`-i, --instance` (default `default`).

### `qpot setup`

Guided setup from a fresh host to a verified, running instance: host checks,
Docker install or start (with consent), settings, instance creation, port
checks, GeoIP download, start, a health wait and a summary of where the web UI
is and what to do next.

In a terminal it asks the questions below; Enter takes the recommended answer
and a wrong answer is asked again. Without a terminal, or with `--yes`, it asks
nothing and uses the flags and defaults. Every question has a flag. The
settings flags only apply when the instance is new; an existing instance keeps
its settings (change them with `qpot config`).

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --instance string` | `default` | Instance name. |
| `--profile string` | `minimal` | Honeypots for a new instance: `minimal`, `standard` or `hifi`. |
| `--honeypots string` | | Honeypots for a new instance by name, comma-separated (instead of `--profile`). |
| `--bind string` | `127.0.0.1` | Web UI address. Anything other than loopback prints an exposure warning. |
| `--port int` | `8080` | Web UI port (the next free one if the default is taken; a chosen port that is taken is an error). |
| `--database string` | `clickhouse` | Event database: `clickhouse` or `timescaledb`. |
| `--outbound string` | `allow` | Honeypot connections to the internet: `allow` or `block` (private networks are always blocked). |
| `--country string` | time zone | Two-letter country of this sensor, where the attack map draws it. |
| `--no-geoip` | `false` | Do not download the DB-IP Lite country database. |
| `--service` | `false` | Install and start a systemd service (Linux). |
| `-y, --yes` | `false` | Ask no questions: use flags and defaults. |
| `--install-docker` | `false` | Allow setup to install, update and start Docker and the Compose plugin (uses sudo). |
| `--docker-group` | `false` | Allow setup to add your user to the `docker` group (root-equivalent; uses sudo). |
| `--docker-source string` | `auto` | Linux only: `docker` (Docker's signed repository), `distro` (the distribution's packages) or `auto`. |
| `--dry-run` | `false` | Check the computer and print what setup would do, without changing anything. |
| `--no-start` | `false` | Set up and create the instance, but do not start it. |
| `--timeout duration` | `4m` | How long to wait for everything to become healthy. |
| `--verbose` | `false` | Show the full output of the commands setup runs. |

```bash
qpot setup                                      # guided
qpot setup --yes --install-docker --docker-group --profile standard --country NL
qpot setup --dry-run
```

**Installing Docker.** When Docker Engine or the Compose plugin is missing,
too old (Engine 20.10+ and Compose 2 are needed) or stopped, setup prints every
command it would run and asks before running them (`--install-docker` answers
yes without a terminal). On Linux:

| Distribution | Method |
|--------------|--------|
| Debian, Ubuntu, Raspberry Pi OS, Linux Mint and other relatives with an Ubuntu/Debian codename | Docker's apt repository (`/etc/apt/sources.list.d/docker.sources`), key `/etc/apt/keyrings/docker.asc` with fingerprint `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88` checked |
| Fedora, CentOS Stream, Rocky Linux, AlmaLinux, RHEL | Docker's dnf repository (`/etc/yum.repos.d/docker-ce.repo`), key `/etc/pki/rpm-gpg/docker-ce.gpg` with fingerprint `060A 61C5 1B55 8A7F 742B 77AA C52F EB6B 621E 9F35` checked |
| Debian/Ubuntu/Fedora releases Docker does not publish (Kali, Parrot, Debian testing, a new Fedora) | The distribution's own packages (`docker.io` + `docker-compose-v2`, `moby-engine` + `docker-compose`) |
| openSUSE, SLES | `zypper install docker docker-compose` |
| Arch, Manjaro | `pacman -Syu docker docker-compose` (Arch only supports full upgrades) |

Nothing is piped from the network into a shell: setup downloads the signing
key itself, refuses it unless its fingerprint matches, installs only the key it
checked (re-armored, never the downloaded bytes), and lets apt or dnf check
every package against it. The key and package source files are prepared in a
private temporary folder before `sudo install` copies them into place. It waits up to two minutes for another program
that is installing software, removes packages that conflict with Docker's own
only as a shown step, and starts Docker with `systemctl enable --now docker`
(or Docker's start script where systemd is not running, such as WSL without
systemd). On macOS it uses `brew install --cask docker-desktop` and on Windows
`winget install -e --id Docker.DockerDesktop`; Docker Desktop's licence is yours
to accept when it first opens, and setup never accepts it for you.

**Re-running.** Setup can be run again after any failure: steps already done
(the key, the package source, an installed Docker, an existing instance) are
skipped, and the answers you gave are offered again.

**Errors.** Every problem has a code such as `QP-PKG-001` with what went wrong,
why and what to do, and the process exits with the code's category status
(10 settings, 11 host, 12 permissions, 13 network, 14 package manager, 15
Docker, 16 Compose, 17 ports, 18 memory/disk, 19 services, 20 web UI, 21
instance, 130 interrupted, 70 unexpected). See
[setup-errors.md](setup-errors.md), or `qpot doctor --explain <code>`. A log of
the commands setup ran is kept in `~/.qpot/logs/setup.log` (it never contains
the QPot ID).

A failed GeoIP download is only a warning; `qpot geoip update` retries it.

### `qpot doctor`

Re-runs the host checks (Docker, Compose, memory, disk) and inspects a running
instance: containers, database schema, control plane and web UI. Every failed
or warning check names its error code, and the command exits with the first
failure's category status (0 when everything passes).

| Flag | Description |
|------|-------------|
| `-i, --instance string` | Instance name (default `default`). |
| `--explain string` | Explain an error code (any case; `pkg-1` works too) and exit. Needs no instance. |

```bash
qpot doctor
qpot doctor --explain QP-PORT-001
```

### `qpot up`

Start an instance with all configured honeypots.

```text
qpot up [flags]
```

| Flag | Description |
|------|-------------|
| `-d, --detach` | Run in the background and return immediately. |
| `-i, --instance string` | Instance name (default `default`). |

**How it works.** `up` loads the instance config, renders a per-instance
`docker-compose.yml` (network names, hostnames, resource limits, and the active
sandbox runtime are all baked in at this point), and then brings the project up.
Each honeypot's start/fail status is reported individually — a single honeypot
that fails to start does not abort the others, and the failure reason is logged.

```bash
# Start the default instance in the foreground
qpot up

# Start a named instance in the background
qpot up --instance production --detach
```

### `qpot down`

Stop a running instance and all of its honeypots.

```text
qpot down [flags]
```

| Flag | Description |
|------|-------------|
| `-i, --instance string` | Instance name (default `default`). |

```bash
qpot down                       # stop the default instance
qpot down --instance production # stop a named instance
```

### `qpot status`

Show the status of all running honeypots and services for an instance.

```text
qpot status [flags]
```

| Flag | Description |
|------|-------------|
| `-i, --instance string` | Instance name (default `default`). |

```bash
qpot status
qpot status -i production
```

---

## Instance management — `qpot instance`

Create, list, and manage multiple QPot instances. Each instance is fully
isolated: its own QPot ID, config, Docker project, networks, and data.

```text
qpot instance [command]
```

| Subcommand | Description |
|------------|-------------|
| `create [name]` | Create a new instance (generates a unique QPot ID). |
| `list` | List all instances. |
| `remove [name]` | Remove an instance. |

```bash
# Create a new instance — prints the generated QPot ID
qpot instance create production
# [OK] Created QPot instance 'production'
#      QPot ID: qp_e2imzc43lisklwokb7vlspi7

qpot instance list
qpot instance remove production
```

> Instance names are validated: they must be filesystem- and Docker-safe
> (no path separators or characters that could escape the instance directory).

---

## Honeypot management — `qpot honeypot`

Enable, disable, and list the individual honeypots inside an instance.

```text
qpot honeypot [command]
```

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `list` | `-i, --instance` | List available honeypots with port, risk, and on/off state. |
| `enable [honeypot]` | `-i, --instance` | Enable a honeypot; starts it (and its companions) if the instance is running. |
| `disable [honeypot]` | `-i, --instance` | Disable a honeypot; stops it if the instance is running. |
| `set [honeypot] key=value...` | `-i, --instance` | Set a honeypot's settings (`key=` removes one); an enabled honeypot on a running instance is recreated with them. |

`-i, --instance string` selects the instance (default `default`).

```bash
qpot honeypot list
# Name             Port  Risk     On  Description
# cowrie            2222 low      [x] SSH/Telnet medium-interaction shell
# dionaea             21 medium   [ ] Malware capture (SMB/FTP/MSSQL/SIP)
# ...

qpot honeypot enable dionaea
qpot honeypot disable endlessh -i production
```

`qpot honeypot list` shows every selectable service — **26 classic honeypots**
(low-interaction tarpits through high-interaction and LLM-backed services) plus
the **HiFi `ssh-proxy`**, for 27 entries in total.

`set` accepts only the keys a honeypot uses. The LLM-backed honeypots refuse to
start without a provider, so `enable` asks for these first:

| Honeypot | Keys | Required |
|----------|------|----------|
| `beelzebub` | `llm_provider` (`ollama` or `openai`), `llm_model`, `llm_host` | `llm_provider`, `llm_model` |
| `galah` | `llm_provider`, `llm_server_url`, `llm_model`, `llm_temperature`, `llm_api_key`, `llm_cloud_location`, `llm_cloud_project` | `llm_provider`, `llm_model` |
| `cowrie` | `persona` (one of the image's persona IDs), `persona_rotation` (days, 0-365) | – |
| `conpot` | `template` (one of the image's deployed device templates) | – |
| `ssh-proxy` | `backends` | – |

```bash
qpot honeypot set beelzebub llm_provider=ollama llm_model=llama3.1 llm_host=http://10.0.0.5:11434/api/chat
qpot honeypot enable beelzebub
```

Cowrie presents one persona of its image: `ubuntu-noble`, `ubuntu-jammy`,
`debian-trixie`, `debian-bookworm`, `rhel-9`, `centos-7`, `raspios`,
`gpu-ubuntu` (servers, one of which is picked per instance when `persona` is
unset), or `dlink-dir859`, `tplink-archer-c7`, `zyxel-nas326`, `openwrt`,
`qnap-qts`, `synology-dsm`, `ubiquiti-edgerouter-x`, `ipcam` (devices;
`dlink-dir859` runs no SSH server, so it closes every SSH connection). The
identity drawn for the persona is kept for `persona_rotation` days across
restarts:

```bash
qpot honeypot set cowrie persona=centos-7 persona_rotation=365
```

Conpot emulates one device template of its image, picked per instance when
`template` is unset, and publishes only that template's ports:

| Template | Device | TCP | UDP |
|----------|--------|-----|-----|
| `IEC104` | Siemens S7-300 substation RTU (IEC 60870-5-104, DNP3, SNMP) | 2404, 20000 | 161 |
| `guardian_ast` | Veeder-Root TLS-350 tank gauge | 10001 | – |
| `ipmi` | Supermicro BMC (IPMI 2.0) | – | 623 |
| `kamstrup_382` | Kamstrup 382 electricity meter | 1025, 50100 | – |
| `beckhoff_cx` | Beckhoff CX5140 with TwinCAT 3 (ADS, OPC UA) | 4840, 48898 | 48899 |
| `building_automation` | LOYTEC LINX-153 (BACnet/IP, KNXnet/IP) | – | 3671, 47808 |
| `hart_gateway` | Emerson 1420 WirelessHART gateway (HART-IP) | 5094 | – |
| `iccp` | SISCO ICCP / TASE.2 server | 102 | – |
| `plc_modbus` | Schneider Modicon M340 (Modbus/TCP) | 502 | – |

The image draws the device's address, MAC, serial numbers and PINs on first
start and keeps them in the honeypot's `state` directory, so a restart does not
turn it into a different unit:

```bash
qpot honeypot set conpot template=building_automation
```

---

## Logs — `qpot logs`

View logs from a specific honeypot, or from all honeypots at once.

```text
qpot logs [honeypot] [flags]
```

| Flag | Description |
|------|-------------|
| `-f, --follow` | Stream new log output as it arrives. |
| `-n, --tail int` | Number of lines to show from the end (default `100`). |
| `-i, --instance string` | Instance name (default `default`). |

```bash
qpot logs                 # all honeypots, last 100 lines
qpot logs cowrie -f       # follow cowrie's logs
qpot logs dionaea -n 500  # last 500 lines from dionaea
```

---

## Docker management — `qpot docker`

Inspect and manage the Docker containers behind a QPot instance. Useful when
you want to drop below the QPot abstraction and look at raw container state.

```text
qpot docker [command]
```

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `ps` | — | List QPot containers with status and honeypot type. |
| `logs [container]` | `-n, --tail int` (default `50`) | Tail a single container's logs. |
| `restart [container]` | — | Restart a single QPot container. |

```bash
qpot docker ps
qpot docker logs qpot-cowrie -n 200
qpot docker restart qpot-cowrie
```

> `qpot logs` reads honeypot application logs; `qpot docker logs` reads raw
> container stdout/stderr. Use the former for attacker activity, the latter for
> debugging container startup.

---

## Database migrations — `qpot db`

Inspect schema versions and run or roll back migrations against the configured
database backend (ClickHouse, TimescaleDB, or Elasticsearch).

```text
qpot db migrate [command]
```

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `status` | `-i, --instance` | Show the current schema version and any pending migrations. |
| `up` | `-i, --instance`, `--to int` | Apply pending migrations (all, or up to a specific version with `--to`). |
| `down` | `-i, --instance`, `--yes` | Roll back the most recent migration. `--yes` skips the confirmation prompt. |

```bash
qpot db migrate status
qpot db migrate up            # apply everything pending
qpot db migrate up --to 5     # migrate forward to version 5
qpot db migrate down --yes    # roll back one migration, no prompt
```

**How it works.** The migration manager reads the backend from the instance
config, opens a connection, and compares the recorded schema version against the
embedded migration set. `up` applies migrations in order inside the backend's
transactional semantics; `down` reverses exactly one. The connection is always
closed cleanly, even on error.

---

## Cluster / pairing — `qpot cluster`

Pair multiple QPot nodes into a managed **group** (cluster). Members gossip
their health and attack statistics, and the **Pairing / Networking** tab in the
web UI shows every node's online status, uptime, and total requests.

> **Aliases:** `qpot group ...`, `qpot pair ...`, and `qpot networking ...` are
> all equivalent to `qpot cluster ...`.

```text
qpot cluster [command]
```

| Subcommand | Description |
|------------|-------------|
| `init` | Initialize a new cluster (prints the cluster ID and password). |
| `join` | Join an existing cluster. |
| `upgrade` | Safely upgrade a stopped legacy cluster, preserving settings and requiring members to rejoin. |
| `requests` | List pending join requests awaiting approval. |
| `approve <request-id>` | Approve a pending join request. |
| `deny <request-id>` | Deny a pending join request. |
| `nodes` | List paired nodes. |
| `status` | Show the cluster summary. |
| `leave` | Unpair this node from the cluster. |

### `qpot cluster init`

```text
qpot cluster init --name <name> [flags]
```

| Flag | Description |
|------|-------------|
| `-n, --name string` | Cluster name (**required**). |
| `-p, --password string` | Cluster password (minimum 8 characters). |
| `--bind-addr string` | Bind address for cluster communication (default `0.0.0.0`). |
| `--bind-port int` | Bind port for cluster communication (default `7946`). |

```bash
qpot cluster init --name production --password "SecurePass123!"
qpot cluster init --name east-coast -p "MyP@ssw0rd" --bind-addr 192.168.1.10 --bind-port 7946
```

### `qpot cluster join`

```text
qpot cluster join --id <cluster-id> [flags]
```

| Flag | Description |
|------|-------------|
| `-i, --id string` | Cluster ID (**required**). |
| `-p, --password string` | Cluster password. |
| `-s, --seed stringArray` | Seed node address(es), `host:port`. Repeat for redundancy. |
| `--instance string` | QPot instance name (default `default`). |
| `--node-name string` | Name for this node (default: hostname). |
| `--node-addr string` | Address for this node (auto-detected if unset). |
| `--node-port int` | Port for cluster communication (default `7946`). |
| `--operator-cert` | Also accept a seed serving a certificate from your own or a public CA, checked against the system roots. |
| `--ca-file string` | PEM bundle the seed's certificate is checked against instead of the system roots (implies `--operator-cert`). |
| `--qpot-id string` | Deprecated and ignored: the QPot ID is the web UI's credential and is not sent to the cluster. |

```bash
qpot cluster join --id qc_abc123 --password "SecurePass123!" --seed 192.168.1.10:7946
qpot cluster join --id qc_abc123 -p "MyP@ssw0rd" -s 10.0.0.5:7946 -s 10.0.0.6:7946 --node-name sensor-01
qpot cluster join --id qc_abc123 -s seed.example.net:7946 --ca-file /etc/qpot/cluster-ca.pem
```

#### Which seeds a joining node trusts

By default a joining node trusts only the cluster's own certificate
authority, which the cluster ID pins: the seed must present a certificate
from that CA before the password is sent. If the seed serves a certificate
from your own or a public CA instead (`tls_cert_path` in its `cluster.json`),
add `--operator-cert` to accept one the system roots trust, or
`--ca-file <bundle.pem>` to check it against a specific CA bundle. The node
keeps that choice for its later connections to the other members. Either way,
the node certificate the seed hands back must come from the CA the cluster ID
names and match the key the joining node made.

### Join approval

New clusters require **host approval** in addition to the password
(`require_approval` is on by default). A node that supplies the correct password
is queued rather than admitted automatically; `cluster join` blocks while it
polls for the decision. On the host:

```text
qpot cluster requests [-p <password>]   # list requests awaiting approval
qpot cluster approve <request-id> [-p <password>]
qpot cluster deny    <request-id> [-p <password>]
```

| Flag (all three) | Description |
|------------------|-------------|
| `-p, --password string` | Cluster password. |

The request list shows the requester's **real source IP** (taken from the
connection, not the request body) alongside its claimed hostname and instance.

On approval the joiner receives the cluster's **member key**, which the peer
endpoints (gossip, intel, nodes, status, leave) require besides the password,
and a signed **node certificate** for a private key generated on the joiner.
The private node key never leaves the node; the CA key stays only on the host
that ran `cluster init`. Use that enrollment host as `--seed`; ordinary members
cannot enroll others. The cluster ID is the authority's fingerprint, so the
joiner verifies the seed before sending the password and checks the returned
certificate against its own key and assigned node ID. Only the joiner collects
the result: its join carries a random poll secret, and the host answers a poll for
the decision only when it carries that secret, so knowing the password and a
request ID is not enough. Certificates expire after one year; re-enroll members
before expiry. The enrollment host renews its own certificate on startup when
it has under 30 days left, including after expiry. Keep that host available for
joins and protect/back up its private cluster state.

Clusters created by earlier QPot versions (password-derived TLS or a CA key
shared with members) do not start until explicitly upgraded. Old clients without
the current protocol version and a valid certificate request are rejected.

### `qpot cluster upgrade`

Stop the old control planes and install the updated QPot on every node first.
Run this **once**, on the chosen enrollment host:

```text
qpot cluster upgrade [-p <password>] [--yes]
```

The password defaults to the stored secret or `QPOT_CLUSTER_PASSWORD`. Without
`--yes`, the command asks before rotating trust. It refuses a running cluster,
an occupied cluster port, an outstanding upgrade lock, changed saved settings,
or invalid configured TLS files. It preserves the cluster name, settings,
metadata and local instance identity, validates the replacement certificate,
writes a private byte-for-byte `cluster.legacy-*.json` configuration/membership
backup, then atomically replaces `cluster.json`. Preparation/write failures
leave the old active file and instance unchanged. Other instance files and event
databases are never modified or backed up by this operation.

The new cluster has a new ID, CA and member key, and initially only the local
node. Start that host's control plane. Every other updated node must leave its
old cluster and rejoin using the printed new ID and the enrollment host as the
seed. The saved approval setting still applies. Missing or incompatible protocol
versions cannot join. Previously shared signing keys cannot be safely retained
as trusted roots, and backups are never automatically activated as fallback.

If preparation was interrupted, keep the old state and any completed backup;
inspect `cluster.upgrade.lock` and confirm no upgrade/control plane is running
before removing a stale lock and retrying. A completed atomic replacement loads
the new version on restart. Keep independent storage backups for power-loss or
filesystem recovery. Configuration backups contain old secrets and must remain
private; do not restore their old CA into the upgraded cluster's trust.

Upgrade/enrollment failures use `QP-CLUSTER-001` through `QP-CLUSTER-009` with
actionable guidance; join API failures also expose `error_code`. Code `009`
means activation completed but filesystem durability is uncertain: inspect
the active new state and backup, and never automatically restore the old CA.

### `qpot cluster leave`

```text
qpot cluster leave [flags]
```

| Flag | Description |
|------|-------------|
| `-f, --force` | Skip the confirmation prompt. |

The node tells every member it can reach that it left, then removes its
`cluster.json`; a `qpot serve` still running for it stops its cluster
membership at its next gossip round instead of carrying on. Members that got
the leave keep the node as *left* for 30 days, so no other member's gossip can
bring it back. A member that was offline still lists it, as failed once it
cannot reach it.
To come back, the node joins again and is approved like a new one; it gets a
new node ID.

### Who is trusted with membership

Every admitted member holds the cluster password, the member key and a node
certificate of its own (never the CA key), so the cluster trusts every member
with its membership: any member can add nodes through gossip, and nothing in a
request proves which member sent it, as members present no client certificate
to each other. Approve only nodes you control. A node's departure is the
exception, taken only from the node itself as far as its address shows: a
leave request counts only when it comes from the address the node is
registered with, gossip pushed to a member never marks a node as left, and the
only gossip that does is a node's own answer when a member contacts it. A node
that leaves from behind NAT is refused; it has stopped, so the members mark it
failed when they cannot reach it. Clusters created before the member key
existed do not start until upgraded (`qpot cluster upgrade`).

### `qpot cluster nodes` / `qpot cluster status`

Both take no flags beyond the global ones.

```bash
qpot cluster status   # cluster summary: ID, name, node counts, total events
qpot cluster nodes    # per-node table: ID, name, address, status, events
```

---

## Canaries — `qpot canary`

Mint and manage **canaries** (honeytokens): decoy artifacts planted inside your
environment that alert on monitored interactions. A trip records a beacon
request or a watched value in captured honeypot event fields; it does not by
itself prove theft or compromise. QPot marks trips as critical for investigation.
The false-positive rate has not been measured: previews, link scanners and
authorized tests can also trip a canary.

Canaries are runtime objects owned by a **running** instance, so `qpot up` must
be active; the CLI talks to the instance's local API (QPot-ID auth). Set
`canary.base_url` in the instance config so minted URLs point at wherever this
QPot is reachable. See [docs/canary.md](../docs/canary.md) for the full design.

Kinds: `web` (a beacon URL), `file` (an HTML document that attempts to fetch its
beacon), `aws` (a fake AWS key pair watched in captured honeypot event fields).
GET or HEAD requests to a reachable beacon can trip web/file canaries. All
kinds can also trip on a watched value in captured events, with intelligence
enabled. Reading a credential or file alone need not alert; direct use against
real AWS is not monitored. No recorded trips does not prove no access occurred.

### `qpot canary create`

```bash
qpot canary create --kind aws  --name ci-runner   --memo "planted in Jenkins"
qpot canary create --kind web  --name wiki-link   --memo "fake intranet bookmark"
qpot canary create --kind file --name q4-salaries --memo "HR share"
```

| Flag | Description |
|------|-------------|
| `-k, --kind` | `web`, `file`, or `aws` (required) |
| `-n, --name` | Human label |
| `-m, --memo` | Where it is planted — echoed on every trip, so the alert is actionable |
| `-i, --instance` | Instance name (default `default`) |

For `aws` the command prints the access key id and secret to plant; for
`web`/`file` it prints the beacon URL.

### `qpot canary list` / `qpot canary trips`

```bash
qpot canary list            # ID, kind, name, lifetime trip count, memo
qpot canary trips --limit 50  # recent trips (the alerts), newest first
```

### `qpot canary artifact`

Download a file canary's document so you can plant it.

```bash
qpot canary artifact cnry_abc123 --out Q4-Salaries.html
```

`--out` defaults to the canary's suggested filename.

### `qpot canary rm`

```bash
qpot canary rm cnry_abc123   # aliases: remove, delete
```

---

## Overview — `qpot overview`

An at-a-glance, entirely local view of an instance: host CPU / memory / disk /
process load, events and unique attackers over the last 24 hours, per-honeypot
activity, cluster membership and the latest events with a severity
(`info` / `warn` / `critical`). The same data is on the dashboard's **Overview**
tab and at `GET /api/overview` (QPot-ID authenticated). Nothing is sent off the
host.

| Flag | Description |
|------|-------------|
| `-i, --instance` | Instance to show (default `default`). |
| `--all` | One summary line per instance on this host: containers, control plane, honeypots enabled, 24h events and attackers, last event, web UI address. |
| `--json` | Print JSON instead of text. |

```bash
qpot overview
qpot overview --all
qpot overview -i sensor1 --json
```

When the instance's control plane is running the data comes from its API;
otherwise `qpot overview` reads the instance database directly.

---

## GeoIP — `qpot geoip`

```text
qpot geoip update [-i instance] [--country CC]
```

Downloads the current [DB-IP](https://db-ip.com) Lite country database
(monthly, about 4 MB compressed, CC BY 4.0) into `<instance>/geoip/`, checks it
is a MaxMind-format file, points the collector at it and restarts the collector
if the instance is running. New events then carry the attacker's country, which
the attack map and dashboards use. Run it monthly for fresh data.
`--country` also sets where the map draws this sensor (`attack_map.country`).

`qpot doctor` reports a configured database file that has gone missing, since
the collector cannot start without it.

---

## Configuration — `qpot config`

Open the instance config file (`config.yaml`) in your editor, or print its path.

```text
qpot config [flags]
```

| Flag | Description |
|------|-------------|
| `-i, --instance string` | Instance name (default `default`). |
| `--print` | Print the config path and exit; do not open an editor. |

**Editor resolution.** `config` opens `$VISUAL`, then `$EDITOR`. On Windows it
falls back to `notepad.exe`; on Linux/macOS it falls back to `nano`, then `vim`,
then `vi`.

```bash
qpot config                 # edit the default instance config
qpot config -i production   # edit a named instance config
qpot config --print         # just print the path
```

---

## Utilities

### `qpot id`

Display the QPot ID for an instance.

```text
qpot id [flags]
```

| Flag | Description |
|------|-------------|
| `-i, --instance string` | Instance name (default `default`). |

```bash
qpot id
# QPot ID: qp_e2imzc43lisklwokb7vlspi7
```

The QPot ID uniquely identifies a deployment. It appears in the GUI popup on
startup, the web UI header (click to copy), the attack map, and API responses,
and is used to tag forwarded events.

### `qpot completion`

Generate a shell autocompletion script (provided by cobra).

```text
qpot completion [bash|zsh|fish|powershell]
```

```bash
# Bash — load for the current shell
source <(qpot completion bash)

# Bash — install permanently
qpot completion bash > /etc/bash_completion.d/qpot

# Zsh
qpot completion zsh > "${fpath[1]}/_qpot"

# Fish
qpot completion fish > ~/.config/fish/completions/qpot.fish
```

Run `qpot completion <shell> --help` for shell-specific install instructions.

---

## How instances are resolved

Almost every command accepts `-i, --instance` (a few, like `cluster join`, spell
it `--instance`). The resolution rule is uniform:

1. If `-i/--instance` is given, that instance is used.
2. Otherwise the instance named `default` is used.

An instance lives at `~/.qpot/instances/<name>/` and owns its `config.yaml`,
QPot ID, Docker Compose project, per-instance networks/hostnames, and data
directory. Because everything is namespaced by instance, you can run several
fully independent honeypot deployments side by side on one host.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | The command failed (the error is printed to stderr). |

Commands print a clear, human-readable error on failure. Where an action is
destructive (for example `cluster leave` or `db migrate down`), QPot prompts for
confirmation unless you pass the corresponding `--force` / `--yes` flag.

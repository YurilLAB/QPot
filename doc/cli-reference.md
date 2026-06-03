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
  - [`qpot up`](#qpot-up)
  - [`qpot down`](#qpot-down)
  - [`qpot status`](#qpot-status)
- [Instance management — `qpot instance`](#instance-management--qpot-instance)
- [Honeypot management — `qpot honeypot`](#honeypot-management--qpot-honeypot)
- [Logs — `qpot logs`](#logs--qpot-logs)
- [Docker management — `qpot docker`](#docker-management--qpot-docker)
- [Database migrations — `qpot db`](#database-migrations--qpot-db)
- [Cluster / pairing — `qpot cluster`](#cluster--pairing--qpot-cluster)
- [Yuril integration — `qpot yuril`](#yuril-integration--qpot-yuril)
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
| `qpot up` | Start an instance and all of its enabled honeypots. |
| `qpot down` | Stop a running instance and its honeypots. |
| `qpot status` | Show the live status of an instance's honeypots and services. |
| `qpot instance` | Create, list, and remove instances. |
| `qpot honeypot` | Enable, disable, and list honeypots within an instance. |
| `qpot logs` | View logs from one honeypot or all honeypots. |
| `qpot docker` | Inspect and manage the underlying Docker containers. |
| `qpot db` | Inspect schema versions and run/roll back migrations. |
| `qpot cluster` | Pair multiple nodes into a managed group (aliases: `group`, `pair`, `networking`). |
| `qpot yuril` | Configure and inspect the Yuril Security Suite integration. |
| `qpot config` | Open or print the instance config file. |
| `qpot id` | Show the QPot ID for an instance. |
| `qpot completion` | Generate a shell autocompletion script. |

---

## Instance lifecycle

The three commands you will use most. Each one targets a single instance via
`-i, --instance` (default `default`).

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
| `enable [honeypot]` | `-i, --instance` | Enable a honeypot in the instance config. |
| `disable [honeypot]` | `-i, --instance` | Disable a honeypot in the instance config. |

`-i, --instance string` selects the instance (default `default`) for all three.

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
the **HiFi `ssh-proxy`**, for 27 entries in total. `enable`/`disable` only edit
the config — run `qpot up` afterward to apply the change.

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
| `--qpot-id string` | QPot ID (auto-detected if unset). |

```bash
qpot cluster join --id qc_abc123 --password "SecurePass123!" --seed 192.168.1.10:7946
qpot cluster join --id qc_abc123 -p "MyP@ssw0rd" -s 10.0.0.5:7946 -s 10.0.0.6:7946 --node-name sensor-01
```

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

### `qpot cluster leave`

```text
qpot cluster leave [flags]
```

| Flag | Description |
|------|-------------|
| `-f, --force` | Skip the confirmation prompt. |

### `qpot cluster nodes` / `qpot cluster status`

Both take no flags beyond the global ones.

```bash
qpot cluster status   # cluster summary: ID, name, node counts, total events
qpot cluster nodes    # per-node table: ID, name, address, status, events
```

---

## Yuril integration — `qpot yuril`

Manage QPot's outbound forwarder to **YurilTracking** and the inbound,
bidirectional API used by **YurilAntivirus**.

```text
qpot yuril [command]
```

| Subcommand | Flags | Description |
|------------|-------|-------------|
| `setup` | `-i, --instance` | Interactively configure the forwarder and write it into the instance config. |
| `test` | `-i, --instance` | Validate connectivity end-to-end (auth + TLS + reachability). |
| `status` | `-i, --instance` | Show the configuration, inbound endpoint URLs, and live forwarder counters. |

`-i, --instance string` selects the instance (default `default`).

```bash
qpot yuril setup     # prompts for endpoint, API key (hidden), source label, TLS
qpot yuril test      # reports success / auth failure / TLS issue / unreachable distinctly
qpot yuril status    # config + live counters from /api/yuril/health when the server is running
```

**How it works.** `setup` walks through the forwarder settings and persists
them. `test` builds a real `Forwarder` and submits an empty test batch, so it
exercises the exact auth and TLS path a live forward would use, and classifies
failures (auth vs. TLS vs. unreachable host) so misconfigurations are easy to
pinpoint. `status` reads live counters from the running web server's
`/api/yuril/health` endpoint.

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

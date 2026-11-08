# Installation and setup

- [Requirements](#requirements)
- [Install the qpot program](#install-the-qpot-program)
- [How the installers check downloads](#how-the-installers-check-downloads)
- [Set up an instance](#set-up-an-instance)
- [What setup does](#what-setup-does)
- [Running instances by hand](#running-instances-by-hand)
- [Dedicated sensor hosts](#dedicated-sensor-hosts)
- [When something goes wrong](#when-something-goes-wrong)

## Requirements

| | Minimum | Recommended |
|---|---|---|
| Memory | 1 GiB | 2 GiB or more (more for the `standard` and `hifi` profiles) |
| Disk | 2 GiB free | 5 GiB or more (data is kept for 90 days) |
| CPU | amd64 or arm64 | |
| Container runtime | Docker Engine with the Compose plugin | `qpot setup` can install it |

Supported hosts:

- **Linux:** Debian, Ubuntu, Raspberry Pi OS, Fedora, CentOS Stream, Rocky,
  AlmaLinux, RHEL, openSUSE and Arch.
- **macOS and Windows:** through Docker Desktop. Honeypots run inside Docker
  Desktop's Linux VM, so a dedicated Linux host is the better choice for a
  sensor exposed to the internet.

## Install the qpot program

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex

# From source (Go 1.26+)
git clone https://github.com/YurilLAB/QPot.git && cd QPot && make build
```

The release installers currently install v1.0.0. The new industrial profile
catalog and refrigeration supervisor are unreleased features on `main`; use
the source-build option above to try them. It creates `./qpot`; run that binary
to use the additions.

The installers offer to run `qpot setup` straight away. `QPOT_NO_SETUP=1`
installs the program only, and `QPOT_SETUP_ARGS="--yes --install-docker"` runs
setup without questions.

## How the installers check downloads

Before they install anything, the installers check what they downloaded:

- the release archive must match its line in the release's `SHA256SUMS`;
- downloads may only come from GitHub's release servers: a redirect elsewhere
  stops them;
- with the [GitHub CLI](https://cli.github.com) installed, they also verify the
  archive's build provenance. `QPOT_REQUIRE_PROVENANCE=1` makes that check
  mandatory.

Until a release is published they build from source instead, but only the one
commit they pin, which git checks by its hash; Go checks every dependency
against that commit's `go.sum`. Any failed check stops with a coded error and
installs nothing. To check a release download yourself, see
[Releases](development.md#releases).

## Set up an instance

```bash
qpot setup                          # guided: a few questions, each with a safe default
qpot setup --yes                    # no questions: flags and defaults (minimal: cowrie + endlessh)
qpot setup --yes --install-docker --docker-group --profile standard
qpot setup --profile industrial     # one Modbus PLC, no unrelated honeypots
qpot setup --profile refrigeration  # native cold storage supervisor
qpot setup --profile hifi --service # real-OpenSSH HiFi mode, as a systemd service
qpot setup --dry-run                # show what setup would do, change nothing
qpot doctor                         # re-check health at any time (non-zero on failure)
```

In a terminal, `qpot setup` asks for:

- the instance name;
- the honeypots: `minimal`, `standard`, `hifi`, `industrial`, `refrigeration` or a list of names;
- the web UI address and port;
- the database;
- whether honeypots may connect out to the internet;
- the attack-map country;
- the GeoIP download;
- whether to start at boot.

Enter takes the recommended answer, and a wrong answer is asked again. Without
a terminal, or with `--yes`, nothing is asked and every answer comes from a
flag instead. `qpot setup --help` lists them.

| Profile | Honeypots |
|---|---|
| `minimal` | cowrie (SSH/Telnet) and endlessh (an SSH tarpit). Low risk, a good start. |
| `standard` | minimal plus dionaea, heralding, conpot and adbhoney |
| `hifi` | minimal plus real OpenSSH servers behind a broker ([HiFi mode](ssh-hifi-proxy.md)) |
| `industrial` | Conpot only, explicitly presenting a Schneider Modicon M340 PLC (Modbus/TCP); change the device in the dashboard or CLI. |
| `refrigeration` | Native refrigeration supervisor only; simulated retail cold storage, with an optional plasma scenario. First start builds its image locally ([details](refrigeration.md)). |

## What setup does

1. **Docker.** It checks Docker Engine and the Compose plugin. If anything is
   missing, it shows the exact commands it would run and waits for your yes
   before it installs, updates or starts them. `--install-docker` gives that
   yes in advance.
   - On Debian, Ubuntu, Raspberry Pi OS, Fedora, CentOS Stream, Rocky,
     AlmaLinux and RHEL it uses Docker's own signed repository and checks the
     signing key's published fingerprint.
   - Where Docker has no packages for the release, and on openSUSE and Arch, it
     uses the distribution's own.
   - Root commands run through `sudo`.
   - On macOS and Windows it installs Docker Desktop through Homebrew or
     winget. You accept Docker Desktop's licence yourself.
2. **The docker group.** It offers to add your user to the `docker` group.
   Being in that group is the same as having root, so it asks first and
   defaults to no. `--docker-group` answers yes.
3. **The instance.**
   - It checks memory, disk space and the ports.
   - It creates the instance with a fresh QPot ID and a random database
     password.
   - It downloads the free [DB-IP](https://db-ip.com) Lite country database.
     `--no-geoip` skips it, and `qpot geoip update` refreshes it monthly.
4. **Start.** It starts the containers and the control plane, and waits until
   everything is healthy.
5. **Summary.** It prints:
   - the web UI address and how to log in (the QPot ID is shown only on your
     own terminal, never written to a log);
   - an `ssh -L` tunnel command for other computers;
   - the honeypots and their ports;
   - where the files are, and the next commands.

Setup can be run again at any time: it checks what is already done and
continues from there. After a failure it offers your previous answers. The web
UI and database listen on `127.0.0.1` by default; choosing another address
prints a warning, because the web UI uses plain HTTP.

## Running instances by hand

```bash
qpot instance create production
qpot up -d -i production    # containers + background control plane (qpot serve)
qpot status -i production
qpot down -i production
```

The **control plane** runs inside `qpot up`. With `-d` it runs in the
background as `qpot serve` and logs to `logs/qpot-serve.log` in the instance's
folder. It holds:

- the web UI and API;
- the intelligence worker;
- alerts;
- cluster membership;
- the HiFi backend recycler.

After an unclean stop, `qpot up -d` and `qpot setup` start whichever parts are
not running.

## Dedicated sensor hosts

`sudo ./install.sh` from a clone runs the T-Pot-style Ansible installer, for
AlmaLinux, Arch, Debian, Fedora, openSUSE, RHEL, Rocky, Ubuntu and others.

## When something goes wrong

Every problem setup, `qpot doctor` and the installers report has a code such
as `QP-PKG-001`, with what went wrong, why, and what to do. The process exits
with the code's category status.

```bash
qpot doctor                       # check every part of the instance
qpot doctor --explain QP-PKG-001  # explain one code
```

[setup-errors.md](setup-errors.md) lists every code. The same checks are on the
web UI's **Doctor** tab.

<p align="center">
  <img src="doc/qpot_wallpaper.png" alt="QPot" width="800">
</p>

<h1 align="center">QPot</h1>

<p align="center">
  <strong>A honeypot platform built on T-Pot, made harder to recognise</strong>
</p>

<p align="center">
  <a href="https://github.com/YurilLAB/QPot/actions/workflows/ci.yml"><img src="https://github.com/YurilLAB/QPot/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8.svg?style=flat-square" alt="Go 1.26+"></a>
  <a href="https://www.docker.com"><img src="https://img.shields.io/badge/Docker-required-2496ED.svg?style=flat-square" alt="Docker required"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=flat-square" alt="GPLv3"></a>
</p>

QPot runs the proven honeypot images of [T-Pot CE](https://github.com/telekom-security/tpotce)
from a single `qpot` program. Where every T-Pot install looks the same to an
attacker, every QPot instance is a believable machine of its own. QPot also
keeps the honeypots away from your network, analyses what attackers do, and
brings T-Pot's web interface with a dashboard for all of it.

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Everyday use](#everyday-use)
- [Documentation](#documentation)
- [Disclaimer](#disclaimer)
- [Credits and licence](#credits-and-licence)

## Features

- **27 honeypots** from T-Pot's upstream images, covering SSH, Telnet, web,
  mail, databases, industrial control systems, medical systems and more.
- **A believable identity per instance.** Each instance gets its own operating
  system, SSH version, host name, users and files, kept across restarts. Shell
  commands answer the way the real tools do. An optional high-interaction mode
  puts attackers on real OpenSSH servers that are rebuilt after every session.
- **Safe by default.** Every honeypot has its own network, no Linux
  capabilities beyond what it needs, a read-only filesystem and resource
  limits. An egress guard stops honeypots reaching your local network, the host
  or cloud metadata. The web UI and database listen only on the local machine.
- **Built-in analysis.** Events flow into ClickHouse or TimescaleDB, are tagged
  with MITRE ATT&CK techniques, and yield indicators of compromise and attacker
  campaigns, with a MISP export.
- **T-Pot's web UI in QPot's colours.** The landing page and live attack map,
  plus a dashboard for honeypot controls, events, intelligence, canaries and
  health checks.
- **Canaries.** Decoy credentials, files and links you plant in your own
  environment, plus bait planted inside the honeypots. QPot raises a critical
  alert when it observes one in use; [canary.md](doc/canary.md) explains what it
  can and cannot detect.
- **Guided setup.** `qpot setup` installs Docker from Docker's signed
  repositories, starts everything and checks it is healthy. Every problem comes
  with a plain-English explanation and a code such as `QP-PKG-001`.
- **Clusters.** Several nodes can share health and attacker data over TLS, each
  with its own certificate.

## Screenshots

<p align="center">
  <img src="doc/images/web-ui-landing.png" alt="Landing page" width="800">
</p>

<p align="center">
  <img src="doc/images/web-ui-map.png" alt="Live attack map" width="49%">
  <img src="doc/images/web-ui-dashboard.png" alt="Dashboard" width="49%">
</p>

## Requirements

| | |
|---|---|
| Operating system | Linux: Debian, Ubuntu, Raspberry Pi OS, Fedora, CentOS Stream, Rocky, AlmaLinux, RHEL, openSUSE or Arch. macOS and Windows work through Docker Desktop. |
| Processor | amd64 or arm64 |
| Memory | 2 GiB or more (1 GiB minimum) |
| Disk | 5 GiB or more free |
| Docker | Docker Engine with the Compose plugin. `qpot setup` can install it for you. |

For a sensor exposed to the internet, use a dedicated Linux host or VM. More
detail is in [installation.md](doc/installation.md#requirements).

## Quick start

Install the `qpot` program. The installers check the download's checksum and
build provenance before installing anything.

```bash
# Linux and macOS
curl -fsSL https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.sh | bash

# Windows (PowerShell)
irm https://raw.githubusercontent.com/YurilLAB/QPot/main/scripts/install.ps1 | iex
```

Set up and start an instance. Setup asks a few questions, each with a safe
default, and prints how to reach the web UI when everything is healthy.

```bash
qpot setup
```

Then open `http://127.0.0.1:8080` and sign in with the QPot ID that `qpot id`
prints. From another computer, use an SSH tunnel:
`ssh -L 8080:127.0.0.1:8080 <user>@<qpot-host>`.

## Everyday use

```bash
qpot status                        # what is running
qpot doctor                        # check every part, with a fix for each problem
qpot honeypot list                 # honeypots, ports and risk levels
qpot honeypot enable dionaea       # turn a honeypot on
qpot honeypot set cowrie persona=rhel-9
qpot logs cowrie -f                # follow a honeypot's log
qpot overview                      # activity and host load in the terminal
qpot down                          # stop the instance
qpot up -d                         # start it again
```

Every command has `--help`, and the [CLI reference](doc/cli-reference.md) lists
them all.

## Documentation

| | |
|---|---|
| [Installation and setup](doc/installation.md) | Requirements, installers, guided setup |
| [Web UI](doc/web-ui.md) | The landing page, attack map and dashboard |
| [Configuration](doc/configuration.md) | The settings file and what you can change |
| [Honeypots](doc/honeypots.md) | The 27 honeypots and how to manage them |
| [Deception](doc/deception.md) | How each instance gets its own identity |
| [Data and threat intelligence](doc/intelligence.md) | Collection, ATT&CK tagging, IOCs and campaigns |
| [Canaries](doc/canary.md) | Decoys, bait and what a trip means |
| [Alerts and response hooks](doc/alerts.md) | Webhooks and your own commands |
| [Clusters](doc/clustering.md) | Pairing nodes, enrollment and trust |
| [Architecture](doc/architecture.md) | What runs where, and how data flows |
| [Security model](doc/security.md) | Isolation, the egress guard, safe operation |
| [CLI reference](doc/cli-reference.md), [Web API](doc/api.md), [Error codes](doc/setup-errors.md) | Reference |

The full index is in [doc/README.md](doc/README.md).

## Disclaimer

A honeypot invites attacks. Run QPot on a host you are prepared to see
attacked, never on a computer that holds personal or business data, and keep
it updated. You are responsible for what you deploy and for complying with the
laws that apply to monitoring network traffic where you run it. QPot is
provided as is, without warranty, under the terms of its licence.

## Credits and licence

QPot is released under the [GPL-3.0](LICENSE). It builds on
[T-Pot CE](https://github.com/telekom-security/tpotce) by Deutsche Telekom
Security and on the work of every honeypot project T-Pot packages. Country
data comes from [DB-IP](https://db-ip.com) Lite (CC BY 4.0), and the attack
map's outlines from [Natural Earth](https://www.naturalearthdata.com).

Questions and bug reports: [GitHub Issues](https://github.com/YurilLAB/QPot/issues).

<p align="center"><strong>Built by Yuril Security</strong><br><em>Australian-made cybersecurity</em></p>

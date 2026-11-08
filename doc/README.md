# QPot documentation

## Getting started

| Page | What it covers |
|---|---|
| [Installation and setup](installation.md) | Requirements, installing the program, guided setup and what it does |
| [Web UI](web-ui.md) | Signing in, the landing page, the attack map and every dashboard tab |
| [Configuration](configuration.md) | The instance's settings file and the settings you can change |

## Using QPot

| Page | What it covers |
|---|---|
| [Honeypots](honeypots.md) | The 28 honeypots, turning them on and off, and the LLM honeypots |
| [Refrigeration supervisor](refrigeration.md) | Retail and plasma scenarios, controller controls, exports and canaries |
| [Deception](deception.md) | How each instance gets its own believable identity |
| [Data and threat intelligence](intelligence.md) | Event collection, the databases, ATT&CK tagging, IOCs and campaigns |
| [Canaries](canary.md) | Decoy credentials, files and links, and the bait planted in the honeypots |
| [Alerts and response hooks](alerts.md) | Webhook alerts and running your own commands |
| [Clusters](clustering.md) | Pairing several QPot nodes, enrollment and trust |

## Reference

| Page | What it covers |
|---|---|
| [CLI reference](cli-reference.md) | Every `qpot` command and flag |
| [Web API](api.md) | Every API endpoint, with its answers and errors |
| [Error codes](setup-errors.md) | Every `QP-` code, with its cause and fix |

## How it works

| Page | What it covers |
|---|---|
| [Architecture](architecture.md) | What runs where, and how an attack becomes data on the dashboard |
| [Security model](security.md) | Isolation, the egress guard and running a sensor safely |
| [HiFi mode](ssh-hifi-proxy.md) | Real OpenSSH behind a transparent broker |
| [SSH fingerprint comparison](fingerprint-comparison.md) | Stock Cowrie, QPot and real OpenSSH under `nmap` |
| [Development](development.md) | Building, testing, CI and releases |

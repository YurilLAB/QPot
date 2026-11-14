# Security model

A honeypot invites attackers in, so QPot is built to keep them inside the
honeypot and away from your network, your host and your data.

| Area | What QPot does |
|---|---|
| Isolation | Each honeypot on its own bridge network, with a non-overlapping subnet |
| Egress | Honeypots cannot open connections to your LAN, the Docker host, cloud metadata (`169.254.169.254`, the Azure WireServer) or any other private, loopback, link-local, CGNAT or multicast address. Replies to attackers, public destinations and DNS to the host's resolvers still work. |
| Runtime | The requested gVisor or Kata runtime must be available and match the containers; missing or unverifiable isolation stops startup |
| Containers | `cap_drop: ALL` with minimal add-backs, read-only root with tmpfs, no privileged containers |
| Limits | CPU, memory, PID and file-descriptor limits per honeypot, and CPU, memory and PID limits on the database, collector and egress guard. Swap is capped at the memory limit, so a 512 MiB container cannot use more memory by swapping. The database gets at least 1 GiB and one CPU whatever the honeypot limit is, and a server configuration sized for that: at 512 MiB without swap ClickHouse ran at its limit and stalled. `qpot doctor` warns (QP-RES-006) when Docker cannot apply a limit. |
| Secrets | The QPot ID is held only by the control plane, a host process. No container gets it: not the honeypots, not the database, not the collector. It is not written to logs, events or log backups, not sent in alerts or cluster traffic, and not returned by the API. Events carry a separate sensor ID. The database password is random per instance. |
| Exposure | Web UI, API and database bound to `127.0.0.1` by default. The control plane refuses to start with no login on any other address. |
| Web | CSP, `X-Frame-Options: DENY`, `nosniff`, constant-time login checks, the QPot ID accepted only in a header |
| HiFi backends | No outbound network, recreated after every session, read-only host keys |
| Downloads | The installers verify checksums and build provenance before installing anything |

## Mandatory containment controls

Every attacker-facing container gets these, whatever `config.yaml` says. The
settings that used to switch them off (`security.read_only_filesystem`,
`drop_capabilities`, `no_new_privileges`,
`network_isolation.separate_networks`) are still read, so old files load, but
`false` is ignored with a warning. A file that leaves the `security` section
out gets them too.

| Control | What it means |
|---|---|
| Read-only root | The image's filesystem cannot be changed; scratch space is tmpfs. Two exceptions: HiFi SSH backends, which are real systems thrown away after each session, and `snare` (tanner's web front end), which writes its log next to the pages its image ships. |
| No capabilities | `cap_drop: ALL`, with a short reviewed add-back per image (`SETUID`, `SETGID`, `NET_BIND_SERVICE` and a few a specific image needs). Never `SYS_ADMIN`, `NET_ADMIN` or `SYS_PTRACE`. |
| No new privileges | setuid binaries inside a container cannot raise privileges |
| Its own network | One bridge per honeypot. No honeypot is on the host network, the control network or another honeypot's bridge. |
| Resource limits | CPU, memory, PID limits, swap capped at the memory limit, a bounded restart count. A limit left at zero is replaced by the default. |
| Nothing of the host | No privileged mode, no host PID or IPC namespace, no devices, no Docker socket, no QPot ID |

`TestMandatoryContainmentCannotBeSwitchedOff` renders every honeypot with all
four former switches off and checks each line of this table.

### Honeypot classes, and what a start requires

QPot sorts honeypots into two classes.

- **Reviewed emulators**: `cowrie`, `conpot`, `refrigeration`. They answer
  from a script and never run what a visitor sends.
- **Sensitive workloads**: everything else. Real services and third-party
  native code that parse, relay or run attacker input: HiFi SSH (`ssh-proxy`),
  tanner's PHP sandbox, dionaea, and any honeypot QPot has not reviewed.

Some containment depends on the host or on a setting, so it is checked when a
honeypot is started, recreated or restarted. A refused start changes nothing:
no file is written and Docker is not asked to start anything.

| Requirement | Emulators | Sensitive workloads |
|---|---|---|
| gVisor or Kata runtime (`sandbox_mode`) | Required, unless `sandbox_fallback: docker` or `sandbox_mode: none` | Required, unless `sandbox_mode: none`. No fallback. (QP-DOCKER-010, 011, 012) |
| Egress guard | May be switched off with `allow_private_egress: true` | Required. HiFi SSH keeps its own guard whatever the setting says; any other sensitive workload with the guard off is refused (QP-INST-015). |
| Docker confirms it enforces CPU, memory, swap and PID limits | A doctor warning if not (QP-RES-006) | Required (QP-RES-005 for HiFi SSH, QP-RES-007 for the rest) |

`sandbox_mode: none` is the one way to run a sensitive workload on Docker's
standard runtime. It is an explicit choice, never a fallback, and the other
two requirements still apply.

`qpot doctor` shows the result as `containment settings`, `honeypot
isolation` and `resource limits`.

## Web UI and API login

The management API takes the QPot ID (the default), or HTTP Basic
authentication when `web_ui.qpot_id_auth` is `false` and both
`web_ui.username` and `web_ui.password` are set. With `qpot_id_auth: false`
and either of the two empty there is no login at all.

| Login | `bind_addr` on loopback | any other `bind_addr` |
|---|---|---|
| QPot ID | starts | starts |
| Basic | starts | starts |
| none | starts; `qpot doctor` warns that any local user or process can manage the instance | refused (QP-WEB-005): `qpot up` stops before starting a container, `qpot serve` does not listen |

An empty address, `0.0.0.0`, `::` and a host name other than `localhost`
count as reachable from other computers. There is no setting that overrides
the refusal. To put the UI behind a reverse proxy, keep a login on and let
the proxy pass the header, or bind to loopback and proxy from the same host.

## Team access: keys with roles

The QPot ID is the owner's key and can do everything. Other people get a key
of their own, with a role, instead of a copy of it:

| Role | May |
|---|---|
| `viewer` | read everything the web UI and API show |
| `analyst` | also create and delete canaries, and switch behaviour alert rules |
| `admin` | everything the owner can do in the web UI: honeypots on and off, their settings, restarts, disk cleanup |

```bash
qpot access add alice --role viewer   # prints alice's key, once
qpot access list
qpot access remove alice              # the key stops working within seconds
qpot access log                       # who changed what
```

- A member's key has the form of a QPot ID and signs in the same way, in the
  `X-QPot-ID` header. It is 120 random bits, printed once and stored only as
  its SHA-256 (`access.json` in the instance's data folder, mode 0600). A
  lost key is replaced by removing the member and adding them again.
- Members are managed on the host only. No web request can add a member,
  change a role or read a key, so a stolen web session cannot make itself a
  key.
- A request a role may not make is answered `403` with the code
  `QP-WEB-006`. The role is checked in the control plane for every
  request; what the web UI shows or hides is not the control.
- Every request that changes something, and every refused one, is appended
  to `audit.log` in the data folder with the member's name, role, method,
  path, status and remote address. Reads are not logged. The log is set aside
  as `audit.log.1` at 4 MiB. The owner and admins see it on the Security tab.
- If `access.json` is damaged, no member is let in and the QPot ID still
  works; the control plane's log says so.

What roles do not do: a viewer reads everything, including captured
passwords, decoy credentials and canary values. Roles limit who can change
the instance, not what a member can learn from it. Anyone with a shell on the
host as the instance's user is the owner. With HTTP Basic authentication or
no login (`web_ui.qpot_id_auth: false`) there are no members: every request
acts as the owner.

## The QPot ID and the sensor ID

The QPot ID (`qp_` and 24 characters, in `qpot.id`) is the API credential. The
sensor ID (`qs_` and 24 characters) names the instance in events, in the
collector's output and in log backups. It is derived from the QPot ID with a
keyed one-way function, so it is stable for the life of the instance and
reading it gives no access. `qpot up` prints the QPot ID only on a terminal:
under systemd, or with output redirected, it prints where to find it instead.

Versions up to 1.0.1 stamped the QPot ID itself into every event. It was not
stored in the database, but it reached the collector's console log, each line
of `backup/logs/<date>/<honeypot>.log`, the database's and collector's
environment (and from there each line of their container logs) and the header
of `vector.yaml` and `docker-compose.yml`. After an upgrade:

1. Restart the instance: `qpot down -i <name>`, then `qpot up -d -i <name>`.
   This regenerates both files, recreates the containers (their old logs go
   with them) and rewrites the existing log backups in place, replacing the
   QPot ID with the sensor ID. The collector is stopped for the rewrite and
   reads on from its checkpoint afterwards, so no event is lost.
2. Run `qpot doctor`. The line `QPot ID in stored files` must say `ok`.
3. If log backups were copied off the host before the upgrade (a SIEM,
   off-site storage), whoever can read those copies has the old QPot ID.
   The ID cannot be changed without changing the instance's deception
   identity, so delete or rewrite those copies, and keep the web UI on
   loopback.

## Container isolation policy

`security.sandbox_mode` selects `gvisor`, `kata` or an explicitly chosen `none`.
The default is `gvisor`. QPot checks the selected Docker daemon for the requested
runtime before starting or recreating honeypots. A missing runtime, unreadable
runtime report or misspelled mode does not silently select ordinary Docker.
Firejail is rejected: QPot does not wrap its Docker containers in Firejail, so
finding the executable would not establish container isolation.

```yaml
security:
  sandbox_mode: gvisor
  sandbox_fallback: deny
```

`sandbox_fallback: deny` is the default. An operator may explicitly choose
`docker` to permit ordinary Docker fallback for supported non-executing
emulators when the requested runtime is absent. It does not permit fallback
when Docker's runtime report cannot be verified. HiFi SSH, Tanner's PHP
execution and other services not explicitly recognized as non-executing
emulators cannot use this fallback. Per-honeypot risk labels do not override
that restriction.

Choosing `sandbox_mode: none` deliberately uses Docker's configured default
runtime; it does not claim a gVisor or Kata boundary. Use a dedicated sensor
host or VM and the remaining network, resource and storage controls. Removing
a requested runtime does not prevent stopping or inspecting an instance.

Docker Desktop on Windows and macOS has only Docker's standard runtime, so
the default policy refuses to start there (QP-DOCKER-011, which names the
runtimes the daemon has). To run on Docker Desktop, set `sandbox_mode: none`
in the instance config (`qpot config`), or, with only cowrie, conpot and
refrigeration enabled, `sandbox_fallback: docker`. For gVisor, run QPot
against a Linux Docker host and register it there with `sudo runsc install`.

Changing the configured runtime requires recreating containers. Restarting
existing containers cannot change their runtime. `qpot doctor` and the doctor
API inspect the actual runtime of this instance's honeypot containers; runtime
registration alone is not a healthy isolation result. Setup distinguishes the
configured choice from verified running containers and reports an explicit
fallback as ordinary Docker, rather than advertising the requested runtime.

## The egress guard

An nftables guard, the `netguard` service, enforces the egress rules. It runs
on the host network with `NET_ADMIN` only, and honeypots start only after it is
in place.

- It runs where Docker's bridges live: on the host itself on Linux, and in
  Docker Desktop's VM on Windows and macOS.
- Its rules outlive a stopped stack until the next reboot.
- The `netguard` service applies them again whenever it starts. Docker restarts
  it with the honeypots after a reboot.

Two settings change it (see [configuration.md](configuration.md)):

- `block_outbound: true` stops honeypots opening any outbound connection.
- `allow_private_egress: true` switches the guard off. This is not recommended,
  and allowed only while every enabled honeypot is a reviewed emulator
  (cowrie, conpot, refrigeration).

## Running a sensor safely

- **Use a dedicated host or VM** for a sensor exposed to the internet, not a
  computer with your personal data.
- **Keep the web UI on `127.0.0.1`** and reach it over an SSH tunnel (see
  [web-ui.md](web-ui.md)). It uses plain HTTP.
- **Watch `qpot doctor`.** It checks every part of the instance.
- **Choose high-interaction honeypots deliberately.** HiFi mode and the LLM
  honeypots carry more risk than the `minimal` profile.

## Release secret scanning and historical keys

CI scans committed changes and the working tree with the pinned upstream
Gitleaks rules, including new files under `docker/`. This separate raw gate
does not use the repository's decoy allowlist, historical fingerprints or
inline exemptions. Its reviewed baseline is commit
`3a77efdc3f1a299f4768392fc1cb2b6883f69f9b`; changing that baseline requires a
new review. It was moved twice on 2026-11-14, each time after the one finding
in between was reviewed: from `85791219d54574fca5d68c60dbbd474f5dfc195a` to
`1c342506c7060aad7064be52e703bceab76b54a9` past a line comparing a key hash
with the hex alphabet, and from there past the first and last line of an
OpenSSH private key file spelled out in the code of Cowrie's `ssh-keygen`,
with no key between them. The scanner took each for a key; both have been
reworded. A missing baseline, scanner or pinned default rules fails the gate.
The release gate also scans the unpacked standalone archives, projecting
executable bytes into text so a binary-file exclusion cannot silently skip
them. Compressed or encrypted content inside an executable is not recursively
decoded. These checks supplement, rather than replace, credential management.

Two real nginx private keys entered the public upstream history in commit
`12842527bbd1d56554a877af83e69fbaf5997fd5` on 2016-07-30, under
`installer/etc/nginx/ssl/` and its `test/` directory. They are absent from the
current source tree. Their matching self-signed certificates expired on
2026-07-27. `.gitleaksignore` acknowledges only those exact historical findings;
they are **known public exposures**, not false positives. A new key, a
reintroduced file or a new commit does not inherit that acknowledgement.

Never deploy or reuse those historical keys. Certificate expiry does not
revoke a private key, and the repository cannot establish whether another
installation reused or rotated a copy. Operators of a legacy installation
that used them must replace its key and certificate and check for reuse.
The acknowledgement does not claim those external installations are safe.

## Semantic analysis before publication

The image and release workflows require completed CodeQL analysis with the
Go bundle and query pack pinned in `.github/ci-tools.env`. Analysis traces the
normal production build without rewriting module files. Missing, malformed or
failed reports and security findings without an exact reviewed disposition
stop publication.

`.github/codeql-reviews.json` records independently reviewed false positives
and intentional decoy behavior. Each entry binds the complete result,
including code flows and fingerprints, to its referenced source and proof
files. A separate catalog binds every non-test Go source path and its contents,
including platform files, plus all `go.mod` and `go.sum` files. New, renamed or
changed catalog inputs invalidate the reviews. Changed proof files also require
review; resolved findings must be removed from the manifest.

To renew a review, run fresh analysis with the pinned producer, inspect each
finding against the current program and its tests, and retain the original
SARIF as evidence. Update only the findings independently validated as false
positives or intentional decoys. Do not disable queries or automatically accept
SARIF suppressions. Tool or query upgrades require fresh analysis and review.
Validate the resulting manifest against the actual reports:

```bash
go run ./internal/cicheck/cirun check-codeql /path/to/sarif .github/codeql-reviews.json
```

The summary retains the reported and reviewed finding counts; reviewed decoy
behavior does not turn a report into a zero-finding scan.

## Reporting a vulnerability

Please don't post details of a security problem in a public issue. Open an
[issue](https://github.com/YurilLAB/QPot/issues) that only asks for a private
contact, and the maintainer will reply with one.

# High-Interaction SSH Proxy (“HiFi” mode)

Closing the protocol-fingerprinting gap by terminating the attacker’s SSH
handshake at a **real OpenSSH daemon** instead of an emulated Python transport.

---

## 1. The problem: single-packet protocol fingerprinting

Low- and medium-interaction SSH honeypots (Cowrie, Kippo) implement the SSH
*transport* themselves, in Python (Twisted/`conch`). Vetterl & Clayton,
*“Bitter Harvest: Systematically Fingerprinting Low- and Medium-Interaction
Honeypots at Internet Scale”* (USENIX WOOT ’18), showed that this transport
answers protocol edge cases — version-string handling, `KEXINIT` ordering,
reaction to malformed packets — **differently from OpenSSH**. A *single* crafted
packet, sent before authentication, reliably classifies the box as a honeypot,
no matter how convincing the post-login shell, filesystem, or credentials are.

Cowrie's persona engine (a per-instance persona, a consistent fake machine, see
the README's *Deception* section) raises the bar against keyword/Shodan/script
detection, and it sets the `KEXINIT` key-exchange and host-key lists from the
advertised OpenSSH release. **But that is only a partial mitigation:** the
cipher and MAC lists and the deeper packet-level behavior live in Cowrie's
Twisted/`conch` transport and still differ from OpenSSH (no
`chacha20-poly1305`, AES-GCM, ETM/umac MACs or `kex-strict`). So emulation
**cannot** fully defeat this class — the tell is ultimately in the transport
library, not the content.

### Why Cowrie’s own “proxy mode” does **not** close it

Cowrie can be built as a proxy in front of a backend “guest”. This is frequently
misunderstood as closing the fingerprinting gap. **It does not.** In Cowrie proxy
mode the attacker still completes the SSH handshake against *Cowrie’s Python
transport*; Cowrie then decrypts, logs, and originates a *second* SSH session to
the backend. The attacker-facing handshake — the exact thing Vetterl
fingerprints — is still Python. The backend’s realness is invisible to the
single-packet probe.

To actually close the gap, **the attacker’s handshake must terminate at real
OpenSSH**, with nothing of ours speaking SSH on that path.

---

## 2. The approach: a transparent Layer-4 splice

QPot HiFi mode puts a **transparent TCP broker** in front of a pool of
disposable **real-OpenSSH backend containers**. The default is one standalone
server per connection; the optional organization environment adds a real
PostgreSQL database and an SSH backup host to each private cell:

```
   attacker ──TCP──▶  qpot-sshproxy (L4 splice)  ──TCP──▶  real sshd (backend)
                      • copies opaque bytes              • genuine OpenSSH
                      • speaks NO SSH                     • genuine Linux/PTY
                      • no parser, no SSRF                • full session recording
```

The broker performs a pure byte splice: it `Read`s from one side and `Write`s to
the other, in both directions, treating the stream as opaque. It never parses,
buffers-to-inspect, or rewrites SSH. Therefore:

* The attacker’s SSH handshake reaches **genuine OpenSSH** → there is no emulated
  transport to fingerprint. The single-packet Vetterl technique sees real
  OpenSSH because it *is* real OpenSSH.
* The broker has **no SSH parser**, so it has no protocol attack surface, and it
  **cannot be coerced into dialing attacker-chosen hosts** (no SSRF): backend
  addresses come only from operator configuration.

Capture combines **inside-backend** sshd `VERBOSE` auth logging and PTY session
recording via `script(1)` with the broker's independent per-connection metadata
(source, byte counts, duration and teardown reason). The broker never sees SSH
plaintext. A hostile guest root can interfere with guest-side logs; those
recordings are useful evidence, not a tamper-proof command audit.

---

## 3. Components

| Component | Path | Role |
|---|---|---|
| Broker library | `internal/proxy/` | The L4 splice, backend pool, admission control, event log. Pure Go, no privileges. |
| Broker binary | `cmd/qpot-sshproxy/` | Wires the library from environment config; graceful shutdown. |
| Broker image | `docker/ssh-proxy/Dockerfile` | Distroless, **nonroot**, static binary. No shell, no docker access. |
| Backend image | `docker/ssh-backend/` | Real Debian + OpenSSH + PTY recording. The genuinely interactive jail. |

### 3.1 Broker library (`internal/proxy`)

* `Broker` / `Config` (`broker.go`) — accept loop, the bidirectional splice with
  **idle** and **absolute-session** deadlines, **TCP half-close** propagation,
  per-connection panic isolation, and context-driven graceful drain.
* `Pool` (`pool.go`) — leases one backend per session; a `ResetFunc` hook runs on
  release so each attacker gets a pristine box; a backend whose reset fails is
  **quarantined** (never handed to a new attacker).
* `limiter` (`limiter.go`) — per-source token-bucket rate limit, per-source
  concurrency cap, and global concurrency cap, with idle-bucket eviction. A
  source is an IPv4 address or an IPv6 /64, so rotating addresses inside one
  /64 does not reset the limits. The map holds at most 65,536 sources; past that,
  sources without a live connection are dropped. Rejections are logged at most
  once per source per second and 100 times a second overall; the next logged
  one (or a minute summary) carries how many were thinned out.
* `Event` / `JSONSink` (`event.go`) — newline-delimited JSON the Vector collector
  ingests like any other honeypot log; every field is from a trusted source, so
  there is no log-injection surface and stream bytes are never logged.

### 3.2 Broker binary configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `QPOT_SSHPROXY_LISTEN` | `:2222` | Listen address |
| `QPOT_SSHPROXY_NAME` | `ssh-proxy` | Logical honeypot name in events |
| `QPOT_SSHPROXY_BACKENDS` | *(required)* | `be1=ssh-backend-1:22,be2=ssh-backend-2:22` |
| `QPOT_SSHPROXY_LOG` | `/var/log/ssh-proxy/sessions.json` | NDJSON session log |
| `QPOT_SSHPROXY_HOST_READABLE_LOG` | unset (false) | Trusted opt-in to host-readable broker metadata; generated only after the neutral private store is verified ready. Custom deployments retain `0640` by default |
| `QPOT_SSHPROXY_IDLE` | `15m` | Idle-session timeout |
| `QPOT_SSHPROXY_MAXSESSION` | `2h` | Absolute session cap |
| `QPOT_SSHPROXY_RATE_IP` | `5` | New conns/sec per IP (token bucket) |
| `QPOT_SSHPROXY_BURST_IP` | `10` | Rate burst per IP |
| `QPOT_SSHPROXY_CONC_IP` | `3` | Max concurrent sessions per IP |
| `QPOT_SSHPROXY_CONC` | `128` | Max concurrent sessions globally |
| `QPOT_SSHPROXY_GENERATIONS` | unset | Read-only host recreation counters; set by generated Compose |
| `QPOT_SSHPROXY_CONTEXT_DIR` | unset | Per-cell context root; generated Compose sets `/run/audit-contexts`. Requires generation counters and a literal, non-wildcard listen address |
| `QPOT_SSHPROXY_CONTEXT_NAMESPACE` | unset | Generated per-instance namespace mapping finite backend IDs to opaque context directories; empty retains compatibility for custom broker deployments |

---

## 4. Security model

The broker forwards opaque bytes without SSH parsing or Docker privileges. The
backend provides genuine code execution inside its disposable container.
A high-interaction honeypot that an attacker can escape, or use to attack third
parties, is a liability — so the backend is wrapped in defense-in-depth:

1. **Egress lockdown.** Each backend slot has its own Docker bridge marked
   `internal: true`. Standalone servers have no outbound access. In organization
   mode, the application, database and backup host can communicate within that
   cell; they cannot use that relationship to reach another cell, the Docker
   host, LAN, management services or the Internet. The broker listens only on
   its separate ingress address. The host egress guard independently enforces
   private-cell boundaries, including the host gateway; `allow_private_egress`
   does not relax HiFi isolation. Its `check-cells` health check must pass before
   exposure. An older helper that lacks this check is incompatible and startup
   fails closed. SSH forwarding and tunnelling remain disabled.
2. **Stronger isolation runtime — with a deception trade-off to understand.**
   Run backends under gVisor (`runsc`) or Kata when available (QPot detects
   these) so real RCE sits behind more than namespaces. **But the choice affects
   deception, not just isolation:**
   - **Kata Containers** runs a Linux guest kernel in a lightweight VM. This
     avoids the host-kernel identity mismatch of plain containers, but VM
     devices and behavior can still be fingerprinted. It needs suitable
     hardware/nested virtualization and more resources.
   - **gVisor (`runsc`)** is excellent *isolation* (a userspace kernel intercepts
     syscalls), but it implements its own kernel and is **detectable from inside**
     — `uname`, parts of `/proc`, and the behaviour/availability of certain
     syscalls differ from a real kernel, and public gVisor-detection techniques
     exist. So gVisor **trades the SSH-transport tell for a sandbox tell**: a
     sophisticated attacker who probes the post-login environment may conclude
     "this is a gVisor sandbox." Prefer it where escape-resistance outweighs
     perfect post-login realism.
   - **Plain containers** share the **host kernel**, so the backend's `uname -r`
     is the host's kernel string. That is fine if the host kernel is plausible for
     the persona (e.g. a Debian/Ubuntu host), but inconsistent if, say, the host
     runs an Amazon-Linux kernel while `/etc/os-release` says Debian 12.
   The real backend userland is Debian 12 on the build host's architecture.
   Credential names and host names do not turn it into Ubuntu, RHEL, Proxmox or
   an emulated Cowrie persona. With plain containers, use a host kernel that is
   plausible for Debian; a runtime choice does not make the environment
   impossible to identify.
3. **No Docker access on the attacker path.** The broker and backend containers
   never receive the Docker socket or general host/control-plane filesystem
   access. Their explicit mounts carry generated scene material, read-only host
   keys and bounded logs. Backend reset is performed by the trusted host-side
   supervisor, never by the attacker-facing containers.
4. **Resource bounds.** Per-container CPU/memory/PID limits; broker admission
   control (rate + concurrency caps) bounds load on the finite, expensive pool.
   **Pool sizing matters:** the pool is non-blocking (one backend per live
   connection, fail-fast on exhaustion), so a connection that lingers — even one
   that just sits in the auth phase — holds a backend until it closes or hits the
   backend's `LoginGraceTime` (120 s) / the broker's idle timeout (15 min). Size
   `custom_config["backends"]` for expected concurrency; with the default 2, two
   simultaneous slow sessions can transiently exhaust the pool (further attempts
   are cleanly rejected with `no_backend_available`, never queued).
   HiFi app/backup roots are intentionally writable so real file, account,
   permission and installed-tool changes have normal OS consequences. This is
   an exception to the static honeypots' read-only roots. PostgreSQL data is on
   bounded ephemeral storage. QPot's log/capture cleanup budget is not a portable
   hard quota for writable image layers: Docker storage-driver support varies,
   and rootless VFS does not provide such quotas. Run genuine root shells on a
   dedicated sensor VM with an appropriate isolation runtime and storage bounds
   for that VM/driver. Verify cgroup enforcement on the host you deploy.
5. **Ephemerality.** State belongs to one ingress SSH TCP connection. Multiple
   SSH channels on that connection share the same server/cell. All cell services
   are recreated before another connection can use the slot; failed reset or
   health checks quarantine it. Reconnecting gets fresh state, even from the
   same source IP. See "Backend reset".
6. **No privilege bridge.** The QPot ID (management-API credential) is never
   mounted into honeypot containers, HiFi included.

### 4.1 Security audit — findings and mitigations

| # | Risk | Mitigation (in code / config) |
|---|---|---|
| 1 | **SSRF** — broker tricked into dialing arbitrary hosts | Backends come only from `ParseBackends` of operator config; attacker input is never used as a dial target. |
| 2 | **SSH-parser exploit** in the broker | The broker has no SSH parser; it copies opaque bytes. This does not claim that TCP handling or the real sshd has no attack surface. |
| 3 | **Connection-flood DoS** exhausting the backend pool | `limiter`: per-source rate + per-source and global concurrency caps, a source being an IPv4 address or an IPv6 /64; `Pool.Lease` is non-blocking and fails fast (no unbounded queue). Rejections are thinned (and counted) so the flood does not move into the log and database. |
| 4 | **Memory exhaustion** via churn of unique source IPs | `limiter.sweep` evicts idle per-source buckets; the map is capped at 65,536 sources between sweeps. |
| 5 | **Slowloris / abandoned sessions** pinning backends | Per-direction **idle deadline** on reads and writes (a peer that stops reading is torn down too) + absolute **MaxSession** deadline. |
| 6 | **Goroutine/fd leaks** | Every session’s goroutines exit on teardown; `Serve` drains via `WaitGroup`; conns closed in `defer`. Verified under `-race`. |
| 7 | **Reason misattribution** (normal close mislabeled idle) | Teardown uses `Close` (→ `net.ErrClosed`, not a timeout) so only genuine idle reads surface as timeouts. Regression-tested. |
| 8 | **TCP half-close** truncating a direction | `halfCloseWrite` propagates FIN to the peer and keeps the other direction draining. Fuzz-verified for transparency. |
| 9 | **Log injection** via attacker-controlled fields | Events carry only trusted fields, encoded with `encoding/json`; fuzz-verified to emit exactly one valid JSON line. |
| 10 | **Panic in one session** taking down the listener | Per-connection `recover`. |
| 11 | **Backend used as an outbound attack platform** | Private per-slot bridges, host cell guard, ingress-only broker listener and disabled sshd forwarding. Organization peers are the only connected decoys. |
| 12 | **Backend escape** | gVisor/Kata when available, limited capabilities/resources and narrowly scoped mounts. Runtime boundaries still require validation on the deployment host. |
| 13 | **Cross-connection contamination / persistence** | The entire leased cell resets; failed resets or peer health checks quarantine the slot. |
| 14 | **Privileged broker** (docker socket) | Broker is distroless nonroot with no docker access; resets are done by the host-side qpot control plane. |
| 15 | **Host-key rotation tell** | The trusted host generates and persists app host keys once and mounts them read-only at `/run/sshd/bootstrap/keys`, below a root-only bootstrap directory even when the source reports permissive Desktop modes. Connected backup hosts have their own stable key, matching the scene's known_hosts. |
| 16 | **Pool-inconsistency tell** (different host key / hostname per backend → SSH "host identification changed" warning on reconnect) | All backends share the SAME host keys (#15) AND the SAME hostname, so the pool presents as one server regardless of which backend a session lands on. |

---

## 5. Deployment

**Enabling HiFi mode is one command:**

```sh
qpot honeypot enable ssh-proxy        # then: qpot up
```

HiFi supports private per-connection cells and an optional connected organization.
Official release binaries select broker and backend images tagged with their full
source commit. Release publication requires both image manifests to exist for
the supported Linux architectures. Missing matching images fail startup; a
release does not fall back to an older mutable `latest` tag.

For a development checkout, build both HiFi images from that checkout and select
them explicitly:

```sh
make build
docker build -f docker/ssh-proxy/Dockerfile -t qpot-local/ssh-proxy:development .
docker build -f docker/ssh-backend/Dockerfile -t qpot-local/ssh-backend:development .
./qpot honeypot set ssh-proxy image_source=local
./qpot honeypot enable ssh-proxy
./qpot up -d
```

`image_source=local` uses those two fixed tags with no registry pull. It selects
the broker, SSH backends and required egress-guard helper, so build only from a
checkout you trust. Missing local images or incompatible helpers produce a
startup error; QPot does not substitute an older published image. The default
`image_source=published` uses QPot's registry images and normal pull behavior.
Official releases use their source-commit tag. Development builds without a
valid embedded full source revision retain legacy `latest` references for offline
rendering, but starting this newer HiFi wiring with them fails with
`QP-INST-013`. Build both Dockerfiles above from the same checkout and select
`image_source=local`, or use an official release with matching images.
The legacy `latest` channel is kept for existing release binaries; this update
publishes commit-specific images without moving that channel. Development
checkouts exercising new HiFi features must build and select local images.
`image_source=` restores that default. No image is published by these commands.
The release installers and their version pins are unchanged by selecting a local
image source.

The dashboard's **HiFi environment** and **HiFi images** settings expose the same
choices. Changing settings while the honeypot is off only saves them; it does not
enable it. Saving a running setting recreates the affected HiFi deployment and
ends its active connections. A saved setting is not evidence that a failed
recreation has become live; the API/UI reports that failure separately.
Restart and recycling also check the actual stored broker, application and
backup image references. Saving `image_source=local` alone does not upgrade an
older stored deployment. Recreate with compatible images; if the whole instance
is already running, stop it with `qpot down` before `qpot up -d`. These checks do
not block stop/remove or offline configuration planning.

### Connected application, database and backup

```sh
./qpot honeypot set ssh-proxy environment=organization image_source=local backends=2
```

Each slot contains a real Debian 12 application host, PostgreSQL 15 database and
Debian 12 SSH backup host. They share one seeded organization: application
connection settings, database names, decoy credentials, backup keys/host keys,
SQL schema and backup files agree. The app is an operations/batch server, not a
claim that an HTTP application or cron daemon is running. Its `backup-db` tool
uses the real PostgreSQL client and SSH to write a compressed SQL backup to the
connected backup host. SQL changes and file changes are real within the cell.
The app and backup use genuine writable Linux filesystems. Available local
packages/tools behave normally; network isolation does not make Internet package
repositories reachable, and unsupported installs must fail rather than produce
a fabricated success message.

The database is a digest-pinned official `postgres:15-bookworm` image. Its data
is ephemeral for this connection; the initial schema and backup come from the
same scene definition. The database has no published host port and is separate
from QPot's telemetry database. The backup host likewise has no published port.
Connection aliases and credentials describe only these controlled decoys.

`backends` is the number of simultaneous ingress SSH connections, from 1 to 16,
default 2. Standalone uses one decoy container per slot; organization uses three.
For two organization slots that is six decoy containers plus the shared broker
and existing instance services. CPU, memory and PID limits apply per container;
plan for the total, not only the app's limits. Finite admission and storage limits
still apply. A full pool rejects further connections rather than sharing a dirty
or already leased cell.

The `ssh-proxy` sensor's custom CPU, memory and PID limits apply to every app,
database and backup container as well as the broker. Unset custom fields inherit
the global limits. CPU limits must be at least 1 percent with Docker's default
CFS period, and memory must be at least Docker's 6 MiB minimum. These numeric
minimums do not guarantee enough resources for the selected services to start.
Reservations stay within the selected caps; invalid or overflowing values are
rejected before deployment.
Starting or restarting HiFi also requires Docker to confirm active CPU, memory
and PID cgroup controls. Missing or unverified controls produce `QP-RES-005`;
accepted Docker settings alone are not proof that the kernel enforces them.

`environment=standalone` or `environment=` restores the standalone environment.
Unknown environment/image-source values and unsupported HiFi setting names are
rejected by the CLI, API and configuration loader/saver. No arbitrary image URL
or extra routing destination can be supplied through these choices.

The generated wiring is:

| Component | Networks and exposure | State |
|---|---|---|
| `ssh-proxy` | Public ingress plus each private cell; listens only on ingress | Trusted broker metadata; no plaintext SSH or Docker access |
| `ssh-backend-N` | Only `ssh-backend-N_net`; no host port | App filesystem/accounts and connection-local changes |
| `ssh-backend-N-db` | Same cell only, organization mode; no host port | Ephemeral PostgreSQL data |
| `ssh-backend-N-backup` | Same cell only, organization mode; no host port | Backup filesystem/accounts and connection-local changes |

Do not replace the generated networks/guard with a shared unrestricted bridge.
A Docker `internal` flag or valid Compose file alone does not prove effective
host, peer and external isolation. Verify the guard and runtime reachability on
the deployment host. The design follows the supporting-isolation principle in
[NIST SP800-53 Rev5 SC-26](https://doi.org/10.6028/NIST.SP.800-53r5), together with
controlled interfaces and deny-by-default communication; NIST does not prescribe
this specific topology or certify QPot's implementation.

### Backend reset (ephemerality)

A lease lasts for one ingress SSH TCP connection. Multiple channels on the same
connection share state; a separate connection does not inherit it. The entire
cell is recreated after the connection ends, including its database and backup
in organization mode. The work is split so the attacker-facing broker still
holds no Docker privilege. A starting or restarted broker begins with its slots
quarantined and requests a trusted reset before its first lease:

1. The broker logs each finished session (`ssh_proxy_session`, or
   `ssh_proxy_backend_error`) with the backend id to its session log.
2. The trusted host-side control plane (`qpot up` in the foreground, or the
   background `qpot serve` that `qpot up -d` starts) follows that log and runs
   stop, host-only recording archival and fresh Docker recreation for exactly
   that configured cell. In organization mode
   the app, database and backup are one reset boundary. Only names from the
   instance's configured pool are acted on, and Docker is invoked without a
   shell. Startup also resets the configured cells.
3. After each successful recreation the control plane increments that
   backend's counter in `honeypots/ssh-proxy/generations/<backend>`, which is
   mounted **read-only** into the broker and unreachable from any backend.
4. The broker's `RecycleReset` hook keeps the backend out of rotation until it
   has *seen* the recreation: the app answers with an OpenSSH banner,
   all required cell peers are healthy, **and** its generation counter has
   moved past the value it had when the connection started. The counter is what
   makes this trustworthy: root on a backend can make sshd disappear and come back (e.g. `kill 1` with a
   restart policy), but cannot make the host record a recreation. If a real
   recreation is not observed in time (no control plane running, docker
   failing) the backend is quarantined - never reused dirty - and rejoins the
   pool after a later recreation is observed.

Consequences: with the control plane stopped, each backend serves one session
and is then held back (fail closed). A backend is unavailable for a few seconds
after each connection, and an organization cell needs its database/backup ready
too. Raise `backends` (honeypot `custom_config`) for expected concurrency while
accounting for the extra containers. The shared host keys are generated by
`qpot` on the host and mounted read-only, so root on a backend cannot replace
the pool's key.

---

## 6. Capture & analytics

The TCP broker records connection metadata; genuine OpenSSH and the session
recorder collect evidence after decryption. OpenSSH does not log plaintext
passwords.

| Evidence | Logical collector location | Analytics |
|---|---|---|
| Broker connection, rejection and reset requests | `honeypots/ssh-proxy/logs/broker/sessions.json` | Original TCP source, opaque byte counts, reason, cell, lease ID and generation |
| Command start and finish | `honeypots/ssh-proxy/logs/cells/<service>/current/uid-<uid>/*.json` | `ssh-proxy.command.start` and `ssh-proxy.command.finish`, command/input preview, source and capture metadata |
| Binary stdin/stdout/stderr and PTY timing | Beside each command JSON record: `.in`, `.out`, `.err`, `.timing` | Retained files; output text is not copied into credential-watched metadata |
| OpenSSH authentication diagnostics | `<service>/current/sshd.log` within the cells log tree | Retained text; not parsed into authentication events |
| PostgreSQL JSON statement and connection logs | `<database-service>/current/*.json` within the cells log tree | Database role, actual internal client address, query preview and PostgreSQL session ID |

The broker writes a separate, read-only connection context into each cell before
forwarding its first byte. App and backup command events retain the original TCP
source, outer `session_id`, lease `generation`, and per-command `capture_id`.
`peer_ip`/`peer_port` identify the actual SSH hop. Missing or malformed context is
reported as `peer-only` or `context-unavailable`; it is not presented as trusted
original-source attribution. These files expose only that cell's context.

Database events retain their actual internal client and `pg_session_id`.
Correlate them with the cell, observed timestamp and command evidence; delayed
SQL logs are never attributed using a newer visitor's current connection file.

A command-start record is synced before the child starts. Its matching finish
record carries the real exit code, including zero. Abrupt termination can leave
a start without a finish. Non-interactive exec records the command and binary
stdin, stdout, and stderr, including raw inbound SFTP requests and file bodies.
Its cancellable input pump allows completed commands to return while the client
still has stdin open. Interactive PTYs retain input/output and script timing;
the input preview is not a parsed shell-command audit. Stream capture has a
shared 8 MiB limit per command and reports truncation without truncating the
actual SSH byte stream. Per-user admission checks limit retained files/bytes;
concurrent commands and arbitrary guest files still require host disk quotas.

The genuine SFTP subsystem retains both protocol directions as binary streams,
subject to the shared capture limit. These streams are evidence, rather than a
separate extracted-file archive. Files left only in a guest's writable layer
disappear when that cell resets. Configured accounts and the default for new
accounts use the recorder as their login shell, so writable shell startup files
execute after recording starts. Authorized-key command restrictions retain
OpenSSH's normal behavior. Guests can alter capture files owned by their account;
genuine guest root can also replace shells and the in-guest recorder. Independent
broker metadata and host-only archives have separate trust boundaries.

Before a cell is reused, the trusted recycler stops all members, moves their
recordings to host-only `archive-g<generation>-<random>/logs/` directories, and
creates empty current directories. Only a successful fresh recreation and health
check advances the generation. Operator recreation uses the same discard and
archive boundary. The next guest mounts only its empty current directory; the
collector reads both current and archived JSON. Existing age/size retention and
archive cleanup apply under the logical `ssh-proxy` log tree. A closed archive is
removed only after its JSON logs have complete, unambiguous acknowledged native
source checkpoints. Missing checkpoints, unsupported file objects, fingerprint
collisions, or incomplete bounded inventories retain the entire archive,
including its binary captures. Cleanup reports that it retained evidence;
configure host disk quotas and monitor remaining space. Closed-header selection
shares a bounded scan fairly across finite cells and reuses unused work budget;
unacknowledged headers do not consume deletion work. Where native hard-link
counts cannot be verified, including Windows, nonempty archive inventory uses
the isolated helper. If that helper is unavailable, evidence is retained;
native empty-directory cleanup remains available.

Vector's file checkpoints persist in the host-only `collector/` directory inside
the instance data directory,
mounted only into the collector at `/var/lib/vector`. Keep this directory when
recreating or upgrading the collector and when restoring its retained logs.
Removing checkpoints makes retained JSON start from the beginning again and can
insert duplicate historical events. Log retention does not remove these cursors.

Guest root can interfere with guest-side recording or replace its login shell
and recorder. It cannot alter the independent broker records or the host-only archived
recordings through its guest mount. This is useful evidence, not a tamper-proof
command audit. Shared application and separate backup host keys remain protected
in the persistent runtime store described below.

### Persistent runtime storage and upgrades

The canonical host sources of guest bind mounts use a persistent private store,
so genuine Linux mount metadata does not expose QPot-generated instance or
honeypot directory names. Public root IDs are derived separately from the
private per-instance namespace used to name cells; the visible root ID cannot
be used as a key for a service-name dictionary check. Keep that namespace in
private control metadata and the trusted broker. No `/proc` contents are fabricated. Container/runtime
artifacts and operator-selected home or data directory names can still be
observable; this is not a claim that containers cannot be identified.

Before first startup, QPot plans a store under
`$XDG_DATA_HOME/session-store/<opaque-instance-id>/`, or
`$HOME/.local/share/session-store/<opaque-instance-id>/` when XDG_DATA_HOME is
unset. XDG_DATA_HOME must be absolute. The private
`<instance-data>/.runtime-store.json` records the exact canonical `root`; its
matching `.owner.json` belongs to that same instance. The root and ownership
records must remain private and owned by the operating account. Future changes
to HOME, XDG_DATA_HOME or the QPot ID do not relocate an existing store.
Rendering or rejecting configuration does not reserve a store.

The ready-store deployment opts its broker into
`QPOT_SSHPROXY_HOST_READABLE_LOG=1`. New broker metadata uses `0644` so the
trusted host recycler can read a file written by the broker's different
container UID. The canonical host store remains private `0700`, and neither its
broker metadata nor the private namespace is mounted into attacker-facing
cells. Private guest capture files keep their existing protection. On Windows,
keep the store in an ACL-private user directory; POSIX mode bits do not enforce
Windows ACLs. An already readable file, such as a Desktop-shared `0777` file,
keeps its mode; an existing broker-owned `0640` file is widened through its
verified open descriptor without truncation or changing its inode. Standalone
custom broker deployments keep `0640` unless the trusted operator explicitly
opts in with a private host parent.

If broker metadata cannot be read, the host reports `QP-INST-014` once for that
failure episode and resumes after a successful read. Missing files before
broker startup are expected. Failed reads consume no cursor bytes or new reset
authority; already authorized full-cell resets can finish normally. Keep the
log and generation counters. Recreate with matching updated images and
regenerated private-store wiring so the broker can upgrade its existing log,
or repair custom reader access. Do not delete, truncate, or forge metadata to
make a cell available.

Under that recorded root, `records/logs/cells/<opaque-cell-id>/` holds each
cell's `current/` and closed archives; `records/logs/broker/` holds independent
broker metadata. `identities/` holds stable host keys, `contexts/` holds opaque
trusted per-cell connection contexts, and `bootstrap/` holds generated database
initialization. The collector receives read-only log mounts with the logical
service names in the table above, never the identity or context parents. A
new guest receives only its own fresh current directory and read-only identity
and context leaves. Service IDs and source event names in analytics are stable.

The first upgrade stops the previous finite SSH layout while holding the
lifecycle lock, then atomically renames existing keys, contexts, seeds, current
logs and archives. File bytes, ownership, modes and inode identities are
preserved. An interrupted upgrade retains its chosen location and resumes;
conflicting source/destination data, changed ownership or symlinks fail closed
with `QP-INST-011`. Cross-filesystem migration is deliberately refused. Keep the
instance stopped, back up both roots, and complete an offline move into the exact
pending destinations while preserving ownership, modes, hard links and symbolic
links as links. Verify the backup and migrated evidence before removing the old
source; do not dereference guest-created links, regenerate keys, merge conflicting
archives, or bypass the location records. Retry startup only after resolving the
reported paths.

Back up **both** the instance data directory and the exact root recorded in
`.runtime-store.json`, including both ownership records, host keys, current and
archived evidence. Keep `collector/` and its source checkpoints with those logs.
Restore to the same canonical paths with the same operating account, owners and
private permissions while stopped. Restoring only `~/.qpot` loses the separate
runtime data. Legacy `collector-state/` is atomically adopted as `collector/`;
conflicting checkpoint directories fail with `QP-INST-012` rather than being
merged or reseeded. Missing native-source checkpoints read retained records from
the beginning, preferring possible duplicates to silent loss.

Instance removal stops the owned deployment under the same lifecycle lock before
removing its verified runtime root. If stopping or ownership verification fails,
removal retains the data. A configuration whose data_path points outside its
normal instance directory retains both that custom data and its runtime store;
remove them separately only after verifying ownership and stopping all users.

---

## 7. Honest limitations

* **Real RCE.** The backend is genuinely interactive. It is only as safe as the
  isolation around it — run it under gVisor/Kata with the egress lock (the egress
  lock is applied automatically; the gVisor/Kata runtime is applied when QPot
  detects it on the host). Do not deploy HiFi mode on a host without a stronger
  isolation runtime for the backends if you cannot accept container-escape risk.
* **Images must be published/built.** `qpot honeypot enable ssh-proxy` renders the
  stack referencing `ghcr.io/yurillab/qpot-ssh-proxy` and `…/qpot-ssh-backend`;
  build/push them from `docker/ssh-proxy` and `docker/ssh-backend` (or retag
  locally) before `qpot up`.
* **Backend OS realism.** A real Debian box is not a perfect replica of the
  specific server you are impersonating; align `BACKEND_USERS`, hostname, and
  packages with the QPot persona/identity advertised for the sensor.
* **Kernel / `uname` consistency.** Containers share the host kernel, so a
  plain-container backend's `uname -r` is the *host* kernel — which can disagree
  with the Debian `/etc/os-release` and is itself a (weak) tell. The packaged
  honeyfs deception (`/proc/version` etc.) is **not** applied to the HiFi backend:
  unlike Cowrie's emulated shell, the backend runs *real* bash on a *real* kernel,
  so `uname`/`/proc` reflect reality. Use **Kata** for a consistent guest kernel,
  or run on a host kernel plausible for the persona. (See §4 item 2 for the
  gVisor-detectability trade-off — gVisor closes the SSH tell but adds a
  sandbox tell.)
* **`script(1)` recording** captures the PTY; for non-interactive `ssh host cmd`
  invocations the bounded command line is logged and all three streams are
  captured as separate binary files under a shared capture budget.

---

## 8. Testing & fuzzing

`internal/proxy` ships unit tests, race tests, and fuzz targets:

* **Transparency** — `FuzzSpliceTransparency` proves arbitrary byte payloads
  (incl. NULs, high bytes, >buffer sizes) round-trip verbatim through the splice
  with no panic — the core “it’s a faithful L4 pipe” guarantee.
* **Admission control** — `limiter` tests cover global/per-IP caps, the
  token-bucket rate limit (injected clock), idempotent release, and idle
  eviction; a concurrent test runs under `-race`.
* **Pool** — lease/release, reset-hook execution, quarantine-on-failed-reset,
  malformed/duplicate rejection, and a concurrent race exercise.
* **Teardown** — idle-timeout, normal-close attribution (regression guard),
  pool-exhaustion rejection, backend-dial-error, and graceful drain.
* **Resource-leak audit** — `TestBrokerReleasesResources` runs many sequential
  sessions (incl. a dial failure) and asserts the pool returns every backend and
  the limiter's global counter returns to zero (no lease/admission leak).
* **Config/encoding** — `FuzzParseBackends`, `FuzzSplitHostPort`,
  `FuzzEventJSON` (exactly one valid JSON line for arbitrary field values).

The compose **wiring** (package `internal/instance`) is fuzzed too:

* `FuzzSSHProxyRenderInvariants` — renders the full stack under fuzzed
  seed / fake-hostname / backend-count, parses the YAML, and asserts the
  security-critical invariants ALWAYS hold: valid YAML, the backend network is
  `internal: true`, and **no backend ever publishes a host port** (real RCE is
  never exposed) — even for a hostile fake hostname that tries to inject a
  `ports:` line (neutralized by `hostnameSafe`).
* `FuzzSSHUsersCSV` — `BACKEND_USERS` always parses to safe `user:pass` pairs
  for arbitrary persona input (no env/`chpasswd` injection).
* `FuzzSSHBackendCSVRoundTrip` — the renderer's `BACKENDS` string always parses
  with the broker's own `proxy.ParseBackends` (the two formats can't drift).

Run them:

```sh
go test -race ./internal/proxy/ ./internal/instance/
go test ./internal/proxy/   -run '^$' -fuzz '^FuzzSpliceTransparency$'        -fuzztime 30s
go test ./internal/instance/ -run '^$' -fuzz '^FuzzSSHProxyRenderInvariants$' -fuzztime 30s
```

### End-to-end live verification

The full path was verified live by building the backend image, running the
broker (`cmd/qpot-sshproxy`) in front of a real-OpenSSH backend, and probing
through it:

* **The handshake terminates at real OpenSSH.** The server `KEXINIT` read
  *through the broker* is byte-identical to the backend's direct `KEXINIT` — same
  banner (`SSH-2.0-OpenSSH_9.2p1 Debian-…`), same modern OpenSSH algorithm lists
  (`sntrup761x25519-sha512`, `chacha20-poly1305@openssh.com`, ETM/umac MACs,
  `rsa-sha2-512` host keys — none of which Cowrie's conch can emit), and the
  **same `hasshServer`**. The splice is perfectly transparent and the attacker
  sees a genuine OpenSSH fingerprint, not an emulator's. (Contrast: Cowrie still
  emits a conch `KEXINIT` / different HASSH.)
* **A real interactive shell.** A genuine SSH client logs in and runs commands
  (`uname -a`, `cat /etc/os-release`, `id`) against real bash on a real Debian 12
  backend.
* **Real authentication.** The persona credentials are accepted and wrong
  passwords / non-existent users are rejected **by the backend `sshd`** — the
  broker performs no auth (it only splices bytes).
* **Capture + admission control.** The broker writes one NDJSON session record
  per connection (`src_ip`, `bytes_in/out`, `duration_ms`, `reason`) and cleanly
  emits `no_backend_available` when the finite pool is exhausted.

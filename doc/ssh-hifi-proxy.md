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

QPot’s config-level deception (per-instance identity, credential personas,
consistent fake filesystem, realistic `/proc`, timeouts — see the README’s
*Deception & Anti-Fingerprinting* section) raises the bar against keyword/Shodan/
script detection, but it **cannot** defeat this class: the tell is in the
transport library, not the content.

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
disposable **real-OpenSSH backend containers**:

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

Capture is done out-of-band, where we legitimately control it: **inside the
backend** (sshd `VERBOSE` auth logging + full PTY session recording via
`script(1)`), plus the broker’s own per-connection metadata (source, byte
counts, duration, teardown reason). The broker never needs to see plaintext.

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
* `limiter` (`limiter.go`) — per-IP token-bucket rate limit, per-IP concurrency
  cap, and global concurrency cap, with idle-bucket eviction (bounded memory).
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
| `QPOT_SSHPROXY_IDLE` | `15m` | Idle-session timeout |
| `QPOT_SSHPROXY_MAXSESSION` | `2h` | Absolute session cap |
| `QPOT_SSHPROXY_RATE_IP` | `5` | New conns/sec per IP (token bucket) |
| `QPOT_SSHPROXY_BURST_IP` | `10` | Rate burst per IP |
| `QPOT_SSHPROXY_CONC_IP` | `3` | Max concurrent sessions per IP |
| `QPOT_SSHPROXY_CONC` | `128` | Max concurrent sessions globally |

---

## 4. Security model

The broker is **safe by construction** (opaque bytes, no parser, no privilege, no
SSRF). The genuinely dangerous component is the **backend: real code execution**.
A high-interaction honeypot that an attacker can escape, or use to attack third
parties, is a liability — so the backend is wrapped in defense-in-depth:

1. **Egress lockdown (non-negotiable).** Backends sit on a docker network marked
   `internal: true`, which removes the default gateway: **no outbound
   connectivity at all**. A real shell on the backend cannot scan, pivot, mine,
   join a botnet, or DDoS. This is the single most important control. As
   belt-and-braces, the backend `sshd_config` also disables every forwarding/
   tunnelling primitive (`AllowTcpForwarding no`, `PermitTunnel no`, …).
2. **Stronger isolation runtime.** Run backends under gVisor (`runsc`) or Kata
   when available (QPot already detects these). Real RCE behind a syscall
   sandbox, not just namespaces.
3. **No docker access on the attacker path.** The broker and backend containers
   never receive the docker socket or host mounts. Backend reset is performed by
   an **external** supervisor, never by the attacker-facing containers.
4. **Resource bounds.** Per-container CPU/memory/PID limits; broker admission
   control (rate + concurrency caps) bounds load on the finite, expensive pool.
5. **Ephemerality.** Backends are reset/rolled back between sessions
   (`ResetFunc` / external `docker restart` or snapshot rollback), so no attacker
   inherits another’s changes (planted creds, persistence, dropped tooling).
6. **No privilege bridge.** The QPot ID (management-API credential) is never
   mounted into honeypot containers, HiFi included.

### 4.1 Security audit — findings and mitigations

| # | Risk | Mitigation (in code / config) |
|---|---|---|
| 1 | **SSRF** — broker tricked into dialing arbitrary hosts | Backends come only from `ParseBackends` of operator config; attacker input is never used as a dial target. |
| 2 | **Protocol-parser exploit** in the broker | None exists — the broker speaks no SSH; it copies opaque bytes. |
| 3 | **Connection-flood DoS** exhausting the backend pool | `limiter`: per-IP rate + per-IP and global concurrency caps; `Pool.Lease` is non-blocking and fails fast (no unbounded queue). |
| 4 | **Memory exhaustion** via churn of unique source IPs | `limiter.sweep` evicts idle per-IP buckets (bounded map). |
| 5 | **Slowloris / abandoned sessions** pinning backends | Per-direction **idle deadline** + absolute **MaxSession** deadline. |
| 6 | **Goroutine/fd leaks** | Every session’s goroutines exit on teardown; `Serve` drains via `WaitGroup`; conns closed in `defer`. Verified under `-race`. |
| 7 | **Reason misattribution** (normal close mislabeled idle) | Teardown uses `Close` (→ `net.ErrClosed`, not a timeout) so only genuine idle reads surface as timeouts. Regression-tested. |
| 8 | **TCP half-close** truncating a direction | `halfCloseWrite` propagates FIN to the peer and keeps the other direction draining. Fuzz-verified for transparency. |
| 9 | **Log injection** via attacker-controlled fields | Events carry only trusted fields, encoded with `encoding/json`; fuzz-verified to emit exactly one valid JSON line. |
| 10 | **Panic in one session** taking down the listener | Per-connection `recover`. |
| 11 | **Backend used as a pivot / outbound attack platform** | `internal: true` egress lock **and** sshd forwarding disabled. |
| 12 | **Backend escape** | gVisor/Kata runtime, dropped/limited caps, resource limits, no host mounts. |
| 13 | **Cross-attacker contamination / persistence** | Per-session reset; failed resets quarantine the backend. |
| 14 | **Privileged broker** (docker socket) | Broker is distroless nonroot with no docker access; resets are external. |
| 15 | **Host-key rotation tell** | Backend host keys generated once and persisted (mount `/etc/ssh`). |

---

## 5. Deployment

**Enabling HiFi mode is one command:**

```sh
qpot honeypot enable ssh-proxy        # then: qpot up
```

QPot's compose generator emits the whole two-service stack automatically: the
broker (publishing the SSH port), the configured number of real-OpenSSH backends
(`custom_config["backends"]`, default 2), the egress-locked `ssh-proxy_backend`
network, the broker's `QPOT_SSHPROXY_BACKENDS` wiring, the per-backend data dirs
(persisted host keys + logs), and the hardening below. The manager starts/stops
the backends together with the broker. `BACKEND_USERS` is derived from the same
credential-persona system as the rest of QPot, so the HiFi box accepts the same
realistic weak credentials the sensor advertises.

The equivalent compose it renders (shown for reference / manual tuning):

```yaml
networks:
  # EGRESS-LOCKED: internal:true removes the default gateway, so backends have
  # NO outbound connectivity. This is the critical control for a real-RCE box.
  ssh_backend_net:
    internal: true

services:
  ssh-proxy:                         # attacker-facing broker (the ONLY published port)
    image: ghcr.io/yurillab/qpot-ssh-proxy:latest
    restart: unless-stopped
    ports:
      - "22:2222"                    # public SSH -> broker
    networks: [ssh_backend_net]
    environment:
      QPOT_SSHPROXY_BACKENDS: "be1=ssh-backend-1:22,be2=ssh-backend-2:22"
      QPOT_SSHPROXY_NAME: "ssh-proxy"
    volumes:
      - ./data/honeypots/ssh-proxy/logs:/var/log/ssh-proxy
    read_only: true
    security_opt: ["no-new-privileges:true"]
    cap_drop: ["ALL"]                # broker needs no capabilities
    tmpfs: ["/tmp"]
    deploy:
      resources:
        limits: { cpus: "0.50", memory: 128M, pids: 64 }

  ssh-backend-1: &backend
    image: ghcr.io/yurillab/qpot-ssh-backend:latest
    restart: unless-stopped          # cheap reset cadence; pair with an external roller
    # runtime: runsc                 # gVisor STRONGLY recommended (real RCE)
    networks: [ssh_backend_net]      # internal only -> never published to the host
    environment:
      BACKEND_USERS: "admin:admin,ubuntu:ubuntu,root:root123"
    volumes:
      - ./data/honeypots/ssh-backend-1/etc-ssh:/etc/ssh        # persist host keys
      - ./data/honeypots/ssh-backend-1/logs:/var/log/ssh-backend
    security_opt: ["no-new-privileges:true"]
    # sshd privilege separation needs a small, specific capability set; drop the
    # rest. (Do NOT cap_drop ALL — sshd auth would break.)
    cap_drop: ["ALL"]
    cap_add: ["SETUID", "SETGID", "CHOWN", "DAC_OVERRIDE", "SYS_CHROOT", "AUDIT_WRITE", "FOWNER", "KILL", "SETPCAP"]
    deploy:
      resources:
        limits: { cpus: "1.00", memory: 512M, pids: 256 }

  ssh-backend-2:
    <<: *backend
    environment:
      BACKEND_USERS: "admin:admin,ubuntu:ubuntu,root:root123"
    volumes:
      - ./data/honeypots/ssh-backend-2/etc-ssh:/etc/ssh
      - ./data/honeypots/ssh-backend-2/logs:/var/log/ssh-backend
```

Key invariants the recipe enforces:

* **Only `ssh-proxy` publishes a host port.** Backends are reachable solely from
  the broker over the internal network — never from the internet directly.
* **`ssh_backend_net` is `internal: true`** — the egress lock.
* The broker runs `cap_drop: ALL`, `read_only`, `no-new-privileges`; the backend
  gets exactly the caps sshd privilege-separation needs and nothing more.

### Backend reset (ephemerality)

The broker must not hold docker privileges, so it does not reset backends
itself. Use one of:

* an external roller (host cron / sidecar with docker access):
  `docker restart <instance>_ssh-backend-1 …` on a schedule or after idle, or
* snapshot rollback (e.g. a read-only image + tmpfs overlay discarded on
  restart), or
* short `MaxSession` + `restart: unless-stopped` so backends recycle frequently.

---

## 6. Capture & analytics

Capture is split deliberately, because **the broker never sees plaintext** — it
forwards encrypted bytes. Anything inside the SSH session (credentials tried,
commands run) is visible only at the backend, post-decryption.

* **Broker** → `honeypots/ssh-proxy/logs/sessions.json` (NDJSON): one record per
  session/rejection with `src_ip`, `src_port`, `backend`, `bytes_in`,
  `bytes_out`, `duration_ms`, `reason`, plus `ssh_proxy_rejected` records
  (rate-limit/cap/pool-exhaustion) as an abuse signal. **This is ingested by the
  existing Vector → ClickHouse pipeline** (the honeypot file source matches
  `…/ssh-proxy/logs/**/*.json`), so connection-level telemetry and the attacker
  source set land in analytics automatically.
* **Backend** → `honeypots/ssh-backend/<svc>/logs/`: `sshd` `VERBOSE` auth log
  (every credential attempt + offered key fingerprints — this is where the
  **actual usernames/passwords** are captured, since the broker can't see them),
  **full PTY recordings** (`*.ttyrec`), and one-shot command logs (`*.cmd`), plus
  persisted host keys under `…/<svc>/etc-ssh/`.

  These backend artefacts are bind-mounted to disk for operator review and
  forensics. Structured ingestion of the backend `sshd` auth log into ClickHouse
  (parsing the credential attempts into the events schema) is a **follow-up**:
  the text/`ttyrec` formats are not JSON, so they are captured but not yet parsed
  into the pipeline. The broker's structured session telemetry already flows
  end-to-end.

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
* **`script(1)` recording** captures the PTY; for non-interactive `ssh host cmd`
  invocations the command line is logged verbatim and output is captured via
  sshd, but not as a ttyrec stream.

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
* **Config/encoding** — `FuzzParseBackends`, `FuzzSplitHostPort`,
  `FuzzEventJSON` (exactly one valid JSON line for arbitrary field values).

Run them:

```sh
go test -race ./internal/proxy/
go test ./internal/proxy/ -run '^$' -fuzz '^FuzzSpliceTransparency$' -fuzztime 30s
```

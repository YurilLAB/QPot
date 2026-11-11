# Reliability: what breaks, what is lost, how long recovery takes

QPot's promise about evidence is narrow and testable: **what a honeypot
logged reaches the database once, and intelligence counts it once**, whatever
else fails in between. This page says how that is tested, what the last run
measured, and where the promise ends.

- [The failure soak](#the-failure-soak)
- [The faults](#the-faults)
- [How each number is measured](#how-each-number-is-measured)
- [Results of the last recorded run](#results-of-the-last-recorded-run)
- [What the soak found and what was changed](#what-the-soak-found-and-what-was-changed)
- [Upgrade and rollback rehearsal](#upgrade-and-rollback-rehearsal)
- [Where the promise ends](#where-the-promise-ends)

## The failure soak

`internal/soak` is a test that runs only when asked. It creates an instance
with the `qpot` program you give it, on real Docker, with Cowrie as the
honeypot and ClickHouse as the database. Then, for as long as you say:

- it keeps up steady traffic: several SSH connections a second, each with a
  client version string that carries a serial number, and every fortieth one
  a real login that runs three commands;
- it breaks one part at a time, holds the fault, clears it, and waits for the
  instance to recover before the quiet gap that precedes the next fault;
- at the end it compares, connection by connection, what the honeypot
  accepted with what the database holds.

```bash
go build -o /tmp/qpot ./cmd/qpot
QPOT_SOAK=1 QPOT_SOAK_BIN=/tmp/qpot QPOT_SOAK_DURATION=3h \
    go test ./internal/soak -run TestSoak -timeout 0 -v
```

| Setting | Default | Meaning |
|---|---|---|
| `QPOT_SOAK_BIN` | none, required | The `qpot` program to test |
| `QPOT_SOAK_INSTANCE` | `soak` | Name of the instance it creates and removes; must not exist |
| `QPOT_SOAK_DURATION` | `20m` | How long faults are injected |
| `QPOT_SOAK_RATE` | `4` | Connections per second |
| `QPOT_SOAK_GAP` | `3m` | Quiet time between faults |
| `QPOT_SOAK_HOLD` | `2m` | How long a fault lasts |
| `QPOT_SOAK_FAULTS` | all | Comma-separated fault names, in order |
| `QPOT_SOAK_FILL_DIR` | unset | A small filesystem that holds the instance (point `HOME` into it); enables `disk-full` |
| `QPOT_SOAK_SANDBOX` | the default | `security.sandbox_mode` for the instance |
| `QPOT_SOAK_REPORT` | a temporary folder | Where the JSON and Markdown reports go |
| `QPOT_SOAK_KEEP` | unset | `1` leaves the instance in place afterwards |

Before the first fault the test checks that nothing is lost or duplicated
with nothing broken. A run that fails there has measured the harness, not
QPot, and stops.

The test fails if any connection is stored twice, if intelligence counts
anything twice, if the instance does not recover from a fault within 15
minutes, or if a fault that leaves the honeypot running loses an accepted
connection.

## The faults

| Name | What is done |
|---|---|
| `database-stop` | The database container is stopped cleanly, later started |
| `database-kill` | The database is killed with SIGKILL mid-write, later started |
| `database-freeze` | The database is frozen (`docker pause`): connections hang instead of failing |
| `collector-kill` | The collector is killed with SIGKILL, later started |
| `collector-recreate` | The collector's container is removed and created again |
| `network-partition` | The collector is disconnected from the database's network while both keep running |
| `honeypot-kill` | The honeypot is killed with SIGKILL; Docker's restart policy brings it back |
| `honeypot-restart` | The honeypot is restarted through `qpot docker restart` |
| `control-plane-kill` | `qpot serve` (web UI, intelligence worker) is killed with SIGKILL, later started |
| `worker-takeover` | `qpot serve` is frozen (SIGSTOP) for longer than its database lease lasts. A second intelligence worker, as another host would run, takes the lease. The first is resumed while the second still holds it, and must stand down. |
| `disk-full` | The filesystem holding the instance is filled to the last byte, later freed |
| `traffic-burst` | Ten times the normal connection rate, nothing broken |

## How each number is measured

- **Accepted.** A connection counts as accepted when the honeypot sent its
  SSH banner and took the client's version line. Connections made while the
  honeypot itself is down are counted as **refused**, not lost: no honeypot
  saw them.
- **Lost.** Accepted, and not in the database when the run ends (after a
  wait for the backlog to drain). Each connection has its own serial number,
  so this is a set difference, not a count comparison.
- **Stored twice.** Database rows beyond one per serial number.
- **Collection delay.** The database row's timestamp, which the collector
  sets when it reads the honeypot's line, minus the time the connection was
  made. It shows how long a line waited in the honeypot's log, for example
  while the collector was down. It does not include the wait for a database
  that is away: that wait ends with the fault's recovery time.
- **Recovery time.** From the moment the fault is cleared until all of this
  is true: the backlog from before that moment has arrived (or has stopped
  arriving for 20 seconds), a connection made after it is in the database,
  the API answers, and the intelligence worker reports `running`. The time
  recorded is when the last of these became true.
- **Intelligence counted twice.** Each login session names a domain no other
  session names. The worker must record that domain as an indicator seen
  exactly once; a count above one, or a second row, means a batch was
  applied twice across a crash, a replay or a takeover.

Connections reach the honeypot through Docker's port proxy, so every one
has the Docker bridge's gateway as its source. For the soak that means one
"attacker". It does not affect the counts above, but the run says nothing
about how QPot behaves with many thousands of distinct sources.

## Results of the last recorded run

2026-11-11, Docker Engine 26.1.5 on Linux (WSL2, 12 cores, 15 GiB),
`sandbox_mode: none`, ClickHouse, 4 connections a second, faults held 30
seconds with 40 seconds between them. This was a 10-minute run that reached
five of the twelve faults; a run of several hours over all of them is the
release requirement and replaces this table when it is recorded.

| Connections | Count |
|---|---|
| sent | 2,322 |
| accepted by the honeypot | 2,081 |
| refused (honeypot down) | 241 |
| stored, distinct | 2,081 |
| **lost** | **0** |
| **stored twice** | **0** |

Collection delay: median 0.2 s, 99th percentile 31.5 s, longest 36.5 s (the
collector being down).

| Fault | Held | Recovery | Accepted during | Refused during | Lost | Longest collection delay |
|---|---|---|---|---|---|---|
| database-stop | 42 s | 34 s | 317 | 0 | 0 | 9 s |
| collector-kill | 31 s | 6 s | 161 | 0 | 0 | 34 s |
| control-plane-kill | 32 s | 4 s | 155 | 0 | 0 | 0 s |
| worker-takeover (control plane frozen 95 s) | 95 s | 4 s | 409 | 0 | 0 | 1 s |
| honeypot-kill | 86 s | 6 s | 139 | 241 | 0 | 9 s |

| Intelligence | Count |
|---|---|
| login sessions completed | 52 of 58 |
| indicators expected (one unique domain per session) | 52 |
| found | 52 |
| missing | 0 |
| **counted more than once** | **0** |
| `nmap` commands stored | 52 of 52 |
| duplicate session rows | 0 |
| events still unclassified at the end | 0 |

In this run the second worker of `worker-takeover` did not take the lease
(a fault in the harness, since fixed: it shared the frozen worker's local
lock), so the row measures a control plane frozen past its lease and
resumed, not a takeover by another host.

The six logins that did not complete were refused by Cowrie's own login
policy, which lets a source in only after a random number of tries.

## What the soak found and what was changed

Two defects, both found by the first short runs and both fixed before the
run above.

**A database outage longer than 30 seconds stopped intelligence for good.**
The intelligence worker holds a database lease that lasts 30 seconds. When
the database was away for longer, the worker lost the lease and stopped, by
design: a worker that lost its lease must never write again. Nothing started
another. The web UI kept working and events kept arriving, but nothing was
classified until someone restarted the control plane, and the only sign was
`worker_status: stopped` in the API. Recovery from `database-stop` was
never. Now the control plane starts a new worker when one stops: it must
take a new lease, which the database refuses while another owner's is
alive, and it begins from the durable checkpoint. Recovery from the same
fault is 34 seconds. `TestWorkerIsReplacedAfterLosingItsLease` covers it.

**The database ran out of memory headroom.** The database container had the
limits meant for one honeypot: 512 MiB and half a CPU. Since swap is capped
at the memory limit, ClickHouse with its embedded Keeper sat at that limit
within minutes of light load. One `clickhouse-client` started inside the
container (`docker exec`, as an operator would to run a query) pushed it
into page reclaim that did not end: 18 million page-cache refaults in five
minutes, four CPU periods in five throttled, health checks timing out,
queries hanging. Measured on the pinned image:

| Limit | Server configuration | Memory in use under load | Page refaults | Slowest query |
|---|---|---|---|---|
| 512 MiB, 0.5 CPU | default | 485 of 512 MiB | 371,742 | 0.6 s |
| 512 MiB, 0.5 CPU | QPot's | 479 of 512 MiB | 72,045 | 1.2 s |
| 1 GiB, 1 CPU | default | 381 MiB | 11,048 | 0.5 s |
| 1 GiB, 1 CPU | QPot's | 249 MiB | 0 | 0.8 s |

The database now gets at least 1 GiB and one CPU whatever the honeypot
limit is, and a server configuration that removes ClickHouse's internal
diagnostic tables (written every few seconds, never trimmed, and the source
of most idle CPU and disk writes) and sizes its caches and merge pools for
the container. `TestDatabaseHasItsOwnLimits` and
`TestClickHouseLimitsConfig` cover it.

## Upgrade and rollback rehearsal

2026-11-11, same host. An instance was started on the previous commit
(`708ea896`), attacked, stopped and backed up; started on this version and
attacked; then rolled back by restoring the backup under the previous
program, and attacked again. The procedure is the one in
[release.md](release.md#upgrading).

| Stage | Check | Result |
|---|---|---|
| Previous version | 60 connections stored once | 60, 0 duplicates |
| | scanner banners (`SSH-2.0-Nmap-…`) stored | 0 of 5: dropped by the old filter |
| | backup lines carrying the QPot ID | 190 |
| | QPot ID in the collector's and database's environment and in both generated files | yes |
| Upgrade | `qpot up` output, redirected, prints the QPot ID | no |
| | generated files, container environments and mounts carrying the QPot ID | 0 |
| | old backup lines rewritten to the sensor ID, file sizes unchanged | 190 of 190 |
| | connections across the upgrade stored once | 120, 0 duplicates |
| | scanner banners stored and tagged `nmap` | 5 of 5 |
| | collector and database container logs carrying the QPot ID | 0 lines |
| | `qpot doctor` | every containment and credential line `ok` |
| Refusals | no login on `0.0.0.0`: `qpot up` and `qpot serve` | refused with QP-WEB-005, no container started |
| | egress guard off with dionaea enabled: `qpot up` | refused with QP-INST-015, no container started |
| | connections after the refusals and a restart stored once | 150, 0 duplicates |
| Rollback | database after restoring the backup | the 60 connections it held, 0 duplicates |
| | previous version collects again | 90, 0 duplicates |

## Where the promise ends

- **Before the honeypot logs it.** A connection the honeypot never took, or
  took and was killed before writing its log line, is not evidence QPot
  ever had. The soak reports these as refused, or as lost during a
  `honeypot-` fault.
- **A full disk.** With no space left a honeypot cannot write its log, and
  the database and the collector cannot record what they have. What happens
  then is measured by the `disk-full` fault, which the run above did not
  reach.
- **HiFi SSH session capture during a long control-plane outage.** HiFi
  sessions are recorded on each backend's container log and converted by
  the control plane. When the control plane stops, the broker turns new
  visitors away after 30 seconds, but sessions already open continue, and a
  visitor that keeps writing can push its own oldest unconverted records
  out of its backend's bounded log
  ([ssh-hifi-proxy.md](ssh-hifi-proxy.md) states the bound). The soak does
  not drive HiFi sessions yet, so there is no measured figure for how much
  one session can lose this way. That measurement is the next piece of
  work here.
- **The database itself.** QPot keeps one copy. The log backups under
  `backup/logs/` hold every event as JSON and are the second copy; nothing
  restores from them automatically.
- **Many sources.** See the note on Docker's port proxy above.
- **TimescaleDB.** The soak measures a ClickHouse instance.

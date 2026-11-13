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
- [Second round: replays, low disk, restore](#second-round-replays-low-disk-restore)
- [The HiFi capture soak](#the-hifi-capture-soak)
- [Restore rehearsal](#restore-rehearsal)
- [The 1.1.2 release run](#the-112-release-run)
- [The 1.1.3 release run](#the-113-release-run)
- [Upgrade and rollback rehearsal](#upgrade-and-rollback-rehearsal)
- [Third round: a disk that fills at once, long HiFi outages, a large database](#third-round-a-disk-that-fills-at-once-long-hifi-outages-a-large-database)
- [Fourth round: TimescaleDB end to end, and lines written to break what reads them](#fourth-round-timescaledb-end-to-end-and-lines-written-to-break-what-reads-them)
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
minutes, if a fault that leaves the honeypot running loses an accepted
connection, if a second copy of any event is left in the database, if the
database refused any query for lack of memory, or if the honeypot kept
taking connections while the disk was below the guard's floor.

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
| `disk-full` | The filesystem holding the instance is filled to the last byte at once, later freed |
| `disk-low` | The filesystem is filled until less than the disk guard's floor is free, later freed. The guard must close the honeypot before it loses anything |
| `collector-amnesia` | The collector is removed and its checkpoints are deleted, so the new one reads every log from its first line: every event arrives a second time |
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

2026-11-11, 19:41 to 22:46 (3 h 6 min). Docker Engine 26.1.5 on Linux
(WSL2, 12 cores, 15 GiB), `sandbox_mode: none`, ClickHouse, the instance on
a 3 GiB filesystem of its own. 4 connections a second, each fault held for
2 minutes with 3 minutes between faults, all twelve faults three times
over. Commit `e4a39b24`.

| Connections | Count |
|---|---|
| sent | 57,498 |
| accepted by the honeypot | 56,781 |
| refused (honeypot down) | 717 |
| stored, distinct | 56,443 |
| **lost** | **338**, all during `disk-full` |
| **stored twice** | **238**, during `database-freeze` and `disk-full` |

Collection delay: median 0.2 s, 99th percentile 101.6 s, longest 127.7 s
(the collector being down for a two-minute fault).

Per fault, the three rounds side by side:

| Fault | Recovery (s) | Lost | Stored twice |
|---|---|---|---|
| database-stop | 14, 19, 14 | 0 | 0 |
| database-kill | 23, 29, 21 | 0 | 0 |
| database-freeze | 15, 9, 7 | 0 | 40, 41, 40 |
| collector-kill | 6, 6, 6 | 0 | 0 |
| collector-recreate | 6, 6, 15 | 0 | 0 |
| network-partition | 23, 17, 13 | 0 | 0 |
| honeypot-kill | 6, 4, 6 | 0 (239 refused each time) | 0 |
| control-plane-kill | 6, 6, 2 | 0 | 0 |
| worker-takeover | 6, 4, 2 | 0 | 0 |
| disk-full | 6, 4, 21 | 0, 105, 233 | 0, 117, 0 |
| traffic-burst (10 times the rate) | 4, 4, 4 | 0 of 14,476 | 0 |

`honeypot-restart` did not run: the harness called `qpot docker restart`
with a flag that command does not take. The harness is fixed; the fault is
exercised in the run described under "After the fix" below.

| Intelligence | Count |
|---|---|
| login sessions completed | 1,077 of 1,113 |
| indicators expected (one unique domain per session) | 1,077 |
| found | 1,077 |
| missing | 0 |
| counted more than once | 3 |
| `nmap` commands stored | 1,080 for 1,077 sessions |
| duplicate session rows | 0 |
| events still unclassified at the end | 0 |

The three indicators counted twice, and the three extra `nmap` commands,
are the same three sessions: their events were among those stored twice
during a `database-freeze`. The worker counted what the database held. No
worker crash, takeover or replay counted anything twice.

The logins that did not complete were refused by Cowrie's own login policy,
which lets a source in only after a random number of tries.

## What the soak found and what was changed

Four things. The first two were found by the first short runs and fixed
before the run above; the other two were found by that run.

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
fault took 14 to 19 seconds in the long run. `TestWorkerIsReplacedAfterLosingItsLease` covers it.

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

**A frozen database stored batches twice.** In the three-hour run every
`database-freeze` left about 40 connections stored twice, and one
`disk-full` left 117. The collector's insert was in flight when the fault
began; it timed out and was sent again; when the fault ended the database
completed both attempts. Both copies carried the same collection time,
which is how they were told apart from two reads of one line. Three login
sessions were among them, so intelligence counted their indicators twice:
the worker was exact about a database that was not.

The collector now gives every event an ID derived from its log line (a
hash of the file and the line; since the second round also of the line's
place in the file, see below), instead of leaving the database to invent
a random one per row, and the events table remembers its last 1,000 insert
blocks and drops one that arrives again. A retried batch is now the same
block byte for byte, and is stored once. Existing tables get the setting at
start. `TestClickHouseStoresARetriedBatchOnce` and
`TestVectorKeepsScannerEvidenceLive` cover the two halves.

### After the fix

2026-11-11, 23:00 to 23:28, same host, the working tree that became the
commit after `74d0f52b`: the two faults that had produced duplicates, the
database kill, and the restart fault the long run had skipped, twice over.

| Fault | Recovery (s) | Accepted during | Lost | Stored twice |
|---|---|---|---|---|
| database-freeze | 10, 15 | 534, 552 | 0 | 0 |
| disk-full | 29, 20 | 618, 584 | 366, 91 | 0 |
| database-kill | 23, 29 | 588, 615 | 0 | 0 |
| honeypot-restart | 18 | 79 (34 refused) | 0 | 0 |

6,679 connections accepted, none stored twice; 149 of 149 indicators found,
none counted twice.

**A full disk loses what the honeypot cannot write.** The connections lost
during `disk-full` were checked one by one on the kept instance: none of
them is in Cowrie's own log or in the log backup. Cowrie reports
`[Errno 28] No space left on device` from its JSON output and carries on
serving without recording. Everything Cowrie did write was collected: after
the run the collector's checkpoint was at the last byte of the log. So
QPot's pipeline lost nothing, and the honeypot lost anywhere from none to
60% of the connections it took while the disk was full (five episodes: 0,
20%, 40%, 59% and 16%). QPot cannot recover what
was never written. What it does is keep the disk from filling: storage
limits per honeypot and disk cleanup ([disk-cleanup.md](disk-cleanup.md)),
and `qpot doctor` fails below 2 GiB free. The second round added a guard
that closes the honeypots before the disk is full; see below.

## Second round: replays, low disk, restore

2026-11-12, same host, the working tree that became the commits after
`4304894d`. This round went after what the first one left open: lines read
twice, a disk that fills, and a database that has to be rebuilt.

**Two equal log lines had one ID.** The ID was a hash of the file and the
line, so two separate occurrences of the same line in one file were one
event to the database's duplicate check. The ID now also covers the byte
offset the line starts at, which the collector reports for every line it
reads. Reading the same line again gives the same ID; another line with the
same text gives another. `TestVectorEventIdentityLive` runs the real
collector over a file with repeated lines, restarts it, deletes its
checkpoints and rotates the file.

**A line read twice was stored twice.** The duplicate check on insert only
catches the same batch sent again. A collector that lost its checkpoints, or
was killed between reading a line and saving its position, reads lines again
in new batches. The intelligence worker now removes such second copies
before it counts anything: for every unclassified event it asks whether the
same ID is already stored, and deletes the later copy. The first copy and
its classification stay. `collector-amnesia` measures it: the whole log
arrives again while traffic continues.

**The disk guard.** The control plane now checks free space on the data
folder every five seconds. Below `cleanup.min_free_mb` (512 MB by default)
it runs disk cleanup and, if that is not enough, stops the honeypots; with
less than a quarter of that left it stops them first. They start again
above `cleanup.resume_free_mb`. A honeypot that is closed refuses
connections, which a visitor sees; a honeypot that is open on a full disk
takes them and records nothing, which nobody sees.
[disk-cleanup.md](disk-cleanup.md) has the settings.

**The database refused queries for lack of memory.** With a few tens of
thousands of events the 1 GiB database answered some inserts and lookups
with "memory limit exceeded". ClickHouse counts its own program pages, about
500 MiB, against the limit QPot gave it (75% of the container), which left
it under 80 MiB to work in. The collector retried, so nothing was lost, but
the first restore rehearsal failed on it. The limit is now 90% of the same
1 GiB container, and the soak fails on any such refusal.

**`qpot instance remove` could not remove an instance.** Files written by
the collector and the database belong to their containers' users, so the
removal failed with "permission denied" on Linux and left the folder. It
now falls back to a short-lived helper container that has only the instance
folder mounted. The soak removes its own instances this way.

The longest run of this round, 04:12 to 04:54, 5 connections a second, each
fault held for 90 seconds:

| Connections | Count |
|---|---|
| sent | 12,659 |
| accepted by the honeypot | 10,687 |
| refused (honeypot closed) | 1,972 |
| stored, distinct | 10,665 |
| **lost** | **22**, all during `disk-full` |
| **stored twice** | **0** |

| Fault | Recovery (s) | Accepted during | Refused during | Lost | Stored twice |
|---|---|---|---|---|---|
| collector-amnesia | 8, 8 | 529, 529 | 0 | 0 | 0 |
| disk-low | 20, 25 | 99, 96 | 487, 511 | 0 | 0 |
| disk-full | 23, 62 | 111, 303 | 487, 487 | 15, 7 | 0 |
| database-freeze | 37, 5 | 651, 492 | 0 | 0 | 0 |
| collector-kill | 6 | 501 | 0 | 0 | 0 |
| control-plane-kill | 6 | 505 | 0 | 0 | 0 |

266 of 266 indicators found, none counted twice, no second copy of any
event left. Two later runs on the same tree (30 and 18 minutes) gave the
same picture: `disk-full` lost 7 and 2 connections, every other fault none;
the worker removed 22,729 and 2,030 second copies and left none; the
database refused no query.

What the numbers say:

- **Reading everything again costs nothing.** Each `collector-amnesia`
  delivered the whole log a second time. Nothing was lost, nothing stayed
  stored twice, and no indicator was counted twice.
- **A disk that runs low loses nothing.** In `disk-low` the guard closed
  Cowrie: about five in six connections during the fault were refused, and
  every one that was accepted is in the database.
- **A disk that is full at once still loses a little.** `disk-full` takes
  the last byte in one step, faster than any guard can act. The guard
  stopped Cowrie 1.3 seconds after it noticed; the 2 to 15 connections lost
  per episode are those Cowrie took before that. Before the guard the same
  fault lost 105 to 366.

## The HiFi capture soak

HiFi SSH sessions take another path to the database: the backend's sshd
records each session on its container's log, the control plane converts
that into evidence files in the cell's folder, a reset moves the folder into
an archive, and the collector reads the files. `TestHiFiCapture` puts that
path under the same kind of faults.

```bash
QPOT_SOAK=1 QPOT_SOAK_HIFI=1 QPOT_SOAK_BIN=/tmp/qpot QPOT_SOAK_DURATION=50m \
    QPOT_SSH_BACKEND_IMAGE=<the backend image> \
    go test ./internal/soak -run TestHiFiCapture -timeout 0 -v
```

It creates an instance with only the HiFi SSH honeypot and three cells, and
uses the settings of the table above. The traffic is one session that stays
open and runs a command every three seconds, and a new session every 20
seconds that runs three commands and leaves. Every command is
`echo <marker with a serial number>`.

- **Ran in a cell.** The client got the marker back: a real shell in a cell
  ran the command.
- **Lost.** Ran in a cell, and no command record with that marker is in the
  database when the run ends.
- **Stored twice.** More than one record for a marker.
- **Taken late.** A login the broker accepted more than 45 seconds into a
  fault that stops the conversion. The broker must turn visitors away once
  the conversion's heartbeat is 30 seconds old.

| Fault | What is done |
|---|---|
| `long-stay` | One visitor runs commands in one cell without a pause, more than the cell can record. The honeypot must end the stay before a command runs without a record |
| `capture-stop` | The control plane, which converts the recordings, is killed with SIGKILL, later started |
| `capture-freeze` | The control plane is frozen (SIGSTOP), later resumed |
| `collector-kill` | The collector is killed with SIGKILL, later started |
| `database-kill` | The database is killed with SIGKILL mid-write, later started |
| `collector-amnesia` | The collector is removed and its checkpoints deleted: it reads every record again, most of them from the archives |
| `cell-kill` | Every cell is killed with SIGKILL with sessions inside |
| `broker-kill` | The broker, which every session passes through, is killed |
| `disk-full` | The filesystem holding the instance is filled to the last byte, later freed |
| `long-outage` | The control plane is killed and, while it is down, one visitor runs commands in one cell until the honeypot ends the connection. Nobody converts the recordings or stops the cell: every command must wait in the cell's own log and be recorded once the control plane is back |
| `hours-outage` | The control plane is killed and stays down for `QPOT_SOAK_HIFI_OUTAGE`, longer than a cell lives, with a session open. Skipped when that is not set (the third round used `2h15m`) |

The test fails if a command that ran in a cell is not in the database, if
one is stored twice, if a login is taken late, or if a long stay is still
being served after 12,000 commands (where sshd would end it anyway; it was
2,100 until the [third round](#hifi-capture-through-a-long-outage)). It
counts once the worker has removed the rows a `collector-amnesia` made the
collector send again, and waits up to 90 minutes for that.

### What it found

**A HiFi instance could not be started by `qpot up`.** The collector reads
the cells' folders through mounts inside a read-only mount, and the mount
points did not exist on the host: Docker failed with "read-only file
system". They are now created before the containers start
(`TestNestedCollectorMountPoints`).

**A record was stored twice after a reset.** First run, 03:10 to 04:07, 14
faults: 1,356 commands ran in a cell, all were stored, one twice. The
event's ID covered the file's path, and a reset moves a cell's files from
`current/` into `archive-gN-…/logs/`. A file the collector had read and then
found again under its new path gave the same lines new IDs. The ID of a cell
record now leaves that part of the path out
(`TestVectorCellRecordIDSurvivesArchiveLive`).

**A long stay ran commands that left no record.** Second run, 05:41 to
06:35, 12 faults: 1,368 commands ran, 1,367 were stored. The missing one was
the 413th command of a session that had stayed in one cell for 21 minutes.
The host keeps at most 2,048 capture files for one account in one cell, five
for a command with its streams; past that the conversion dropped the
session's record and the cell went on serving. The backend's sshd had the
same gap one level down: a connection whose 64 MiB capture budget was used
up, which eight commands with large output do, ran every later command
unrecorded. Both now stop serving instead:

- the control plane stops a cell whose capture reaches the last eighth of a
  limit, and what the cell runs until it has stopped keeps its record;
- sshd ends a connection when a new command no longer fits its budget.

[ssh-hifi-proxy.md](ssh-hifi-proxy.md) has the details.
`TestWriterSaysFullBeforeAnyCommandGoesUnrecorded`,
`TestFollowRetiresACellCloseToItsCaptureLimit` and
`TestSSHBackendCaptureCostLive` cover them, and `long-stay` drives it in
the soak.

### Results of the last run

07:26 to 08:04, the tree with all of the above, faults held for two minutes
(`cell-kill` 20 seconds), two minutes apart.

| Commands | Count |
|---|---|
| sent | 1,753 |
| ran in a cell | 1,741 |
| stored | 1,741, and one more that a killed cell had recorded without its output reaching the client |
| **lost** | **0** |
| **stored twice** | **0** |

| Fault | Recovery (s) | Ran during | Lost | Stored twice | Logins taken / turned away | Taken late |
|---|---|---|---|---|---|---|
| long-stay | 9, 6 | 399, 393 | 0 | 0 | 1 / 0, 1 / 0 | 0 |
| collector-amnesia | 15, 18 | 59, 59 | 0 | 0 | 6 / 2, 6 / 3 | 0 |
| capture-stop | 12, 9 | 44, 47 | 0 | 0 | 1 / 5, 2 / 5 | 0 |
| cell-kill | 9, 9 | 4, 5 | 0 | 0 | 1 / 1, 1 / 1 | 0 |
| collector-kill | 6 | 59 | 0 | 0 | 6 / 0 | 0 |
| disk-full | 18 | 1 | 0 | 0 | 0 / 29 | 0 |

The two long stays were ended by the honeypot after 392 and 389 commands,
and every one of them is in the database. The earlier runs covered the
remaining faults, each twice, with no loss: `capture-freeze` (recovery 6 to
9 s), `database-kill` (15 to 25 s) and `broker-kill` (18 to 21 s).

What the numbers say:

- **A session that is open when the conversion stops keeps its evidence.**
  During `capture-stop` and `capture-freeze` the open session ran 42 to 47
  commands. They waited in the cell's container log and were converted and
  stored when the control plane came back.
- **The broker turns visitors away while nothing converts.** Of the six or
  seven logins during such a fault, one or two (those in the first 30
  seconds) were taken and the rest refused. None was taken late.
- **A full disk closes the HiFi honeypot.** 29 of 29 logins were refused.

Two minutes is what this run measured. An outage of 2 h 15 min with a
session open all the while, and outages in which one visitor uses all a
connection can carry, were run in the
[third round](#hifi-capture-through-a-long-outage).

## Restore rehearsal

`qpot db restore` fills a database from the collector's log backups
([release.md](release.md#rebuilding-the-database-from-log-backups)).
`TestRestoreRehearsal` rehearses the whole loss on an instance a soak left
in place (`QPOT_SOAK_KEEP=1`): it notes every event the database holds,
moves the database's folder away, starts an empty database, restores, lets
the worker classify everything again, and compares event by event.

```bash
QPOT_SOAK=1 QPOT_SOAK_RESTORE=1 QPOT_SOAK_BIN=/tmp/qpot QPOT_SOAK_INSTANCE=<kept instance> \
    go test ./internal/soak -run TestRestoreRehearsal -timeout 0 -v
```

The rehearsal of 08:24, on the instance of an 18-minute soak (collector
killed, disk filled, checkpoints lost, database killed):

| | Before | After the restore |
|---|---|---|
| events | 12,327 | 12,327 |
| indicators | 456 | 456 |
| indicator sightings | 724 | 724 |
| events missing | | 0 |
| events with any column changed | | 0 |
| events that were not there before | | 0 |
| events with another reading's time | | 114 |

The backup was one file of 18,607 lines: the soak had made the collector
read everything a second time, so 6,279 lines were later readings of events
already restored, and were skipped; one line was unreadable. The restore
took one second and classification under two minutes. A second restore
stored nothing. Two earlier rehearsals, on instances with 26,971 and 14,972
events, ended with the same events and the same indicators as before.

Two things it showed:

- **A restored event can carry another reading's time.** An event's time is
  the moment the collector read its log line. The 114 events had been read
  and written to the backup a moment before the collector was killed or the
  disk filled, so that reading never reached the database, which got them
  83 to 94 seconds later when the line was read again. The restore keeps
  the first reading in the backup. Everything else about those events is
  the same.
- **A full disk can cut a backup line short.** The unreadable line was
  being written when the disk filled. Its event was read again later, so
  nothing was missing here; an event whose only backup line is cut short is
  in the database but would not come back from a restore.

The first rehearsal failed outright: the database refused the restore's
lookups for lack of memory (see the second round above).


## The 1.1.2 release run

2026-11-12, 12:26 to 13:28, the tree that was tagged 1.1.2. Every fault of
the table above once, the two database faults twice, 5 connections a second,
each fault held for 90 seconds with two minutes between. The instance was on
a 4 GB ext4 filesystem of its own.

| Connections | Count |
|---|---|
| sent | 22,788 |
| accepted by the honeypot | 21,441 |
| refused (honeypot closed or restarting) | 1,347 |
| stored, distinct | 21,441 |
| **lost** | **0** |
| **stored twice** | **0** |

Collection delay: median 0.2 s, 99th percentile 84.8 s, longest 105.3 s.

| Fault | Recovery (s) | Accepted during | Refused during | Lost | Stored twice |
|---|---|---|---|---|---|
| database-stop | 45, 36 | 746, 706 | 0 | 0 | 0 |
| database-kill | 53, 54 | 738, 744 | 0 | 0 | 0 |
| database-freeze | 2 | 477 | 0 | 0 | 0 |
| collector-kill | 6 | 501 | 0 | 0 | 0 |
| collector-recreate | 4 | 504 | 0 | 0 | 0 |
| network-partition | 4 | 486 | 0 | 0 | 0 |
| honeypot-kill | 6 | 172 | 304 | 0 | 0 |
| honeypot-restart | 18 | 100 | 41 | 0 | 0 |
| control-plane-kill | 4 | 495 | 0 | 0 | 0 |
| worker-takeover | 2 | 501 | 0 | 0 | 0 |
| collector-amnesia | 10 | 539 | 0 | 0 | 0 |
| disk-low | 23 | 111 | 491 | 0 | 0 |
| disk-full | 27 | 120 | 511 | 0 | 0 |
| traffic-burst (10 times the rate) | 4 | 4,535 | 0 | 0 | 0 |

434 of 434 indicators found, none counted twice, no second copy of any event
left (the worker removed 37,967), no query refused for lack of memory.

Three things to read these numbers with:

- **Database outages took 36 to 54 seconds to recover from**, against 14 to
  29 in the three-hour run. The database itself was back within seconds each
  time. What takes the rest is intelligence: a worker that lost its lease is
  replaced after a wait that doubles up to one minute while the database is
  away, so recovery depends on where that wait stands when the database
  returns. Nothing is lost meanwhile; events are classified later.
- **The full disk lost nothing here, and did lose connections on a RAM
  disk.** The same matrix had run two hours earlier with the instance on a
  RAM disk, which fills within a second: 8 connections were lost during
  `disk-full` there (11 in a third run). The ext4 filesystem took a few
  seconds to fill, long enough for the disk guard to close Cowrie first.
  How fast a disk can fill decides this, not the guard alone.
- **The RAM disk also explained the memory refusals of the second round.**
  That earlier run refused one query for lack of memory, and a third run
  two. Both were the worker's checkpoint being written during the traffic
  burst, and both were retried. The cause was the test bed: on a RAM disk
  every byte the database writes to its own files is charged to its
  container's memory limit (375 MB of the 1 GiB by the end of a run), and
  ClickHouse lowers its own allowance to match. On a disk those pages are
  ordinary file cache. The soak now runs on a disk filesystem; the memory
  setting changed in the second round stays, since it costs nothing.

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

### From 1.0.1 to 1.1.2

2026-11-12, same host, the released 1.0.1 and the tree that was tagged
1.1.2, both run by an ordinary user in the `docker` group. The same
procedure.

| Stage | Check | Result |
|---|---|---|
| 1.0.1 | 60 connections stored once | 60, 0 duplicates |
| | scanner banners stored | 0 of 5: dropped by its filter |
| | backup lines carrying the QPot ID | 190 |
| Upgrade | connections across the upgrade stored once | 120, 0 duplicates |
| | old backup lines rewritten to the sensor ID, file sizes unchanged | 190 of 190 |
| | generated files, container environments, mounts and logs carrying the QPot ID | 0 |
| | scanner banners stored and tagged `nmap` | 5 of 5 |
| Refusals | no login on `0.0.0.0`: `qpot up` and `qpot serve` | refused with QP-WEB-005, no container started |
| | egress guard off with dionaea enabled: `qpot up` | refused with QP-INST-015, no container started |
| | connections after the refusals and a restart stored once | 150, 0 duplicates |
| Rollback | database after restoring the backup under 1.0.1 | the 60 connections it held, 0 duplicates |
| | 1.0.1 collects again | 90, 0 duplicates |

**What this rehearsal found.** Its first run stored the 60 connections of
1.0.1 a second time after the upgrade. 1.0.1 kept the collector's reading
positions inside its container, so an upgraded instance has none, and QPot
marks the logs it finds as already collected before the new collector
starts. Cowrie's log belongs to the container's user, though, and a QPot run
by an ordinary user could not read it: that log was skipped without a word,
and the collector read it from its first line. (The rehearsal of the day
before started from a later build, which already kept positions in the
instance, and could not see this.) QPot now reads such logs through a
short-lived, read-only helper container, and does not start the instance
when it cannot mark a log: sending everything again silently is worse than
stopping. `TestSeedReadsWhatThisUserMayNot` and `TestCollectorLogReaderLive`
cover it; the table above is the run after the fix.

### From 1.1.2 to 1.1.3

2026-11-13, same host, the released 1.1.2 and the tree that was tagged
1.1.3, both run by an ordinary user in the `docker` group. The same
procedure. Its checks for what 1.0.1 did wrong (scanner banners dropped,
the QPot ID in backups and container environments) have nothing to find in
1.1.2 and are left out.

| Stage | Check | Result |
|---|---|---|
| 1.1.2 | 60 connections stored once | 60, 0 duplicates |
| | scanner banners stored and tagged `nmap` | 5 of 5 |
| Upgrade | connections across the upgrade stored once | 120, 0 duplicates |
| | scanner banners stored and tagged `nmap` | 10 of 10 |
| | generated files, container environments, mounts and logs carrying the QPot ID | 0 |
| Refusals | no login on `0.0.0.0`: `qpot up` and `qpot serve` | refused, no container started |
| | egress guard off with dionaea enabled: `qpot up` | refused, no container started |
| | connections after the refusals and a restart stored once | 150, 0 duplicates |
| Rollback | database after restoring the backup under 1.1.2 | the 60 connections it held, 0 duplicates |
| | 1.1.2 collects again | 90, 0 duplicates |

What 1.1.3 changes in an instance 1.1.2 made, on a second instance with 40
connections before the upgrade and 40 after:

| Check | Under 1.1.2 | After `qpot up` with 1.1.3 |
|---|---|---|
| Cowrie's log, which the container's user owns | mode 640, no room beyond its end | writable by QPot (mode 662) and one megabyte of room, within 5 seconds |
| Events table takes lightweight updates | no | yes (`enable_block_number_column`) |
| Events stored / classified / distinct IDs | 120 / 0 (the worker had not run yet) | 240 / 240 / 240 |
| Connections made after the upgrade, classified | | 40 of 40 |
| Tagging mutations | | 0 |

## The 1.1.3 release run

2026-11-13, 18:35 to 19:38, the tree that was tagged 1.1.3. Every fault
once, the three database faults twice, 5 connections a second, each fault
held for 90 seconds with two minutes between. The instance was on a 4 GB
ext4 filesystem of its own.

| Connections | Count |
|---|---|
| sent | 23,207 |
| accepted by the honeypot | 21,872 |
| refused (honeypot closed or restarting) | 1,335 |
| stored, distinct | 21,872 |
| **lost** | **0** |
| **stored twice** | **0** |

Collection delay: median 0.2 s, 99th percentile 84.2 s, longest 103.8 s.

| Fault | Recovery (s) | Accepted during | Refused during | Lost | Stored twice |
|---|---|---|---|---|---|
| database-stop | 14, 17 | 595, 611 | 0 | 0 | 0 |
| database-kill | 20, 9 | 574, 515 | 0 | 0 | 0 |
| database-freeze | 6, 15 | 498, 540 | 0 | 0 | 0 |
| collector-kill | 6 | 502 | 0 | 0 | 0 |
| collector-recreate | 6 | 514 | 0 | 0 | 0 |
| network-partition | 16 | 547 | 0 | 0 | 0 |
| honeypot-kill | 6 | 175 | 301 | 0 | 0 |
| honeypot-restart | 8 | 49 | 40 | 0 | 0 |
| control-plane-kill | 4 | 494 | 0 | 0 | 0 |
| worker-takeover | 2 | 500 | 0 | 0 | 0 |
| collector-amnesia | 8 | 529 | 0 | 0 | 0 |
| disk-low | 18 | 80 | 498 | 0 | 0 |
| disk-full | 16 | 68 | 496 | 0 | 0 |
| traffic-burst (10 times the rate) | 4 | 4,532 | 0 | 0 | 0 |

446 of 446 indicators found, none counted twice, no second copy of any event
left (the worker removed 37,027), no event left unclassified, no query
refused for lack of memory.

Before this run, the changes of the two rounds below were gone through
again. That found six things, each fixed with a test that fails without the
fix:

- **A restore undone.** Rows `qpot db restore` brought back after the
  events table had lost them were deleted again as second copies (see
  "A row is a second copy only while the first is there" below).
- **A server without lightweight updates** would have failed every batch;
  it is now asked once at start.
- **What a honeypot's logs folder could cost the host.** The guard listed
  the whole folder every five seconds, opened every log in it, and named
  every one of them in a log line. It now lists at most 4,096 entries (a
  folder with more gets no room), opens at most four logs a tick and names
  at most eight.
- **Conpot stopped on a state file of nested brackets.** A file of 20,000
  `[` raised an error the two state readers did not catch.
- **A worker stopped in the middle of a step reported an error.** This was
  the test that failed once or twice in a hundred runs on Linux
  (`TestIntelligenceSummaryReportsWorkerLifecycleWithoutSecrets`: 58
  failures in 2,400 runs before, none in 4,800 after).
- **Cowrie logged a client in on a public-key query** that carries no
  signature ([deception.md](deception.md#cowrie-patch-layer)).

## Third round: a disk that fills at once, long HiFi outages, a large database

2026-11-12 into the 13th, after 1.1.2. Same host as the runs above; every
instance on an ext4 filesystem of its own. Three things the earlier rounds
had left open were tested until they stopped failing, and each found
faults the short runs had not.

### Abrupt disk exhaustion

The fault: the filesystem that holds the instance is filled to the last
byte at once (one megabyte at a time, as fast as the disk takes it) while
connections keep arriving at 5 a second, held for 45 to 60 seconds and
freed. A connection the honeypot accepted must still be stored. Four
versions of the protection were run against it:

| Version | Fills | Accepted | Lost | What the kept instance showed |
|---|---|---|---|---|
| A. Cowrie holds lines it cannot write; the guard frees a reserve file when the disk is low | 12 | 6,729 | 2 | Cowrie's log said `Event sink Output failed: No space left on device`: the holding was not in use |
| B. The same, in use | 14 | 7,276 | 4 | `stopping with N events the disk did not take`, the reserve already gone |
| C. The reserve is freed when the disk is full and no longer filling; a stopping Cowrie waits for room | 8 | 2,784 | 1 | The reserve was freed at the right moment and the wait still found no room |
| D. A stopping Cowrie writes what waits into a file of its own that has its blocks | 8 | 2,557 | 0 | |

What each step found:

- **A: the protection was not running.** The patched log writer queued
  lines only for Cowrie's rotating log file. An instance's Cowrie is
  configured with the plain one, and for that kind the patch had kept the
  image's code, which raises on a full disk and drops the event. The live
  test that should have caught it set the rotating kind itself. The writer
  now queues for both, and the test runs both (the image's own code on the
  same disk: 197 of 261 writes raised with the plain file, 62 of 261 events
  kept with the rotating one).
- **B: the reserve was freed too early.** The guard saw 120 to 170 MB left,
  which is below its floor, and freed its 64 MB at once. The writer that
  was filling the disk took those too. Cowrie was stopped a second later,
  wrote what it held once, found the disk full and exited with two to five
  events in memory. The guard now frees the reserve when the disk is full
  and has stopped filling (two looks 150 ms apart under 16 MB, the second
  no lower), and it watches for that while it stops the honeypots. Cowrie
  waits two seconds for room when it stops.
- **C: the reserve is anybody's.** In one fill of eight the reserve was
  freed while Cowrie waited, and Cowrie still found no room for six
  seconds: something else on the full disk (the database and the collector
  had work waiting too) took it first. Cowrie therefore keeps one megabyte
  of its own, written in full when it starts; what still waits when it
  stops is written into that file, which needs no new space, and goes into
  the log at the next start.

D was then run for hours, and the disk had one more fault to show (a line
written in two pieces): see [the extended run](#the-extended-run).
[disk-cleanup.md](disk-cleanup.md#a-disk-that-fills-at-once) describes the
mechanism and what it cannot do.

### HiFi capture through a long outage

Two faults were added to the HiFi soak. `long-outage`: the control plane is
killed and one visitor runs commands in one cell without a pause until sshd
ends the connection at its 64 MiB (17,340 commands in every run).
`hours-outage`: the control plane stays down for `QPOT_SOAK_HIFI_OUTAGE`
(2 h 15 min, longer than a cell lives) with a session open.

With the control plane down nobody stops a cell that passes its capture
limits, and until this round its commands past them left no record. They
now keep a short one (who, when, the command, exit status, the first 4 kB
of input and output) in one file per account. The soak found three faults
in the first version of that:

- **Every such record stored twice.** One run stored 10,418 commands twice
  (21,585 in another). The kept instance's file held 54,747 lines where
  about 34,000 belonged. A cell reset drains the cell's log into the folder
  before it archives it; the drain wrote the file one synced line at a
  time, did not finish 17,000 commands in its two minutes, and was stopped
  half-way. The follower then went on with its next batch, remembering
  the file as it had been before the drain, and appended what the drain
  had written. The writer now reads the file again, from where it last
  looked, whenever another writer may have been there (after every batch),
  and syncs once per batch. `TestWriterOverflowWithADrainInBetween` fails
  without that; the fuzz target has the same step.
- **Recovery after such an outage took 135 to 161 seconds**, most of it the
  one synced line at a time. It now takes 39 to 55 seconds.
- **The long stay was measured on a RAM disk.** `long-stay` expected the
  follower to stop a cell before 2,100 commands. On a filesystem that
  really syncs every file, a visitor running 160 commands a second is
  1,600 to 2,500 commands in by the time the follower has read the 360
  that a cell keeps in full and stopped the cell. Nothing is lost (the
  later ones get short records), so the test now requires that the
  follower ends the stay before sshd would (12,000 commands).

After the fix, three `long-outage` faults in a row: 52,152 commands run,
none lost, none stored twice.

### The database at 25 million events

`TestDatabaseBench` (`QPOT_SOAK=1 QPOT_BENCH=1`, sizes in
`QPOT_BENCH_SIZES`) creates an instance as the soak does and, for each
size, fills the events table with classified history spread over 60 days
(one indicator per 40 events, one session per 100), then measures for five
minutes while everything that touches the database runs at once: live
traffic at 5 connections a second, the collector, the intelligence worker,
and two dashboards asking every ten seconds for what an open dashboard
asks. ClickHouse under QPot's own limits (1 GiB, one CPU).

Both columns are from the same host, run one after the other with nothing
else running: 1.1.2 as released, and after this round's changes. API
times are the 95th percentile in milliseconds.

| | 1 M | 5 M | 10 M | 25 M |
|---|---|---|---|---|
| Events table on disk | 122 MB | 522 MB | 961 MB | 2.2 GB |
| `/api/intelligence`, 1.1.2 | 275 | 783 | 1,112 | 3,067 |
| after | 66 | 161 | 292 | 539 |
| `/api/iocs?limit=15`, 1.1.2 | 143 | 547 | 965 | 2,554 |
| after | 71 | 167 | 293 | 628 |
| `/api/ttps?limit=50`, 1.1.2 | 139 | 347 | 667 | 1,745 |
| after | 63 | 73 | 206 | 425 |
| `/api/techniques`, 1.1.2 | 276 | 569 | 861 | 1,633 |
| after | 64 | 70 | 106 | 319 |
| `/api/stats`, 1.1.2 | 232 | 352 | 663 | 1,632 |
| after | 156 | 183 | 334 | 730 |
| `/api/events?limit=50`, 1.1.2 | 35 | 40 | 65 | 42 |
| after | 13 | 14 | 92 | 29 |
| Database CPU held back by its limit, 1.1.2 | 7% | 16% | 22% | 60% |
| after | 4% | 6% | 7% | 19% |
| Events waiting for classification, most, 1.1.2 | 964 | 889 | 880 | 3,101 |
| after | 892 | 964 | 883 | 2,210 |
| Live connections lost / stored twice | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Queries refused for lack of memory | 0 | 0 | 0 | 0 |

Loading history ran at 66,000 to 190,000 rows a second through the same
limits. No call failed at any size in either version.

What grew with the table in 1.1.2, and what was changed:

- **Indicators and sessions.** The dashboard asks for the newest 15
  indicators and 50 sessions. Each answer read every column of every
  indicator or session ever stored, twice (once to leave out what an older
  table also holds), and sorted them: 1.8 s and 136 MB per call at 625,000
  indicators. A page is now chosen from keys and times alone and only its
  rows are read in full; the older tables are left out of the query when
  they are empty. 0.43 s and 9 MB.
- **Summary counts.** `/api/intelligence` loaded 10,000 indicators to count
  them and 5,000 events to count their techniques; `/api/techniques` and
  `/api/categories` loaded 10,000 events each, payloads and all. ClickHouse
  now counts, from the columns that matter. The indicator total is exact
  where it was capped at 10,000.
- **The worker's replay check.** For every batch the worker asks which
  event IDs already have a classified row. The events table is ordered by
  time, and its ID index cannot rule out a few hundred IDs at once, so the
  question read the whole table: 24 of 25 million rows, 2.0 s, per batch
  of 500. The IDs of classified events are now also kept in a small table
  ordered by ID. A database from an earlier version gets that table filled
  in the background at the worker's first batch.

What still grows, and was left:

- **Classification** (changed since; see the next section). In this round
  the worker marked events classified with mutations of 250 events each,
  and a mutation rewrites the changed columns of every part it touches:
  about 2 s each at 1 M events, 4 to 5 s at 25 M, about 55 events a second
  at 25 M on the one CPU the database has. Live traffic in the benchmark was
  15 events a second.
- **Unique visitors of the last 24 hours** (`/api/stats`) is an exact
  count over that day's events: 0.43 s at 450,000 events a day.
- **Every batch writes the worker's whole session state** (all open
  sessions, 37 to 59 MB at 15,000 to 20,000 of them). Not measured here:
  the benchmark's traffic comes from one address.
- The benchmark is ClickHouse only, one sensor, 25 million events (about
  three days of a busy sensor at 100 events a second, or the 90 days the
  events table keeps at 3 a second).

### Classification at its limit, and rows sent again

`TestDatabaseBench` now also measures, after each size's five minutes:

- **the worker at its limit**: 30,000 new events stored at once (from 400
  addresses, the last 20 minutes), and the rate from the last look that
  found none of them classified to the first that found all;
- **a collector that lost its place**: about 200,000 classified events of
  the history (an even sample of all 60 days; 249,000 at 1 M) stored again
  with the IDs they have, and the time until no second copy is left. The
  history's IDs are of the collector's kind and in the set of classified
  IDs, as if the worker had classified them.

Before is `cd84f192`, after is the tree that was tagged 1.1.3, both with the
extended benchmark, on the same host. The 25 M "before" figures come from
two runs: the first (during which another soak ran on the host, in its own
containers) stopped when its copy of the sample hit the harness's 30 s
query limit, the second measured only the copies.

| | 1 M before | 1 M after | 25 M before | 25 M after |
|---|---|---|---|---|
| Classified per second, worker at its limit | 72.4 | 436.0 | 62.2 | 226.3 |
| Rows sent again | 249,377 | 249,437 | 201,177 | 201,895 |
| Last second copy gone after (s) | 1,876 | 31 | 1,966 | 147 |
| IDs stored twice at the end | 0 | 0 | 0 | 0 |
| Live connections lost / stored twice | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Queries refused for lack of memory | 0 | 0 | 0 | 0 |

The rate varies from run to run: earlier trees of this change measured
231.1 and 288.8 a second at 25 M (the second without copies), and 167.5
with patches written in from 20,000 rows instead of 2,000. One run of the
final tree stopped at 1 M when the database refused the harness's own
statement that stores the sample again, for lack of memory; the run above
is the one after it.

**The dashboard's slowest calls at 25 M are slower than with 1.1.2's
tagging.** Median, 95th percentile and longest call in the five minutes of
live traffic (61 calls each), with nothing else running on the host:

| Call | Before (ms) | After (ms) |
|---|---|---|
| `/api/stats` | 404 / 591 / 867 | 404 / 754 / 1,041 |
| `/api/intelligence` | 273 / 458 / 670 | 268 / 651 / 849 |
| `/api/techniques` | 160 / 268 / 557 | 154 / 453 / 655 |
| `/api/iocs?limit=15` | 272 / 370 / 552 | 262 / 550 / 653 |

The medians are the same; the slowest calls take 1.3 to 1.7 times as long.
What they wait for is the database's one CPU: patches of lightweight
updates are written into the parts in the background (a mutation each
time 2,000 patched rows have built up), and a call that falls into one
waits. A run that never wrote the patches in had lower 95th percentiles
(706, 570, 465 and 477 ms) and higher medians (507, 385, 363 and 365 ms),
because every read then applies all of them; that is no way to run.

The first version of this change was slower still (95th percentiles of
967, 760, 632 and 646 ms): a worker that was keeping up looked for second
copies every two minutes, a read of every unclassified row and a lookup in
the set of classified IDs, one to two seconds of the database's CPU each
time, for rows its own next batch reads anyway. It no longer does. At 1 M
the same calls take 23 to 35 ms at the median and 114 to 124 at the 95th
percentile.

What was changed:

- **Lightweight updates.** Events are marked classified with `UPDATE`,
  which writes a small patch holding the changed values of the batch's
  rows, instead of a mutation rewriting the changed columns of every part
  holding one of them. On the pinned server under QPot's limits, at 25 M
  rows: about 0.07 s per 250 events against 1.7 to 2.2 s. The events table
  gets the two settings this needs when the control plane starts; a table
  made by 1.1.2 takes them and its old rows are tagged the same way
  (`TestClickHouseLightweightTaggingUpgrade`). Reads apply the patches until
  they are written into the parts: with 123,000 patched rows in 16 patches,
  the worker's read of unclassified events took 1.2 s at 25 M. Once the
  patches hold 2,000 rows the worker starts `APPLY PATCHES` in the
  background, at most every 30 seconds.
- **Two copies with the same time end as one row.** Tagging marked both;
  the extra one is now deleted by the part and offset it is stored at
  (`TestClickHouseTaggingLeavesOneRowPerObservation`).
- **Second copies are found by ID.** The worker looks through the
  unclassified rows a window at a time for IDs it has already classified
  and deletes those rows wherever they are in time, taking turns with
  classification (`TestWorkerSweepsCopiesAheadOfOrder`,
  `TestClickHouseSweepsReplayedEvents`). Deletes of second copies are
  patches too. It looks ahead only while it has more than a batch to
  classify or is finding copies.
- **A row is a second copy only while the first is there.** `qpot db
  restore` stores events the events table no longer has. Where the table
  had lost rows the worker had classified, the set of classified IDs still
  knew them, and the restored rows would have been deleted as second
  copies: the restore undone, without a word. Restoring now takes those IDs
  out of the set first (`TestClickHouseRestoredRowsAreNotSecondCopies`).
- **A server that takes the settings and not the statements** is asked
  once, at start, with an update and a delete that name no row; if it
  refuses, events are marked with mutations as before. A background write
  of the patches that keeps failing is logged every ten minutes.
- **What else a batch waited for.** The lookup of a batch's stored
  indicators named each key as a filter on the deduplicated indicators and
  read all of them (0.55 s at 25,000 indicators, 0.9 s at 625,000); the
  keys now go where the table's order finds them (0.08 s at 625,000). The
  canary scan confirmed the worker's lease once per event (a fifth of a
  batch at 1 M); it now does so once a second.

What the 25 M figure is made of now: per batch of 500, the read of
unclassified events (0.2 to 1.2 s, depending on the patches not yet
written in), the lookup of the batch's IDs in the set of classified IDs
(0.5 to 0.8 s at 25 million IDs in the freshly filled set), and the
checkpoint's own writes. The benchmark's look at the backlog (a count over
the table every 2 seconds) costs the database's CPU too, as it did before.

### The extended run

Commit `d3928ecb`, 18:34 to 21:49 (3 h 15 min). 5 connections a second,
each fault held for 90 seconds with two minutes between. Eighteen faults
per round, five of them the full disk; three rounds bar the last two
faults.

| Connections | Count |
|---|---|
| sent | 66,687 |
| accepted by the honeypot | 56,964 |
| refused (honeypot closed or restarting) | 9,723 |
| stored, distinct | 56,964 |
| **lost** | **0** |
| **stored twice** | **1** |

Collection delay: median 0.2 s, 99th percentile 93.2 s, longest 139.1 s.

| Fault | Times | Recovery (s) | Accepted during | Refused during | Lost | Stored twice |
|---|---|---|---|---|---|---|
| disk-full | 14 | 16 to 25 | 1,237 | 7,124 | 0 | 1 |
| disk-low | 3 | 23, 25, 26 | 279 | 1,536 | 0 | 0 |
| database-stop | 3 | 14, 11, 17 | 1,786 | 0 | 0 | 0 |
| database-kill | 3 | 18, 27, 28 | 1,782 | 0 | 0 | 0 |
| database-freeze | 3 | 14, 2, 7 | 1,517 | 0 | 0 | 0 |
| collector-kill | 3 | 6, 6, 6 | 1,507 | 0 | 0 | 0 |
| collector-recreate | 3 | 4, 4, 4 | 1,517 | 0 | 0 | 0 |
| collector-amnesia | 3 | 13, 27, 44 | 1,885 | 0 | 0 | 0 |
| network-partition | 3 | 14, 21, 6 | 1,603 | 0 | 0 | 0 |
| honeypot-kill | 3 | 6, 6, 4 | 495 | 925 | 0 | 0 |
| honeypot-restart | 3 | 18, 19, 19 | 288 | 138 | 0 | 0 |
| control-plane-kill | 3 | 4, 4, 2 | 1,475 | 0 | 0 | 0 |
| worker-takeover | 3 | 2, 2, 2 | 1,502 | 0 | 0 | 0 |
| traffic-burst (10 times the rate) | 2 | 4, 4 | 9,065 | 0 | 0 | 0 |

1,219 of 1,219 indicators found, none counted twice, no second copy of any
event left (the worker removed 183,965), no query refused for lack of
memory. Recovery from a database outage, 36 to 54 seconds in the release
run, is 11 to 28: a worker that lost its lease is now replaced after 15
seconds at most instead of 60.

Nothing was lost in fourteen full disks. The run still failed, on the one
connection stored twice, and that was one more thing a full disk does:

- **A line written in two pieces.** When the disk filled, 223 bytes of one
  log line fitted and the rest did not; Cowrie's patched writer wrote the
  rest a second later, in place. The collector had read the first piece
  meanwhile. It gives every line an identity made of its file, the place
  it starts at and its text, and for this line it took the place where the
  second piece started. 38 minutes later the `collector-amnesia` fault made
  it read the log again, the line whole this time, at its true place: a
  second identity, so a second row that nothing recognised as a copy.
  (Both identities were recomputed from the kept log to be sure.) Cowrie's
  writer no longer continues a line: what the disk took is ended with a
  newline, which the collector drops as not being JSON, and the whole line
  is written after it. `TestCowrieJSONLogEndsAHalfWrittenLine`.

The HiFi soak ran beside it on the same commit for 3 h 15 min, with the
control plane down for 2 h 15 min in the middle (`hours-outage`):

| Fault | Held (s) | Recovery (s) | Commands during | Lost | Stored twice |
|---|---|---|---|---|---|
| long-stay | 15 | 9 | 732 | 0 | 0 |
| long-outage | 137 | 18 | 17,376 | 0 | 0 |
| capture-stop | 122 | 6 | 47 | 0 | 0 |
| collector-amnesia | 137 | 18 | 59 | 0 | 0 |
| cell-kill | 35 | 18 | 8 | 0 | 0 |
| disk-full | 124 | 21 | 1 | 0 | 0 |
| hours-outage | 8,102 | 24 | 2,359 | 0 | 0 |
| long-stay | 17 | 6 | 1,072 | 0 | 0 |
| long-outage | 109 | not within 15 min | 17,379 | | 0 |

During the 2 h 15 min the broker turned away 608 logins and the sessions
already open ran 2,359 commands; all of them were stored, once, within 24
seconds of the control plane's return. The last fault did not recover, and
the run failed on it:

- **The collector takes 2 kB of a file per round.** After the last outage
  every record was converted and on disk, the database was idle, and the
  collector delivered three lines a second: 15 minutes later it had 24,171
  of 39,579 commands. Vector reads its files in turn, by default 2,048
  bytes of each, and by then it had 3,004 HiFi record files to go round
  (every command with its streams is a file). On the kept instance the
  same collector delivered 523 lines a second with that limit at one
  megabyte, and the backlog was in within a minute. The limit is now one
  megabyte for every log the collector reads. The first outage of the same
  run, with few files, had recovered in 18 seconds.

### The two fixes, run again

The full matrix above ran on `d3928ecb`. The two fixes it led to were then
run on their own (`51f4119d`), each against the sequence it had failed on.

Disk, 22:06 to 23:23: four full disks and then the collector losing its
place, six times over, 5 connections a second, each fault held for a
minute with a minute between.

| Connections | Count |
|---|---|
| sent | 22,129 |
| accepted by the honeypot | 13,581 |
| refused (honeypot closed) | 8,548 |
| stored, distinct | 13,581 |
| **lost** | **0** |
| **stored twice** | **0** |

| Fault | Times | Recovery (s) | Accepted during | Lost | Stored twice |
|---|---|---|---|---|---|
| disk-full | 24 | 20 to 47 | 2,395 | 0 | 0 |
| collector-amnesia | 6 | 6 to 12 | 2,334 | 0 | 0 |

No second copy of any event was left (the worker removed 151,223). Three
times Cowrie was stopped holding events the disk had not taken (2, 4 and 5
of them): each time they went into its spare file and into the log at the
next start. Whether a line was cut in two in this run was not counted; the
unit test and the live test cut one on purpose.

HiFi, 23:28 to 01:04: six `long-outage` faults with `long-stay`,
`collector-amnesia` and `capture-stop` between them, two minutes apart.

| Commands | Count |
|---|---|
| sent | 106,613 |
| ran in a cell | 106,599 |
| stored | 106,599, and one more whose output never reached the client |
| **lost** | **0** |
| **stored twice** | **0** |

| Fault | Times | Recovery (s) | Commands during | Lost | Stored twice |
|---|---|---|---|---|---|
| long-outage | 6 | 27, 34, 37, 37, 50, 50 | 104,269 | 0 | 0 |
| long-stay | 2 | 9, 13 | 1,340 | 0 | 0 |
| collector-amnesia | 2 | 25, 32 | 118 | 0 | 0 |
| capture-stop | 1 | 6 | 44 | 0 | 0 |

By the end the collector had 4,112 record files to go round, more than
the 3,004 at which the extended run stopped recovering, and the sixth
outage recovered in 50 seconds.

The first attempt at this run showed a fault in the test and gave one
number worth having. Its last fault was `collector-amnesia` with 108,000
commands stored. The collector sent 216,000 rows again within five
minutes, under the identities they already had, and the test counted a
minute later, before the worker had come to them. The test now waits for
the worker. It removes such rows once it has classified what is older: in
the run above every copy was gone 47 minutes after the last session (22
minutes of classifying what the last outages had left, then 213,000 copies
in 23 minutes). Until then a list of events shows such a row twice;
indicators and sessions count it once.

## Fourth round: TimescaleDB end to end, and lines written to break what reads them

2026-11-13, after 1.1.3. Both soaks run Cowrie on ClickHouse. This round
went where they do not: an instance on TimescaleDB from the visitor to the
dashboard, and log lines made to be refused by whatever reads them. Real
Docker, the pinned images, one sensor.

### TimescaleDB, end to end

An instance with Cowrie on TimescaleDB, the worker at a one-minute interval.
Every connection carried a serial number in its SSH version string.

| Check | Result |
|---|---|
| 30 plain connections | 30 stored, none twice |
| Database stopped for 33 s while 40 connections arrive | 40 stored, none twice |
| Database killed while 40 connections arrive | 40 stored, none twice |
| Collector killed while 60 connections arrive | 60 stored, none twice |
| At the end: rows, distinct event IDs, unclassified | 986, 986, 0 |
| Every read endpoint of the dashboard | answered |

This is three faults once each, not a soak.

### One NUL character cost a whole batch (TimescaleDB)

The collector hands PostgreSQL a batch as one JSON value, and PostgreSQL
refuses all of it when one value in it cannot be stored. A NUL character is
such a value. Cowrie writes the bytes of a login as text (`\x00`), but a
command as it was typed: a visitor who logged in and ran `echo a\0b` made
Cowrie write the JSON escape of NUL, PostgreSQL answered "unsupported
Unicode escape sequence", and the collector dropped the request:

| | Before | After |
|---|---|---|
| Events in the batch with the command | 103 lost, among them all 30 connections other sources made in those 5 seconds | all stored |
| The command itself | lost | stored, without the NUL |
| The collector's mark in the log | moved past the lost lines | (nothing lost) |

The lost events were still in the log backup, and `qpot db restore --merge`
brings them back. Nothing else told the operator: the collector logged the
error and went on.

The same loss followed from a value an index entry cannot hold (an event
name of 12,000 characters, which a honeypot that is no longer its own can
write), and from any field the honeypot's own JSON carried beside the ones
QPot stores, because the whole event went to the database. The step in
front of PostgreSQL now hands over the stored columns and nothing else,
each made storable: text without NUL, the indexed names bounded, the address
an address or absent, the ports ports, metadata a flat map of strings. The
payload column is bytes and keeps every byte.

`TestTimescaleCollectorStoresHostileEventsLive` sends eleven such lines in
one batch through the real collector into the pinned TimescaleDB with the
production schema: eleven rows. With the old step: none. With only the NUL
removal or only the name bound taken out: none. The test, and every other
PostgreSQL test, now runs in CI against the image an instance runs
(`timescaledb-integration`); before, CI ran only the worker's lease tests,
on plain PostgreSQL.

ClickHouse stores a NUL. Eleven hostile lines of the same kinds, appended to
the log of a live Cowrie on ClickHouse, were all stored (among them a
90,000-character command and a line whose own fields carry the names of
QPot's columns with the wrong types).

### One odd row broke every list of events (TimescaleDB)

The metadata column is JSONB and takes any JSON. The collector stores a flat
map of strings there, and the reads assumed nothing else could be in it: one
row whose metadata held a number failed the scan of the whole page. On the
live instance the dashboard's event lists answered "internal error", and the
worker's batch query fails the same way at the same row on every pass. No
line the collector writes produces such a row (and the step above now
guarantees it), but one row from anywhere else stopped every read. A value
that is not a string is now read as its JSON text
(`TestPGReadsSurviveOddMetadata`, against the pinned image in CI).

### A long line left no record (both databases)

The collector discards, whole, a line longer than 102,400 bytes. Cowrie
writes a command twice in one line (as `input` and in `message`), so a
command of 51,000 characters is already too long:

| A real Cowrie session runs one command of | Cowrie's line | Before | After |
|---|---|---|---|
| 20,000 characters | 40 kB | stored | stored |
| 60,000 characters | 120 kB | the command in neither the database nor the log backup; the rest of the session stored | stored: the first 16,384 characters, with the length and SHA-256 of all of it |

The command in the test began with a download (`wget http://...`) and went
on with padding. Before, nothing an operator looks at showed the download.

Two changes. QPot's Cowrie logger no longer writes a line the collector
discards: a line that would be longer than 96 kB has its long values cut,
and names each one with its full length and SHA-256; the event carries that
as `metadata.truncated`, `input_chars` and `input_sha256`. And for every
honeypot, the collector now stores an event when it discards a line:
`<honeypot>.log.line_discarded`, with the start of the line (the first
thousand bytes or so, which is what the collector reports) as its payload,
and the visitor's address and session when that start names them. On the
live instance a 200 kB line appended to Cowrie's log came out as that event,
with the address and the session of the line.

### The worker's batches on a large table (TimescaleDB)

The third round measured ClickHouse at 25 million events; TimescaleDB had
never been measured at any size. With 5 million events stored over 60 days
and 600 new ones waiting, on the one CPU and one gigabyte the database gets,
these are PostgreSQL's own execution times for what the worker runs for
every batch of 500:

| Statement | Before | After |
|---|---|---|
| The batch: the oldest unclassified rows | 1.4 to 3.4 s | 2 to 10 ms |
| Removing second copies of the batch | 6.2 to 6.9 s | 73 to 89 ms |

Before, the batch query sorted every chunk of the table to find the few
rows it wanted, and the removal looked for the batch's rows by an ID that
has no index. An index that holds only unclassified rows now answers the
first, and the batch's own span of time bounds the second. Planning adds 60
to 200 ms to each statement (61 chunks). The index is created at the first
start with the new version, which took 4 seconds on those 5 million rows.
Not measured: 25 million events,
and a backlog of more than a few hundred rows.

## Where the promise ends

- **Before the honeypot logs it.** A connection the honeypot never took, or
  took and was killed before writing its log line, is not evidence QPot
  ever had. The soak reports these as refused, or as lost during a
  `honeypot-` fault.
- **A disk that fills in one step.** The disk guard closes the honeypots
  when free space runs low, and then nothing is lost. For a disk that goes
  from enough to nothing between two looks, up to four logs per honeypot
  that QPot can write to (its own logs first) have a megabyte allocated
  beyond their end, and the honeypot goes on logging into it until the
  guard has stopped it: endlessh, Conpot and
  Dionaea kept 100 of 100 visitors on a full disk, where without it
  endlessh kept 3 to 68, Conpot stopped itself at the first failed write and
  Dionaea kept 1 when stopped. Cowrie also holds what it cannot write. A
  20-minute soak with 8 full disks lost nothing. A log a honeypot created
  as its own user (every other honeypot's, and the logs of an instance made
  before this change) is made writable by cleanup's helper container and
  then gets its room too. What can still be lost: more than a megabyte of
  one honeypot's log before it stops; logs of a honeypot past its fourth; a
  log in the seconds before the helper has reached it; hosts other than
  Linux, and btrfs or ZFS (XFS was not measured); and what a Cowrie holds
  in memory when it is killed instead of stopped. See
  [disk-cleanup.md](disk-cleanup.md#a-disk-that-fills-at-once).
- **A log line longer than 102,400 bytes.** The collector does not store
  it. Cowrie under QPot no longer writes one: it cuts the long values of
  such a line and records each one's full length and SHA-256. For any other
  honeypot, and for the stock Cowrie arm of the comparison, the collector
  stores a `<honeypot>.log.line_discarded` event with the first thousand
  bytes or so of the line; the rest of the line is in the honeypot's own
  log until cleanup empties it, and nowhere else. That event is the
  collector's own report and is not read from a log: one that had not
  reached the database when the collector was killed is not written again.
- **A log line that reaches the disk in two pieces.** The collector gives
  such a line one identity when it reads it live and another when it reads
  the file again, and the event is then stored twice. Cowrie under QPot no
  longer writes a line that way, and no honeypot whose log has room did so
  in the full-disk test. One without room can, on a full disk; it shows
  only if the collector later loses its place (`collector-amnesia`) or the
  logs are restored.
- **HiFi SSH session capture during a long control-plane outage.** HiFi
  sessions are recorded on each backend's container log and converted by
  the control plane. When the control plane stops, the broker turns new
  visitors away after 30 seconds, but sessions already open continue. The
  third round measured 2 h 15 min with a session open, and outages in which
  one visitor ran commands until sshd ended the connection: nothing lost,
  nothing stored twice. What bounds it is the backend's container log (five
  files of 64 MiB for a cell, four of them always whole). One source's
  three connections fit in it; more connections into one cell that each
  use their 64 MiB within one outage push the oldest unconverted records
  out before anyone reads them, and that was not run. A command past a
  cell's capture limits keeps
  the first 4 kB of its input and output, not all of it
  ([ssh-hifi-proxy.md](ssh-hifi-proxy.md) states the bounds).
- **Rows sent again stay for a few minutes.** When the collector loses its
  place it sends every log again. Those rows carry the identities they
  already had and the worker removes them, ahead of what it still has to
  classify: in the database benchmark 202,000 such rows at 25 million
  events were gone 147 seconds after they were stored (33 minutes before
  this change; 47 minutes for 213,000 in the third round's soak). Until
  then a list of events shows them twice; indicators and sessions count
  them once. The worker finds the first of them in its next pass
  (`worker_interval`, 5 minutes by default; one minute in the benchmark) and
  from then on looks for more before every batch.
  On TimescaleDB they are removed in time order, as before.
- **A large database.** Measured to 25 million events on ClickHouse with
  one sensor. Past that, and with many sensors or many addresses at once,
  nothing here is measured. Classification is bounded by the database's one
  CPU: 226 events a second at 25 million events and 436 at 1 million in
  the benchmark; traffic above that is stored at once and classified late.
  At 25 million the dashboard's slowest calls (95th percentile) take 1.3 to
  1.7 times as long as with 1.1.2's tagging, at the same median.
- **One long HiFi channel.** Past 8 MiB one channel's bytes are carried but
  not kept, and its record says so. In an interactive session that includes
  what is typed after that point.
- **The database itself.** QPot keeps one copy. The log backups under
  `backup/logs/` hold every event as JSON and are the second copy;
  `qpot db restore` rebuilds the database from them, with the limits the
  rehearsal above measured.
- **Many sources.** See the note on Docker's port proxy above. Events whose
  source address is one of the instance's own Docker networks are now
  marked, and intelligence no longer treats them as one visitor
  ([release.md](release.md) says which setups are affected).
- **TimescaleDB.** Both soaks measure a ClickHouse instance. For
  TimescaleDB the duplicate check, the removal of second copies, the
  restore and the collector's delivery of hostile lines are covered by
  integration tests against the pinned image in CI, and three faults were
  run once each on a live instance (fourth round). It has not been soaked.
- **Deception against real attackers.** Nothing on this page says whether
  QPot's Cowrie holds real visitors longer than the stock image. The
  controlled comparison that would is described in
  [effectiveness.md](effectiveness.md). Its procedure was carried out in a
  lab with harmless sessions, two arms that differ only in the deception
  layer; the comparison itself has not been run.

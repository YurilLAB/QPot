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

The test fails if a command that ran in a cell is not in the database, if
one is stored twice, if a login is taken late, or if a long stay is still
being served after 2,100 commands.

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

Two minutes is what was measured. An outage of hours with a session open
all the while is bounded by the cell's container log (five files of 64 MiB)
and by the cell's two-hour life, not by anything this soak ran.

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

## Where the promise ends

- **Before the honeypot logs it.** A connection the honeypot never took, or
  took and was killed before writing its log line, is not evidence QPot
  ever had. The soak reports these as refused, or as lost during a
  `honeypot-` fault.
- **A disk that fills in one step.** The disk guard closes the honeypots
  when free space runs low, and then nothing is lost. A disk that goes from
  enough to nothing within the guard's five-second check still costs what
  the honeypot took before it was stopped: 2 to 15 connections per episode
  in the soak. Nothing the honeypot wrote was lost, and nothing was stored
  twice.
- **HiFi SSH session capture during a long control-plane outage.** HiFi
  sessions are recorded on each backend's container log and converted by
  the control plane. When the control plane stops, the broker turns new
  visitors away after 30 seconds, but sessions already open continue. The
  soak measured two-minute outages with a session open: nothing lost. Over
  hours, a visitor that keeps writing can push its own oldest unconverted
  records out of its backend's bounded log, and can pass the cell's capture
  limits with nobody there to stop the cell
  ([ssh-hifi-proxy.md](ssh-hifi-proxy.md) states the bounds).
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
  TimescaleDB the duplicate check, the removal of second copies and the
  restore are covered by integration tests against a real server, not by a
  soak.
- **Deception against real attackers.** Nothing on this page says whether
  QPot's Cowrie holds real visitors longer than the stock image. The
  controlled comparison that would is described in
  [effectiveness.md](effectiveness.md) and has not been run.

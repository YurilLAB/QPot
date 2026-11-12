# Disk cleanup

Events go to the database, which keeps them for its own retention period.
Everything else an instance writes stays on disk until something removes it:

- each honeypot's logs, which the collector reads;
- what attackers left: downloads, session recordings, uploads and payloads;
- the collector's backup copy of every event, one folder per day.

A busy honeypot fills a disk with these. `qpot serve` therefore cleans up two
minutes after it starts and every hour after that. The Overview tab shows the
last run and the settings, and `qpot cleanup` runs it by hand.

If the disk still gets nearly full, the [disk guard](#disk-guard) stops the
honeypots until there is room again.

## What a run does

For each honeypot's folder (`<instance>/honeypots/<name>`):

1. **Old files go.** Captured files and rotated logs older than
   `max_age_days` are deleted. A log the collector reads is never deleted,
   however old: a honeypot can hold it open, and would go on writing to a
   file the collector can no longer find.
2. **Large logs are emptied once delivered.** A log the collector reads that
   is larger than `max_log_mb` is emptied, in place, only when both hold:
   - the collector runs;
   - the collector has delivered the whole log to the database and the
     backup. It records how far it has delivered each log (see below), and
     cleanup checks that mark against the log's size, then empties it on the
     same open file.

   Emptying keeps the file, so the honeypot goes on writing to it, and the
   collector reads the new lines from the start. A log still holding lines
   the collector has not delivered, because the database is away or the
   collector is behind, waits for a later run. The run says so.
3. **The folder is kept under its storage limit.** A folder above its limit
   loses its oldest captured files and rotated logs first. If that is not
   enough, its largest delivered logs are emptied as in step 2. The folder is
   pruned to 90% of the limit so the next run does not start at it again. A
   honeypot's state and settings are never touched; a folder that is still
   above its limit is reported.

### How cleanup knows a log is delivered

The collector (Vector) keeps a checkpoint per log in the instance's
`collector` folder. Its database and backup sinks acknowledge what they have
stored, and a checkpoint moves only after that, so a log whose checkpoint is
at its end holds nothing the database lacks. Cleanup finds a log's checkpoint
by the collector's own fingerprint of it, the checksum of its first line. Two
logs with the same first line look like one log to the collector, so neither
is emptied.

The size check and the emptying happen back to back on one file handle:
microseconds apart, or a few milliseconds when the helper container below
does it. A line the honeypot writes in exactly that gap would be lost, as with
`copytruncate`. A log is only ever emptied after it has gone quiet long enough
for the collector to deliver and checkpoint its end.

The limit is `security.resource_limits.max_storage_gb` (10 GB by default), or
the honeypot's own `resources.max_storage_gb` when it sets one.

The collector's backup folder (`<instance>/backup/logs/YYYY/MM/DD`) loses its
days older than `max_age_days`, then its oldest days while it is above
`max_backup_mb`. The current day, which the collector is still writing, is
never removed.

The captured files are, per honeypot:

| Honeypot | Folders |
|---|---|
| cowrie | `dl` (downloads), `logs/tty` (session recordings) |
| adbhoney | `dl` (pushed files) |
| dionaea | `data/binaries`, `data/bistreams`, `data/rtp`, `data/roots/ftp`, `data/roots/tftp` |
| tanner | `files` |
| h0neytr4p, log4pot | `payloads` |
| miniprint | `uploads` (print jobs) |

Keep a sample beyond `max_age_days` by copying it somewhere else first.

## Settings

```yaml
cleanup:
  enabled: true        # the hourly run; unset means on
  max_age_days: 30     # captured files, rotated logs and backup days
  max_log_mb: 256      # empty a collected log above this
  max_backup_mb: 2048  # the collector's backup folder
```

The Overview tab's **Disk cleanup** card changes the same settings. They apply
from the next run, without a restart. A manual run (the card's **Clean up
now**, or `qpot cleanup`) also works while the hourly run is off.

## Disk guard

Cleanup keeps the instance's own files small. It cannot stop a disk from
filling up for another reason: the database grows, or another program writes
to the same disk.

A honeypot on a full disk is worse than a stopped one. It still accepts
connections, but it cannot write its log. What attackers do in that time is
recorded nowhere. So a honeypot that cannot record must not accept.

`qpot serve` therefore watches the free space of the disk that holds the
instance's data folder. It reads the free space every second and acts the
moment it falls below `min_free_mb`.

1. **Below `min_free_mb` (512 MB): cleanup first.** The guard runs the cleanup
   described above once and looks at the disk again. It waits at most one
   minute for it. If automatic cleanup is off (`enabled: false`), this step
   removes nothing.
2. **Still below: the honeypots stop.** The guard stops every honeypot that
   runs. A stopped honeypot's port is closed, so nobody can connect. The
   database, the collector, the egress guard and `qpot serve` keep running,
   so events already written are still stored.
3. **While the disk stays below `min_free_mb`**, a honeypot that someone
   starts again is stopped again within seconds. Cleanup is tried again every
   10 minutes.
4. **At `resume_free_mb` (1024 MB) or more: the honeypots start.** The guard
   starts the honeypots it stopped, and only those. They go through the same
   checks as any other start.

**When the disk is almost completely full** (less than a quarter of
`min_free_mb` free, 128 MB by default), steps 1 and 2 change places: the
honeypots stop first and cleanup runs afterwards. At that point a honeypot
can no longer write its log, and a minute of cleanup would be a minute of
connections recorded nowhere.

### A disk that fills at once

A disk can go from enough to nothing between two looks, for example when
another program writes a large file. Four things keep that from costing
events:

- **The watch.** One second is the longest a full disk goes unnoticed.
- **Cowrie holds what it could not write.** On a full disk the Cowrie image
  loses events while it goes on serving: its log write fails and the event
  is dropped, or (with the rotating log file) a line is cut short. QPot's
  Cowrie keeps such events in memory (up to 100,000 events or 64 MB) and
  writes them in order when there is room again. A line the disk took only
  part of is ended where it broke and written again whole: the collector
  drops the piece, which is not JSON, and never sees a line arrive in two
  parts (it would give that line another identity than when it reads the
  file again, and the event would be stored twice). In a test on a 256 kB filesystem that was filled and freed,
  the image's own code kept 62 of 261 events with the rotating log file and
  raised an error for 197 of them with the plain one; QPot's kept all 261
  with either.
- **The reserve.** The guard keeps a file of `reserve_mb` (64 MB) on the
  same disk, named `.disk-guard-reserve` in `<instance>/honeypots`, and
  deletes it when the disk is full, so that what Cowrie holds can be
  written. It waits for the disk to be full and to have stopped filling
  (under 16 MB free on two looks 150 ms apart, the second no lower): room
  freed while something is still filling the disk is filled with the rest.
  The guard watches for that moment while it runs cleanup and stops the
  honeypots, which is when it comes. Once the honeypots are stopped it frees
  the reserve in any case, for the collector and the database, which still
  have to store what was logged. It writes the file again when the honeypots
  run and there is room for it above `resume_free_mb`.
- **Cowrie's own spare file.** The freed reserve is anybody's: the database
  can take it before Cowrie does. So Cowrie also keeps one megabyte of its
  own, `qpot-jsonlog.spill` in its `etc` folder, written in full when it
  starts. A Cowrie that is stopped while events still wait gives the disk
  two seconds and then writes them into that file, which needs no new disk
  space. The next start puts them into the log before anything new.

The first version of this (in the tree before 2026-11-12, never released)
freed the reserve as soon as the disk was low, and did not have the spare
file. The failure soak filled the disk at once 14 times against it and lost
4 connections of 7,276: each time the guard had seen 120 to 170 MB left,
freed 64 more, and the writer took them too; Cowrie was stopped a second
later with two to five events it could not write. See
[reliability.md](reliability.md#abrupt-disk-exhaustion).

What can still be lost: events of a Cowrie that is killed instead of stopped
while it holds events (they are in memory only), more than a megabyte of
them at one stop, and events on a filesystem that needs new space to
overwrite a file (btrfs, ZFS). The other honeypots run T-Pot's images
unchanged: what they cannot write while the disk is full is lost, for the
second or so until they are stopped. Cowrie run as the comparison arm
(`deception=stock`) behaves like the image.

Between the two marks nothing changes. A disk that moves up and down around
one mark does not stop and start the honeypots in turn.

### What the guard starts again

The guard writes the honeypots it stopped to `disk-guard.json` in the
instance's data folder. A restarted `qpot serve` reads the file and starts
exactly those when there is room.

It never starts a honeypot that it did not stop:

- A honeypot you stopped or turned off before the guard acted is not in the
  file.
- A honeypot you turn off while the guard holds it stays stopped.
- A honeypot that someone starts again between the two marks is taken off the
  list. If you stop it afterwards, it stays stopped.
- If the file is damaged, the guard ignores it and starts nothing because of
  it.
- If the whole instance is down when there is room again, the guard starts
  nothing. The next `qpot up` starts everything.

If a honeypot does not start, the guard tries again later: after 1 minute,
then 2, 4 and 8, then every 10 minutes.

### `qpot up`

`qpot up` does not start containers while the disk is below `min_free_mb`. It
ends with error `QP-RES-008` and says how much space is free. Free some space
and run it again. It only checks `min_free_mb`, not `resume_free_mb`: you
asked for the start yourself.

An instance whose containers all run already is not refused. `qpot up` then
only starts the control plane, and its guard does the rest.

### Seeing what the guard does

- `qpot doctor` has a `disk guard` line. It shows the free space and the
  honeypots the guard keeps stopped. A honeypot the guard stopped is reported
  with `QP-RES-008`.
- `GET /api/status` has a `disk_guard` field:

  ```json
  "disk_guard": {
    "state": "low",
    "free_bytes": 104857600,
    "min_free_bytes": 536870912,
    "resume_free_bytes": 1073741824,
    "reserve_bytes": 0,
    "stopped": [{"name": "cowrie", "stopped_at": "2026-11-12T10:00:05Z"}],
    "code": "QP-RES-008",
    "checked_at": "2026-11-12T10:00:10Z"
  }
  ```

  `state` is one of:

  | State | Meaning |
  |---|---|
  | `ok` | There is room. The guard holds nothing. |
  | `low` | The disk is below `min_free_mb`. Honeypots are kept stopped. |
  | `waiting` | The disk is back above `min_free_mb`. The honeypots in `stopped` start at `resume_free_mb`. |
  | `off` | The guard is turned off. |
  | `unknown` | The free space cannot be read. `free_bytes` is `null`. The guard does nothing. |

  `code` is only there while the state is `low` or `stopped` is not empty.
  `reserve_bytes` is the size of the reserve file the guard holds now: 0
  when it keeps none or has freed it.
- The log of `qpot serve` has a warning for every honeypot the guard stops
  and for every one it starts again.

### Settings

```yaml
cleanup:
  min_free_mb: 512      # stop the honeypots below this much free space; 0 turns the guard off
  resume_free_mb: 1024  # start them again at this much; must be greater than min_free_mb
  reserve_mb: 64        # the file the guard frees when the disk is full; 0 keeps none; must be less than min_free_mb
```

All three are in MB. They apply within seconds, without a restart. The guard
works whether the hourly cleanup (`enabled`) is on or off.

A config file written before the guard existed has none of these keys. The
guard is then on with 512 and 1024 and keeps a reserve of 64 MB. If you set
only `min_free_mb`, `resume_free_mb` is 1024, or twice `min_free_mb` when that
is more, and the reserve is 64 MB, or half of `min_free_mb` when that is less.
The reserve is extra: it is not part of the free space the two marks count.

A `resume_free_mb` that is not greater than `min_free_mb` is a mistake. QPot
then refuses to read the config file and names the two values.

### Limits

- The guard is part of `qpot serve`. If `qpot serve` does not run, nothing
  stops the honeypots. `qpot up` still refuses to start them on a full disk.
- The guard reads one disk: the one that holds `<instance>/honeypots`. It does
  not see a database kept on another disk.
- Honeypots are stopped one after another. Each stop can take up to about 10
  seconds, so an instance with many honeypots needs a few minutes.
- The guard needs Docker to answer. While Docker does not, it changes nothing
  and logs an error.

## Safety

A compromised honeypot controls what is in its folders. Cleanup never follows
a symlink: it skips links while listing, and it removes or empties a file only
from inside the folder the container itself mounts (`dl`, `logs`, `data` and so
on). A folder the honeypot swaps for a link after the listing therefore leads
nowhere outside that mount, so cleanup never changes anything the honeypot
could not change itself. A log is emptied only when the file opened is the
regular file that was listed.

On Linux, files a container's own user wrote can belong to another user than
QPot. When QPot may not remove or empty one of them, a short-lived helper
container does it. The helper runs from the collector's image with no network,
a read-only root and only the two capabilities that let it change another
user's files. It mounts only that same folder (or the backup folder), so a
planted symlink leads within it or into the helper's own throwaway filesystem,
never anywhere else on the host. It empties a log only if the log still holds
no more than the collector has delivered.

## `qpot cleanup`

```text
qpot cleanup [-i instance] [--dry-run]
```

Runs cleanup once and prints, per folder, its size, limit and what was freed.
`--dry-run` only says what it would do. The command exits non-zero when
something could not be removed.

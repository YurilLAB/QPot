# Disk cleanup

Events go to the database, which keeps them for its own retention period.
Everything else an instance writes stays on disk until something removes it:

- each honeypot's logs, which the collector reads;
- what attackers left: downloads, session recordings, uploads and payloads;
- the collector's backup copy of every event, one folder per day.

A busy honeypot fills a disk with these. `qpot serve` therefore cleans up two
minutes after it starts and every hour after that. The Overview tab shows the
last run and the settings, and `qpot cleanup` runs it by hand.

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

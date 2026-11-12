# Releases: supported deployments, upgrade, rollback and rebuilding

- [Supported deployments](#supported-deployments)
- [What a release contains](#what-a-release-contains)
- [Upgrading](#upgrading)
- [Rolling back](#rolling-back)
- [Rebuilding a release yourself](#rebuilding-a-release-yourself)
- [Cutting a release](#cutting-a-release)

## Supported deployments

Each row says how it is known to work. "CI" means every push runs it.
"By hand" means it was run and checked on the date given, and is not
repeated automatically. "Expected" means QPot is built for it and nothing is
known to break, but nobody has run it end to end. Please report results for
"expected" rows.

### Host

| Host | Status | Notes |
|---|---|---|
| Linux x86-64, Docker Engine, cgroup v2 | **CI** | Ubuntu (GitHub's `ubuntu-latest`): the whole stack is started, attacked and checked. |
| Linux x86-64, other distributions | **CI** for the program, **expected** for the stack | The program is run inside Alpine 3.20, Debian 12, Ubuntu 22.04, Fedora 40, Rocky 9 and openSUSE Leap 15.6. `qpot setup` installs Docker on Debian, Ubuntu, Raspberry Pi OS, Fedora, CentOS Stream, Rocky, AlmaLinux, RHEL, openSUSE and Arch; its plans are unit-tested, not run on each. |
| Debian-family Linux under WSL2 | **By hand**, 2026-11-11 | Docker Engine 26.1.5; the upgrade rehearsal and the failure soak ran here. |
| Linux arm64, arm | **Expected** | Cross-compiled in CI, never run. The T-Pot honeypot images are multi-architecture. |
| Windows 11 with Docker Desktop | **By hand**, 2026-11-11 | Docker Desktop 4.99, `sandbox_mode: none`. CI runs the installer and the Windows-specific tests on Windows; the full test suite is run there by hand before a release. For trying QPot out, not for collecting: see "Source addresses" below. |
| macOS with Docker Desktop | **Expected** | Built in CI, never run. The same limit on source addresses applies. |
| Podman | **Not supported** | Refused with QP-DOCKER-004. |
| Docker Engine older than 20.10, Compose v1 | **Not supported** | Refused by setup and doctor. |

### Source addresses

A honeypot can only record who connected if the connection reaches it with
the visitor's address. That depends on how Docker forwards the port.

| Docker | Honeypots see | Status |
|---|---|---|
| Docker Engine on Linux, default settings | The visitor's address | **Supported** for collecting |
| The same, for connections made from the host itself | Docker's address | Expected: your own tests look like one visitor |
| Docker Desktop (Windows, macOS) | Docker's address for every visitor | **Not supported** for collecting |
| Rootless Docker, or a daemon with `iptables: false` | Docker's address for every visitor | **Not supported** for collecting |
| A reverse proxy or source NAT in front of the honeypot ports | The proxy's address | **Not supported** for collecting |

Where honeypots see Docker's address, QPot marks the events, does not
attribute them to a source, and keeps connections apart by the honeypot's
own session IDs. Everything else works. `qpot doctor` reports the share of
marked events as "source addresses" (QP-NET-015).

### Container runtime

| `security.sandbox_mode` | Status | Notes |
|---|---|---|
| `gvisor` (default) | **By hand**, 2026-11-10 | runsc on Docker Engine, four honeypots, banners compared with the standard runtime. Linux only. |
| `none` (Docker's standard runtime) | **CI** | The only choice on Docker Desktop. See [security.md](security.md) for what it gives up. |
| `kata` | **Expected** | Never run: it needs KVM, which neither CI nor the test host has. |
| cgroup v1 hosts, rootless Docker | **Expected** for emulators only | Honeypots other than cowrie, conpot and refrigeration need Docker to confirm CPU, memory, swap and PID limits (QP-RES-007); such hosts often cannot. |

### Database

| `database.type` | Status | Notes |
|---|---|---|
| `clickhouse` (default) | **CI**, and the soak | Image pinned by digest. |
| `timescaledb` | **CI**, and **by hand** 2026-11-12 | Schema, ingest view and worker lease are tested against the pinned image. Storing a repeated batch once, removing a line read twice, and restoring from backups were run by hand on a real hypertable. The soak has not been run on it. |
| `elasticsearch` | **Legacy** | A client for an existing cluster. QPot does not run one, and the collector does not write to it. |

### Honeypots

All 28 are rendered together and checked in CI. Cowrie, conpot,
refrigeration, the HiFi SSH proxy and the collector's handling of every
honeypot's log format run against real images in CI. The others start from
T-Pot's unchanged images; their behaviour is T-Pot's.

## What a release contains

- `qpot_<version>_<os>_<arch>.tar.gz` (`.zip` for Windows) for linux/amd64,
  linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64: the `qpot`
  program, `LICENSE` and `README.md`.
- `SHA256SUMS`, and a signed build-provenance attestation
  (`qpot_<version>_provenance.sigstore.json`).
- The HiFi images `ghcr.io/yurillab/qpot-ssh-proxy` and
  `qpot-ssh-backend`, tagged with the release's full commit hash. A release
  program uses exactly those.

The installers check all of it before installing; see
[installation.md](installation.md#how-the-installers-check-downloads).

## Upgrading

An upgrade replaces the `qpot` program and restarts each instance. The
honeypots are down for the restart, usually under two minutes. Events are
not lost across it: the collector reads on from its checkpoint.

1. **Check the instance is healthy first**, so a later problem is the
   upgrade's: `qpot doctor -i <name>`.
2. **Stop it:** `qpot down -i <name>`.
3. **Back up the instance folder** while it is stopped. It holds everything:
   settings, the QPot ID, the database, the honeypots' identities and logs,
   the collector's checkpoints.

   ```bash
   sudo tar --numeric-owner -czf <name>-backup.tgz -C ~/.qpot/instances <name>
   ```

   `sudo` and `--numeric-owner` matter: the database's and the honeypots'
   files belong to their containers' users. With the HiFi profile, also back
   up its private SSH runtime store
   ([ssh-hifi-proxy.md](ssh-hifi-proxy.md#persistent-runtime-storage-and-upgrades)).
   Keep the old program too: `cp "$(command -v qpot)" qpot-<old version>`.
4. **Install the new program**, with the installer or by unpacking a
   release archive over the old one.
5. **Start the instance:** `qpot up -d -i <name>`. This regenerates the
   Compose file and the collector configuration and recreates the
   containers whose settings changed.
6. **Check:** `qpot doctor -i <name>`. Every line should be `ok`.

Read the release notes for anything a version asks of you. From 1.0.1 or
earlier, see ["The QPot ID and the sensor ID"](security.md#the-qpot-id-and-the-sensor-id):
the first start rewrites old log backups.

What changes shape between versions, and in which direction it is safe:

| State | Forward (upgrade) | Backward (old program on new state) |
|---|---|---|
| `config.yaml` | Old files load. New settings get safe defaults. | Unknown settings are ignored. |
| Database tables | Created or extended at start; never dropped. The events table gets an index on the event ID (ClickHouse) or an event ID column, a unique index and an insert trigger (TimescaleDB). ClickHouse also gets a table of the IDs of classified events (`classified_event_ids`); for a database an earlier version filled, the worker copies them in the background at its first batch and reads the events table until that is done. | Extra tables, columns and indexes are ignored. |
| Event IDs | Events stored by 1.0.1 or earlier keep the random ID they have. New events get an ID derived from their log line. Only new IDs are used to find a line stored twice. | Readable. |
| Intelligence checkpoint (in the database) | Older formats are read and carried until their sessions end. | **Not readable** when its format number is newer: the old worker reports an error and does not classify. |
| Collector checkpoints | Kept. 1.0.1 and earlier kept none in the instance: at the first start every log found is marked as collected up to its end, so nothing is sent twice. | Kept. |
| Log backups | 1.0.1 and earlier: rewritten once to remove the QPot ID. | Readable. |

## Rolling back

Because the intelligence checkpoint cannot be read by an older program,
rolling back means restoring the backup, not only the old program.

1. `qpot down -i <name>` with the new program.
2. Put the old program back.
3. Restore the folder:

   ```bash
   sudo rm -rf ~/.qpot/instances/<name>
   sudo tar --numeric-owner -xzf <name>-backup.tgz -C ~/.qpot/instances
   ```

4. `qpot up -d -i <name>`, then `qpot doctor -i <name>`.

Events captured between the upgrade and the rollback are not in the
restored database. To keep them, copy `backup/logs/` out of the instance
folder before step 3: it holds every event as one JSON object per line.

This procedure is rehearsed on real Docker before a release: an instance on
the previous version is attacked, backed up, upgraded, attacked, rolled
back and attacked again, and the database must hold every connection
exactly once at each stage. The last rehearsal is recorded in
[reliability.md](reliability.md#upgrade-and-rollback-rehearsal).

## Rebuilding the database from log backups

Use this when the database is lost or damaged and there is no backup of the
instance folder to restore: a deleted or corrupted database volume, a disk
that failed under it, a database emptied by mistake.

The collector writes every event twice: to the database, and as one JSON
object per line to `backup/logs/YYYY/MM/DD/<honeypot>.log` in the instance
folder. `qpot db restore` puts those lines back into the database.

1. **Stop the instance:** `qpot down -i <name>`.
2. **If the database is damaged, move it away** (keep it until the restore
   has been checked):

   ```bash
   sudo mv ~/.qpot/instances/<name>/db ~/.qpot/instances/<name>/db.damaged
   ```
3. **Start the instance:** `qpot up -d -i <name>`. It creates an empty
   database. The honeypots collect again from here on.
4. **See what the backups hold:** `qpot db restore -i <name> --dry-run`.
5. **Restore:** `qpot db restore -i <name>`. It prints one line per backup
   file. It can be stopped and run again; what is stored is skipped. Because
   the collector has been storing new events since step 3, the database is
   no longer empty when you run it a second time: add `--merge` then.
6. **Wait for classification.** The control plane classifies the restored
   events in the background, oldest first, and rebuilds indicators and
   sessions. `qpot overview -i <name>` shows the counts grow.

What comes back, and what does not:

| | |
|---|---|
| Events | Every event of the days the backups hold, with its original time and ID. |
| Indicators, sessions, ATT&CK tags | Rebuilt by classifying the restored events. Sessions are rebuilt in one pass, so a session that was split by a quiet period before may be joined differently. |
| Canary trips | Found again when a restored event carries a planted value. Alerts and hooks for them fire again. |
| Days older than the backups | Gone. Disk cleanup removes backup days by age (`cleanup.max_age_days`) and when the backup folder exceeds `cleanup.max_backup_mb` (2 GB by default). Raise both if the backups are your only second copy. |
| Captured files, TTY recordings | Not in the database: they stay in the honeypots' folders. |

The same command fills gaps. If events are missing from a database that is
otherwise intact (for example the ones captured between an upgrade and a
rollback), run `qpot db restore -i <name> --merge --from <folder of copied
backups>`. Only the missing events are added.

The last rehearsal is recorded in
[reliability.md](reliability.md#database-restore-rehearsal).

## Rebuilding a release yourself

Release archives are reproducible: the same commit and the same Go version
give byte-identical files on any host. Everything time-dependent in them
(file times in the archive, the build date in the program) is the commit's
own time.

```bash
git clone https://github.com/YurilLAB/QPot.git && cd QPot
git checkout v<version>
go run ./cmd/qpot-release pack -version <version> -out /tmp/qpot-dist
# compare with the published list
curl -fsSL -o /tmp/SHA256SUMS https://github.com/YurilLAB/QPot/releases/download/v<version>/SHA256SUMS
diff <(sort /tmp/SHA256SUMS) <(sort /tmp/qpot-dist/SHA256SUMS) && echo identical
```

Go downloads the toolchain version named in `go.mod` by itself. `pack`
refuses to build a tree that is not exactly the commit: a modified tracked
file would otherwise be built and labelled with that commit.

**Releases 1.0.0 and 1.0.1** need one more thing. They were packed into
`dist/` inside the repository, and Go recorded "this tree has uncommitted
files" in every program built after the first, because the output folder
itself was such a file. So `go version -m` shows `vcs.modified=true` for
four of their five programs, and they reproduce only with the same output
folder:

```bash
go run ./cmd/qpot-release pack -version 1.0.1 -out dist
```

That was checked on 2026-11-11: 1.0.1 rebuilt from its tag on Windows 11 and
on Linux gave the published `SHA256SUMS` exactly. Later releases build with
`-buildvcs=false` and do not depend on where the output goes: 1.1.2,
rebuilt from its tag on Windows 11 on 2026-11-12 into a folder outside the
repository, gave the published `SHA256SUMS` exactly.

## Cutting a release

1. Set the version in `scripts/install.sh`, `scripts/install.ps1`
   (`QPOT_VERSION`) and the `Makefile` (`VERSION`).
2. Run the whole CI locally (`scripts/ci-local.sh`) and the HiFi gate
   (`scripts/test-hifi.sh`).
3. Run the upgrade and rollback rehearsal and a failure soak of at least a
   few hours ([reliability.md](reliability.md)); record both.
4. Tag `v<version>` on a commit whose CI, image and CodeQL workflows are
   green, and push the tag. `.github/workflows/release.yml` refuses a tag
   that does not match step 1, builds, attests, verifies and publishes.
5. Rebuild the tag on another machine and compare `SHA256SUMS`, as above.
6. Set `QPOT_SOURCE_COMMIT_PINNED` in both installers to the tag's commit.

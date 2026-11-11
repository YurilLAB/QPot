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
| Windows 11 with Docker Desktop | **By hand**, 2026-11-11 | Docker Desktop 4.99, `sandbox_mode: none`. CI runs the installer and the Windows-specific tests on Windows; the full test suite is run there by hand before a release. |
| macOS with Docker Desktop | **Expected** | Built in CI, never run. |
| Podman | **Not supported** | Refused with QP-DOCKER-004. |
| Docker Engine older than 20.10, Compose v1 | **Not supported** | Refused by setup and doctor. |

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
| `timescaledb` | **CI** | Schema, ingest view and worker lease are tested against the pinned image; the soak has not been run on it. |
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
| Database tables | Created or extended at start; never dropped. | Extra tables and columns are ignored. |
| Intelligence checkpoint (in the database) | Older formats are read and carried until their sessions end. | **Not readable** when its format number is newer: the old worker reports an error and does not classify. |
| Collector checkpoints | Kept. | Kept. |
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
`-buildvcs=false` and do not depend on where the output goes.

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

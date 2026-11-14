# Development

QPot is written in Go 1.26. The honeypots themselves are T-Pot's upstream
images; the code here builds the stack around them. [architecture.md](architecture.md)
explains how the parts fit together.

## Building and testing

```bash
make build      # build ./qpot
make test       # unit tests
make ci         # format, vet, lint, tests and security checks
make build-all  # cross-compile for every supported platform
```

`scripts/ci-local.sh` runs the same checks GitHub's CI runs, from the same
pinned tool versions in `.github/ci-tools.env`, so a change can be checked
before it is pushed.

## Continuous integration

Every push runs:

- **Build and test:** build, gofmt, go vet, staticcheck and the race-enabled
  test suite.
- **Fuzzing:** a smoke run of every fuzz target.
- **Security:** govulncheck, gosec and gitleaks.
- **Database:** integration tests against a real ClickHouse.
- **Industrial protocols:** actual Conpot PLC/RTU/Beckhoff clients, read/write
  operations, fragmented/coalesced Modbus frames, errors and persistent identity
  across restart/recreation, on isolated
  containers without host ports.
- **Smoke tests:** the CLI on a matrix of Linux distributions, and the Windows
  installer against a local fake release.
- **Lint:** the shell scripts and the workflows.
- **Builds:** cross-compiles for Linux, macOS and Windows.

Changes to the HiFi broker or the egress guard also rebuild and publish their
container images.

Run the native refrigeration acceptance checks with Docker. They build from
the same embedded sources an installed QPot binary emits; no unpublished
registry image or host compiler is required for deployment:

```bash
QPOT_TEST_REFRIGERATION=1 go test -race -count=1 -timeout 12m ./internal/instance -run '^TestRefrigerationLive'
```

The shared Dockerfile is `internal/refrigeration/Dockerfile`; it uses a pinned
official Go builder, an offline standard-library build and a nonroot scratch
runtime. Do not duplicate emulator code into a second build context.

Run the industrial protocol checks locally after pulling the versioned image:

```bash
docker pull ghcr.io/telekom-security/conpot:24.04.2@sha256:be17a238709c78909c7d2e0da55bc3ea66dc3aa46618f0d89b7080f3e7dda3e8
QPOT_TEST_CONPOT=1 go test -race -count=1 -timeout 8m ./internal/instance -run '^TestConpotLive(Profiles|AcceptLoop)$'
```

The image reference includes the reviewed multi-architecture index digest;
mutable tag contents cannot silently replace the modules the patches target.
Readiness checks poll listeners/bootstrap only. Each full protocol assertion
script runs once per startup/restart/recreation, so a failed assertion is not
hidden by repeating the whole script until it passes.

The TimescaleDB checks need the pinned database image on a loopback port and
the collector image; `scripts/ci-local.sh --only timescaledb-integration`
starts both and runs what CI runs: every PostgreSQL test of the database
package, and hostile log lines through the real collector into the production
schema. By hand, against a server of your own:

```bash
QPOT_TEST_POSTGRES=1 QPOT_TEST_TIMESCALE=1 QPOT_TEST_PG_PORT=15433 \
    go test -race -p 1 -count=1 ./internal/database ./internal/instance -run '^(TestPG|TestTimescale)'
```

The tests drop and recreate the `events` table of the database they are given.

Ordinary unit runs skip this opt-in test. A requested run fails if Docker or the
image is unavailable. `scripts/ci-local.sh --only conpot-integration` runs the
same image pull and tests as CI. These checks validate isolated protocol
endpoints; a full deployment also needs a host that supports the egress guard.

## Releases

Pushing a version tag such as `v0.1.0` runs `.github/workflows/release.yml`,
which:

1. refuses a tag that is not the version the installers download
   (`QPOT_VERSION` in both installers, `VERSION` in the Makefile);
2. builds the archives reproducibly: the same commit and Go version give
   byte-identical files;
3. writes `SHA256SUMS` and a signed build-provenance attestation for every
   archive, using GitHub's keyless artifact attestations;
4. checks that provenance the way the installers do, then publishes the
   release.

To check a download yourself:

```bash
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify qpot_0.1.0_linux_amd64.tar.gz --repo YurilLAB/QPot \
  --signer-workflow YurilLAB/QPot/.github/workflows/release.yml --source-ref refs/tags/v0.1.0
```

After a release, set `QPOT_SOURCE_COMMIT_PINNED` in both installers to the
tag's commit. Until the first release it is a `main` commit that passed CI. A
test checks that both installers pin the same commit from this repository's
history.

## Source layout

The folder layout is described in
[architecture.md](architecture.md#source-layout).

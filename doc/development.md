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
- **Smoke tests:** the CLI on a matrix of Linux distributions, and the Windows
  installer against a local fake release.
- **Lint:** the shell scripts and the workflows.
- **Builds:** cross-compiles for Linux, macOS and Windows.

Changes to the HiFi broker or the egress guard also rebuild and publish their
container images.

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

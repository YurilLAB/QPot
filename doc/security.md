# Security model

A honeypot invites attackers in, so QPot is built to keep them inside the
honeypot and away from your network, your host and your data.

| Area | What QPot does |
|---|---|
| Isolation | Each honeypot on its own bridge network, with a non-overlapping subnet |
| Egress | Honeypots cannot open connections to your LAN, the Docker host, cloud metadata (`169.254.169.254`, the Azure WireServer) or any other private, loopback, link-local, CGNAT or multicast address. Replies to attackers, public destinations and DNS to the host's resolvers still work. |
| Runtime | gVisor or Kata for honeypots when installed |
| Containers | `cap_drop: ALL` with minimal add-backs, read-only root with tmpfs, no privileged containers |
| Limits | CPU, memory, PID and file-descriptor limits per honeypot |
| Secrets | The QPot ID is never given to honeypot containers, written to logs, sent in alerts or cluster traffic, or returned by the API. The database password is random per instance. |
| Exposure | Web UI, API and database bound to `127.0.0.1` by default |
| Web | CSP, `X-Frame-Options: DENY`, `nosniff`, constant-time login checks, the QPot ID accepted only in a header |
| HiFi backends | No outbound network, recreated after every session, read-only host keys |
| Downloads | The installers verify checksums and build provenance before installing anything |

## The egress guard

An nftables guard, the `netguard` service, enforces the egress rules. It runs
on the host network with `NET_ADMIN` only, and honeypots start only after it is
in place.

- It runs where Docker's bridges live: on the host itself on Linux, and in
  Docker Desktop's VM on Windows and macOS.
- Its rules outlive a stopped stack until the next reboot.
- The `netguard` service applies them again whenever it starts. Docker restarts
  it with the honeypots after a reboot.

Two settings change it (see [configuration.md](configuration.md)):

- `block_outbound: true` stops honeypots opening any outbound connection.
- `allow_private_egress: true` switches the guard off. This is not recommended.

## Running a sensor safely

- **Use a dedicated host or VM** for a sensor exposed to the internet, not a
  computer with your personal data.
- **Keep the web UI on `127.0.0.1`** and reach it over an SSH tunnel (see
  [web-ui.md](web-ui.md)). It uses plain HTTP.
- **Watch `qpot doctor`.** It checks every part of the instance.
- **Choose high-interaction honeypots deliberately.** HiFi mode and the LLM
  honeypots carry more risk than the `minimal` profile.

## Release secret scanning and historical keys

CI scans committed changes and the working tree with the pinned upstream
Gitleaks rules, including new files under `docker/`. This separate raw gate
does not use the repository's decoy allowlist, historical fingerprints or
inline exemptions. Its reviewed baseline is commit
`85791219d54574fca5d68c60dbbd474f5dfc195a`; changing that baseline requires a
new review. A missing baseline, scanner or pinned default rules fails the gate.
The release gate also scans the unpacked standalone archives, projecting
executable bytes into text so a binary-file exclusion cannot silently skip
them. Compressed or encrypted content inside an executable is not recursively
decoded. These checks supplement, rather than replace, credential management.

Two real nginx private keys entered the public upstream history in commit
`12842527bbd1d56554a877af83e69fbaf5997fd5` on 2016-07-30, under
`installer/etc/nginx/ssl/` and its `test/` directory. They are absent from the
current source tree. Their matching self-signed certificates expired on
2026-07-27. `.gitleaksignore` acknowledges only those exact historical findings;
they are **known public exposures**, not false positives. A new key, a
reintroduced file or a new commit does not inherit that acknowledgement.

Never deploy or reuse those historical keys. Certificate expiry does not
revoke a private key, and the repository cannot establish whether another
installation reused or rotated a copy. Operators of a legacy installation
that used them must replace its key and certificate and check for reuse.
The acknowledgement does not claim those external installations are safe.

## Semantic analysis before publication

The image and release workflows require completed CodeQL analysis with the
Go bundle and query pack pinned in `.github/ci-tools.env`. Analysis traces the
normal production build without rewriting module files. Missing, malformed or
failed reports and security findings without an exact reviewed disposition
stop publication.

`.github/codeql-reviews.json` records independently reviewed false positives
and intentional decoy behavior. Each entry binds the complete result,
including code flows and fingerprints, to its referenced source and proof
files. A separate catalog binds every non-test Go source path and its contents,
including platform files, plus all `go.mod` and `go.sum` files. New, renamed or
changed catalog inputs invalidate the reviews. Changed proof files also require
review; resolved findings must be removed from the manifest.

To renew a review, run fresh analysis with the pinned producer, inspect each
finding against the current program and its tests, and retain the original
SARIF as evidence. Update only the findings independently validated as false
positives or intentional decoys. Do not disable queries or automatically accept
SARIF suppressions. Tool or query upgrades require fresh analysis and review.
Validate the resulting manifest against the actual reports:

```bash
go run ./internal/cicheck/cirun check-codeql /path/to/sarif .github/codeql-reviews.json
```

The summary retains the reported and reviewed finding counts; reviewed decoy
behavior does not turn a report into a zero-finding scan.

## Reporting a vulnerability

Please don't post details of a security problem in a public issue. Open an
[issue](https://github.com/YurilLAB/QPot/issues) that only asks for a private
contact, and the maintainer will reply with one.

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

## Reporting a vulnerability

Please don't post details of a security problem in a public issue. Open an
[issue](https://github.com/YurilLAB/QPot/issues) that only asks for a private
contact, and the maintainer will reply with one.

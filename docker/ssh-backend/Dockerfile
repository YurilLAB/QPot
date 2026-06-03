# QPot high-interaction SSH backend.
#
# A REAL Debian + OpenSSH server. The attacker's SSH handshake terminates here
# (the broker only splices opaque TCP), so there is no emulated transport to
# fingerprint — this is what closes the Vetterl/Clayton (WOOT '18) single-packet
# fingerprinting gap that every Python-transport honeypot (Cowrie/Kippo, incl.
# Cowrie proxy mode) leaves open.
#
# This container is GENUINE code execution for the attacker. It is only safe
# because the orchestration layer (see doc/ssh-hifi-proxy.md) runs it under a
# stronger isolation runtime (gVisor/Kata), pins it to an EGRESS-LOCKED internal
# network (no outbound — it can never be used to pivot, scan, mine, or DDoS),
# caps its resources, and RESETS it between sessions. Do not run it without
# those controls.
#
# Build context is the repository root:
#   docker build -f docker/ssh-backend/Dockerfile -t ghcr.io/yurillab/qpot-ssh-backend:latest .
FROM debian:12-slim

# Real openssh-server + `script` (util-linux/bsdextrautils) for PTY session
# recording. A small set of ordinary tools makes the box look lived-in without
# providing networking utilities that would aid a pivot if egress ever leaked.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        bsdextrautils \
        util-linux \
        ca-certificates \
        less vim-tiny procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log/ssh-backend \
    && chmod 0750 /var/log/ssh-backend \
    # Host keys are generated/persisted at runtime so the fingerprint is stable
    # across restarts (a key that rotates every restart is itself a tell).
    && rm -f /etc/ssh/ssh_host_*

COPY docker/ssh-backend/files/sshd_config   /etc/ssh/sshd_config
COPY docker/ssh-backend/files/rec-shell.sh  /usr/local/bin/rec-shell
COPY docker/ssh-backend/files/entrypoint.sh /usr/local/bin/entrypoint
RUN chmod 0755 /usr/local/bin/rec-shell /usr/local/bin/entrypoint

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint"]

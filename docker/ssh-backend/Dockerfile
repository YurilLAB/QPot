# QPot high-interaction SSH backend.
#
# A REAL Debian + OpenSSH server. The attacker's SSH handshake terminates here
# (the broker only splices opaque TCP), so there is no emulated transport to
# fingerprint — this is what closes the Vetterl/Clayton (WOOT '18) single-packet
# fingerprinting gap that every Python-transport honeypot (Cowrie/Kippo, incl.
# Cowrie proxy mode) leaves open.
#
# This container is GENUINE code execution for the attacker. The orchestration
# layer (see doc/ssh-hifi-proxy.md) restricts reachable peers to its private cell,
# caps its resources, and RESETS it between sessions. It applies a stronger
# isolation runtime (gVisor/Kata) when available. Deploy on an isolated sensor
# host/VM with appropriate storage bounds; a real shell can still consume its
# allowed resources. Do not run it without those deployment controls.
#
# Build context is the repository root:
#   docker build -f docker/ssh-backend/Dockerfile -t ghcr.io/yurillab/qpot-ssh-backend:latest .
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
# The helper only uses the standard library. A small neutral module avoids
# embedding repository names in the attacker-readable audit binary.
COPY internal/sshbackend ./internal/sshbackend
COPY cmd/qpot-sshbackend/main.go ./cmd/session-audit/main.go
RUN printf 'module session-audit\n\ngo 1.26.0\n' > go.mod \
    && sed -i 's|github.com/qpot/qpot/internal/sshbackend|session-audit/internal/sshbackend|' cmd/session-audit/main.go \
    && CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
       GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
       -o /out/session-audit ./cmd/session-audit

FROM public.ecr.aws/docker/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

# Real openssh-server + `script` (util-linux/bsdextrautils) for PTY session
# recording. Ordinary shell/database clients are genuine; orchestration, rather
# than missing binaries, restricts reachable peers to the selected private cell.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        bsdextrautils \
        util-linux \
        ca-certificates \
        less vim-tiny procps postgresql-client-15 \
    # Retain genuine signed package indexes and one cached optional package.
    # apt-get --no-download install tree updates real dpkg/files while offline.
    && apt-get install -y --download-only --no-install-recommends tree \
    && mkdir -p /run/sshd/bootstrap /var/log/ssh-backend \
    && chmod 0700 /run/sshd/bootstrap \
    && chmod 0750 /var/log/ssh-backend \
    # Host keys are generated/persisted at runtime so the fingerprint is stable
    # across restarts (a key that rotates every restart is itself a tell).
    && rm -f /etc/ssh/ssh_host_*

COPY docker/ssh-backend/files/sshd_config   /etc/ssh/sshd_config
COPY docker/ssh-backend/files/rec-shell.sh  /usr/local/bin/rec-shell
COPY docker/ssh-backend/files/entrypoint.sh /usr/local/bin/entrypoint
COPY --from=build /out/session-audit /usr/local/libexec/session-audit
RUN sed -i '2,${/^[[:space:]]*#/d;}' /usr/local/bin/rec-shell /usr/local/bin/entrypoint \
    && sed -i '/^[[:space:]]*#/d' /etc/ssh/sshd_config \
    && sed -i 's|^SHELL=.*|SHELL=/usr/local/bin/rec-shell|' /etc/default/useradd \
    && printf '/usr/local/bin/rec-shell\n' >> /etc/shells \
    && chmod 0755 /usr/local/bin/rec-shell /usr/local/bin/entrypoint /usr/local/libexec/session-audit

# Keep the complete Debian filesystem in one final layer. This avoids retaining
# repeated full rootfs snapshots on VFS-backed development Docker engines.
FROM scratch
COPY --from=runtime / /
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" SESSION_CONTAINER=1
USER 0:0
WORKDIR /
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint"]

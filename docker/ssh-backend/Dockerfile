# QPot high-interaction SSH backend.
#
# A REAL Debian + OpenSSH server. The attacker's SSH handshake terminates here
# (the broker only splices opaque TCP), so there is no emulated transport to
# fingerprint — this is what closes the Vetterl/Clayton (WOOT '18) single-packet
# fingerprinting gap that every Python-transport honeypot (Cowrie/Kippo, incl.
# Cowrie proxy mode) leaves open.
#
# Sessions are recorded inside sshd itself: Debian's own openssh package, built
# here with one small patch (docker/ssh-backend/openssh) whose privileged
# monitor copies each session's plaintext to the container's output stream.
# Accounts keep /bin/bash; no wrapper, script or log file exists in the guest.
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
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
# The start-up helper only uses the standard library, and deletes itself
# before sshd starts. A small neutral module keeps repository names out of it.
COPY internal/sshbackend ./internal/sshbackend
COPY cmd/qpot-sshbackend/main.go ./cmd/session-audit/main.go
RUN printf 'module session-audit\n\ngo 1.26.0\n' > go.mod \
    && sed -i 's|github.com/qpot/qpot/internal/sshbackend|session-audit/internal/sshbackend|' cmd/session-audit/main.go \
    && CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off \
       GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
       go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
       -o /out/session-audit ./cmd/session-audit

# Debian's openssh source, built the way Debian builds it, plus the capture
# patch. The packages keep Debian's version, so dpkg and apt see the stock
# package and `dpkg -V openssh-server` is clean. A security update that moves
# the patched lines fails this build loudly instead of shipping an unrecorded sshd.
FROM public.ecr.aws/docker/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS openssh
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends dpkg-dev fakeroot quilt \
    && apt-get build-dep -y -P pkg.openssh.nognome,noudeb openssh
WORKDIR /build
COPY docker/ssh-backend/openssh/ /build/capture/
RUN apt-get source openssh \
    && cd openssh-*/ \
    && cp /build/capture/qpcapture.c /build/capture/qpcapture.h . \
    && QUILT_PATCHES=debian/patches quilt import -P session-capture.patch /build/capture/session-capture.patch \
    && QUILT_PATCHES=debian/patches quilt push \
    && DEB_BUILD_OPTIONS="nocheck noddebs parallel=$(nproc)" DEB_BUILD_PROFILES="pkg.openssh.nognome noudeb" \
       dpkg-buildpackage -b -uc -us \
    && mkdir /debs \
    && mv /build/openssh-client_*.deb /build/openssh-server_*.deb /build/openssh-sftp-server_*.deb /debs/

FROM public.ecr.aws/docker/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime

# The patched openssh packages, and ordinary shell/database clients. They are
# genuine; orchestration, rather than missing binaries, restricts reachable
# peers to the selected private cell.
RUN --mount=type=bind,from=openssh,source=/debs,target=/tmp/openssh \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        /tmp/openssh/openssh-client_*.deb \
        /tmp/openssh/openssh-server_*.deb \
        /tmp/openssh/openssh-sftp-server_*.deb \
        bsdextrautils \
        util-linux \
        ca-certificates \
        less vim-tiny procps postgresql-client-15 \
    # Retain genuine signed package indexes and one cached optional package.
    # apt-get --no-download install tree updates real dpkg/files while offline.
    && apt-get install -y --download-only --no-install-recommends tree \
    # The pool's shared host keys are written at start: one fingerprint for
    # every backend, stable across resets (a key that rotates is itself a tell).
    && rm -f /etc/ssh/ssh_host_*

COPY docker/ssh-backend/files/sshd_config /etc/ssh/sshd_config
COPY --from=build /out/session-audit /usr/local/libexec/session-audit
RUN sed -i '/^[[:space:]]*#/d' /etc/ssh/sshd_config \
    && chmod 0755 /usr/local/libexec/session-audit

# Keep the complete Debian filesystem in one final layer. This avoids retaining
# repeated full rootfs snapshots on VFS-backed development Docker engines.
FROM scratch
COPY --from=runtime / /
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" SESSION_CONTAINER=1
USER 0:0
WORKDIR /
EXPOSE 22
ENTRYPOINT ["/usr/local/libexec/session-audit", "serve"]

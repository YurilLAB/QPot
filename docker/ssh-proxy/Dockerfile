# QPot high-interaction SSH proxy (HiFi broker), plus the egress guard.
#
# The image also carries /qpot-netguard (cmd/qpot-netguard), which every
# instance runs as its own service (entrypoint override, host network,
# CAP_NET_ADMIN only) to keep honeypots off the networks around the host. It
# ships here because this package is already public; the broker never runs it.
#
# A transparent Layer-4 TCP splice that forwards attacker connections, byte for
# byte, to a pool of real-OpenSSH backends. It speaks no SSH (nothing to
# fingerprint, no parser to exploit) and needs NO privileges — it must never be
# given a docker socket or host access. See doc/ssh-hifi-proxy.md.
#
# Build context is the repository root:
#   docker build -f docker/ssh-proxy/Dockerfile -t ghcr.io/yurillab/qpot-ssh-proxy:latest .

# ---- build stage ----
FROM public.ecr.aws/docker/library/golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
WORKDIR /src
# Copy only the broker and guard sources. Other honeypot assets, local evidence
# and Git history have no place in this image's build context layers.
COPY go.mod go.sum ./
COPY cmd/qpot-sshproxy ./cmd/qpot-sshproxy
COPY cmd/qpot-netguard ./cmd/qpot-netguard
COPY internal/proxy ./internal/proxy
COPY internal/netguard ./internal/netguard
# Static, stripped binary. CGO off so it runs in a scratch image.
RUN --mount=type=secret,id=proxy_ca \
    if [ -s /run/secrets/proxy_ca ]; then export SSL_CERT_FILE=/run/secrets/proxy_ca; fi; \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/qpot-sshproxy ./cmd/qpot-sshproxy && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/qpot-netguard ./cmd/qpot-netguard

# ---- runtime stage ----
# Distroless static + nonroot: no shell, no package manager, minimal surface, and
# the broker never runs as root. (The compose runs /qpot-netguard as uid 0 with
# every capability dropped except NET_ADMIN.)
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/qpot-sshproxy /qpot-sshproxy
COPY --from=build /out/qpot-netguard /qpot-netguard

# Listener (mapped to the public SSH port by the orchestration layer).
EXPOSE 2222

# Defaults are overridden by the orchestration layer via environment variables
# (see cmd/qpot-sshproxy/main.go for the full list). BACKENDS is REQUIRED.
ENV QPOT_SSHPROXY_LISTEN=":2222" \
    QPOT_SSHPROXY_NAME="ssh-proxy" \
    QPOT_SSHPROXY_LOG="/var/log/ssh-proxy/sessions.json"

# nonroot uid from the distroless base.
USER 65532:65532
ENTRYPOINT ["/qpot-sshproxy"]

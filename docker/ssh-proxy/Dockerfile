# QPot high-interaction SSH proxy (HiFi broker).
#
# A transparent Layer-4 TCP splice that forwards attacker connections, byte for
# byte, to a pool of real-OpenSSH backends. It speaks no SSH (nothing to
# fingerprint, no parser to exploit) and needs NO privileges — it must never be
# given a docker socket or host access. See doc/ssh-hifi-proxy.md.
#
# Build context is the repository root:
#   docker build -f docker/ssh-proxy/Dockerfile -t ghcr.io/yurillab/qpot-ssh-proxy:latest .

# ---- build stage ----
FROM golang:1.25-alpine AS build
WORKDIR /src
# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static, stripped binary. CGO off so it runs in a scratch image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/qpot-sshproxy ./cmd/qpot-sshproxy

# ---- runtime stage ----
# Distroless static + nonroot: no shell, no package manager, minimal surface, and
# the process never runs as root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/qpot-sshproxy /qpot-sshproxy

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

# A repository checkout and QPot's emitted minimal context use this same file.
FROM public.ecr.aws/docker/library/golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
COPY go.mod ./
COPY internal/refrigeration/server.go internal/refrigeration/model.go internal/refrigeration/xml.go internal/refrigeration/events.go internal/refrigeration/persistence.go ./internal/refrigeration/
COPY internal/refrigeration/assets ./internal/refrigeration/assets
COPY cmd/qpot-refrigeration ./cmd/qpot-refrigeration
RUN go build -trimpath -ldflags="-s -w" -o /out/refrigeration ./cmd/qpot-refrigeration

FROM scratch
COPY --from=build /out/refrigeration /refrigeration
USER 65532:65532
EXPOSE 8080
ENV LISTEN_ADDR=:8080 EVENT_LOG=/var/log/refrigeration/events.json STATE_DIR=/var/lib/refrigeration SITE_PROFILE=retail
# Collect garbage before the container's 128 MB limit, not at an OOM kill.
ENV GOMEMLIMIT=96MiB
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/refrigeration", "healthcheck"]
ENTRYPOINT ["/refrigeration"]

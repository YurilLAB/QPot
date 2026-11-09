#!/usr/bin/env bash
# Bootstrap the same source-image integration gate for CI and image publication.
# The mandatory production guard is part of this gate; a missing capability fails.
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

if [ "$#" -gt 1 ]; then
  echo 'too many arguments to scripts/test-hifi.sh' >&2
  exit 2
fi
case "${1:-}" in
  "")
    build_args=()
    if [ -n "${QPOT_BUILD_CA_FILE:-}" ]; then
      build_args+=(--secret "id=proxy_ca,src=$QPOT_BUILD_CA_FILE")
    fi
    docker build "${build_args[@]}" -f docker/ssh-proxy/Dockerfile -t qpot-local/ssh-proxy:development .
    docker build -f docker/ssh-backend/Dockerfile -t qpot-local/ssh-backend:development .
    ;;
  --use-built-images)
    # Only images from this workflow's successful smoke-test jobs are loaded.
    # No registry lookup can replace them with a mutable :latest image.
    for image in ssh-proxy ssh-backend; do
      docker image inspect "ghcr.io/yurillab/qpot-${image}:ci" >/dev/null
      docker tag "ghcr.io/yurillab/qpot-${image}:ci" "qpot-local/${image}:development"
    done
    ;;
  *)
    echo 'usage: scripts/test-hifi.sh [--use-built-images]' >&2
    exit 2
    ;;
esac

docker pull docker.io/library/postgres:15-bookworm@sha256:19b8449e2187e8a174b40c8832a7ed9da45813b74c2779b1c614e7e7d0ee47f0
docker pull timberio/vector:0.61.0-alpine@sha256:3bb7ed5152910ed51729e256937b1d8a4bf67ff624e9d565e8e5877bffd015c7

# Publication must also pass the same real IPv4/IPv6 packet-isolation matrix
# as ordinary CI. Reuse that job so namespace prerequisites and fail-closed
# behavior cannot drift between the two workflows.
go run ./internal/cicheck/cirun -root "$repo_dir" run netguard-integration

export QPOT_TEST_HIFI_LIVE=1 QPOT_TEST_HIFI_DATABASE=1 QPOT_TEST_HIFI_SERVICES=1 QPOT_TEST_SSH_COLLECTOR=1 QPOT_TEST_SSH_BACKEND=1 QPOT_TEST_DOCKER=1
export QPOT_SSH_BACKEND_IMAGE=qpot-local/ssh-backend:development
test_pattern='^Test(SSHOrganizationLive|SSHOrganizationDatabaseLive|SSHOrganizationServicesLive|SSHCollectorPrivateLogsLive|SSHBackendLive|SSHStoreNativeMountMetadataLive)$'
test_packages=(./internal/instance ./internal/sshbackend)

# Go considers a pattern matching zero tests successful. Missing gate names
# must instead prevent publication, including accidental future renames.
listed=$(go test "${test_packages[@]}" -list "$test_pattern")
for required in TestSSHOrganizationLive TestSSHOrganizationDatabaseLive TestSSHOrganizationServicesLive TestSSHCollectorPrivateLogsLive TestSSHBackendLive TestSSHStoreNativeMountMetadataLive; do
  if ! printf '%s\n' "$listed" | grep -Fxq "$required"; then
    echo "required HiFi test is missing: $required" >&2
    exit 1
  fi
done
go test -race -p 1 -v -count=1 -timeout 15m "${test_packages[@]}" -run "$test_pattern"

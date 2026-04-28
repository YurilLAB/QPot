#!/usr/bin/env bash
# genuser.sh — runs the qpotinit container's genuser helper to create
# nginx web user credentials, using the repo / version pinned in .env.
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
if [ ! -r "$ENV_FILE" ]; then
  echo "Error: cannot read ${ENV_FILE}; run this script from the qpotce repo root." >&2
  exit 1
fi

QPOT_REPO=$(grep -E "^QPOT_REPO=" "$ENV_FILE" | cut -d "=" -f2- | tr -d '"' | tr -d "'")
QPOT_VERSION=$(grep -E "^QPOT_VERSION=" "$ENV_FILE" | cut -d "=" -f2- | tr -d '"' | tr -d "'")

if [ -z "$QPOT_REPO" ] || [ -z "$QPOT_VERSION" ]; then
  echo "Error: QPOT_REPO or QPOT_VERSION missing from ${ENV_FILE}." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not on PATH." >&2
  exit 1
fi

# id(1) prints numeric UID/GID; the variable names mirror the previous
# script but are scoped local-only here so they don't shadow $USER.
my_uid=$(id -u)
my_username=$(id -un)
my_gid=$(id -g)

echo "### Repository:        ${QPOT_REPO}"
echo "### Version Tag:       ${QPOT_VERSION}"
echo "### Your User Name:    ${my_username}"
echo "### Your User ID:      ${my_uid}"
echo "### Your Group ID:     ${my_gid}"
echo

# Make sure the bind-mount target exists, otherwise docker silently creates
# a root-owned directory and the helper can't write to it.
mkdir -p "${HOME}/qpotce"

docker run --rm \
  -v "${HOME}/qpotce:/data" \
  --entrypoint bash \
  -it \
  -u "${my_uid}:${my_gid}" \
  "${QPOT_REPO}/qpotinit:${QPOT_VERSION}" \
  "/opt/qpot/bin/genuser.sh"

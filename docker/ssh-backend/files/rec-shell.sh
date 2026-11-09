#!/bin/sh
# Preserve the original command and both streams through the audit service.
set -eu
exec /usr/local/libexec/session-audit record "$@"

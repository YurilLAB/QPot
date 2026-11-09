#!/bin/sh
# Bootstrap uses the local session service; configuration is never shell source.
set -eu
exec /usr/local/libexec/session-audit serve

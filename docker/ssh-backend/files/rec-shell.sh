#!/bin/sh
# rec-shell — the login shell for every persona user on the HiFi backend.
#
# It records the attacker's session and then hands off to a REAL bash, so the
# environment is genuine (no emulation to detect) while every keystroke and byte
# of output is captured. This is the high-interaction capture that low/medium
# honeypots cannot provide faithfully.
#
# Two paths:
#   - interactive login (no args): record the full PTY with script(1).
#   - `-c <cmd>` (e.g. `ssh host 'id'`): run the attacker's command in real bash
#     WITHOUT re-quoting it through another shell (so behaviour is faithful and
#     our wrapper introduces no command-injection of its own); the command line
#     is logged verbatim and its output is captured by sshd/PTY logging.
set -u

LOGDIR=/var/log/ssh-backend
ts="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo unknown)"
sess="${LOGDIR}/${ts}-${USER:-unknown}-$$"

if [ "${1:-}" = "-c" ]; then
    shift
    # Log the raw command line for the analytics pipeline. printf with %s never
    # interprets the content, so this is injection-safe.
    printf '%s\n' "$*" >>"${sess}.cmd" 2>/dev/null || true
    exec /bin/bash -c "$@"
fi

# Interactive: script(1) records output + timing to a ttyrec-style file, then
# execs an interactive login bash inside the recorded PTY.
if command -v script >/dev/null 2>&1; then
    exec script -q -f -c "/bin/bash -l" "${sess}.ttyrec"
fi

# Fallback if script(1) is somehow unavailable: still give a real shell (auth and
# any -c commands are already logged by sshd); never deny the shell.
exec /bin/bash -l

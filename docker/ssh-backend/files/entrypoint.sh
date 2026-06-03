#!/bin/sh
# entrypoint — prepare and run the real OpenSSH backend.
#
# Responsibilities:
#   1. Generate (or reuse persisted) host keys, so the fingerprint is stable.
#   2. Seed the persona users + weak passwords the attacker is meant to guess.
#   3. Run sshd in the foreground, logging to stderr so docker/Vector collect it.
#
# Persona users come from BACKEND_USERS="user:pass,user2:pass2,root:pass". Keep
# these consistent with the QPot credential persona advertised for this sensor.
set -eu

LOGDIR=/var/log/ssh-backend
mkdir -p "$LOGDIR"
chmod 0750 "$LOGDIR"

# 1) Host keys. ssh-keygen -A creates any missing key types. Mount /etc/ssh as a
# volume to persist them across restarts (stable fingerprint).
ssh-keygen -A

# 2) Persona users. Default set is deliberately weak/common; override per sensor.
USERS="${BACKEND_USERS:-admin:admin,ubuntu:ubuntu,user:password,root:root123}"

OLDIFS="$IFS"
IFS=','
for pair in $USERS; do
    u="${pair%%:*}"
    p="${pair#*:}"
    [ -n "$u" ] || continue
    if [ "$u" = "root" ]; then
        printf '%s:%s\n' "$u" "$p" | chpasswd
        usermod -s /usr/local/bin/rec-shell root 2>/dev/null || true
        continue
    fi
    if ! id "$u" >/dev/null 2>&1; then
        useradd -m -s /usr/local/bin/rec-shell "$u" 2>/dev/null || true
    else
        usermod -s /usr/local/bin/rec-shell "$u" 2>/dev/null || true
    fi
    printf '%s:%s\n' "$u" "$p" | chpasswd
done
IFS="$OLDIFS"

# 3) Run sshd in the foreground (-D) logging to stderr (-e).
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config

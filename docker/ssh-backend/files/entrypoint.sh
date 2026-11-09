#!/bin/sh
# entrypoint — prepare and run the real OpenSSH backend.
#
# Responsibilities:
#   1. Generate (or reuse persisted) host keys, so the fingerprint is stable,
#      and give sshd private copies of them.
#   2. Seed the persona users + weak passwords the attacker is meant to guess.
#   3. Run sshd in the foreground, logging to stderr so docker/Vector collect it.
#
# Persona users come from BACKEND_USERS="user:pass,user2:pass2,root:pass". Keep
# these consistent with the QPot credential persona advertised for this sensor.
set -eu

LOGDIR=/var/log/ssh-backend
mkdir -p "$LOGDIR"
chmod 0750 "$LOGDIR"

# 1) Host keys, in the SHARED /etc/ssh/keys dir (identical in every backend) so
# the whole pool presents ONE stable host-key fingerprint. qpot generates them on
# the host and mounts the dir READ-ONLY, so an attacker with root here cannot
# replace them. Only when keys are missing (a hand-run container with a writable
# dir) are they generated here, serialized with flock so concurrently booting
# backends agree on one key set.
KEYDIR=/etc/ssh/keys
missing=0
for kt in rsa ecdsa ed25519; do
    [ -f "${KEYDIR}/ssh_host_${kt}_key" ] || missing=1
done
if [ "$missing" = 1 ]; then
    mkdir -p "$KEYDIR"
    chmod 0750 "$KEYDIR" || true
    (
        flock 9
        for kt in rsa ecdsa ed25519; do
            if [ ! -f "${KEYDIR}/ssh_host_${kt}_key" ]; then
                ssh-keygen -q -t "$kt" -f "${KEYDIR}/ssh_host_${kt}_key" -N "" </dev/null || true
            fi
        done
    ) 9>"${KEYDIR}/.keygen.lock"
fi
# sshd refuses a host key others may read, and the mounted keys keep the host's
# modes (Docker Desktop shows every file shared from Windows as 0777). sshd
# reads private copies instead; the pool's keys stay read-only.
PRIVDIR=/run/qpot-hostkeys
rm -rf "$PRIVDIR"
mkdir -m 0700 "$PRIVDIR"
for kt in rsa ecdsa ed25519; do
    if [ -f "${KEYDIR}/ssh_host_${kt}_key" ]; then
        install -m 0600 -o root -g root "${KEYDIR}/ssh_host_${kt}_key" "${PRIVDIR}/ssh_host_${kt}_key"
    fi
done

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

# 3) Run sshd in the foreground (-D) logging to stderr (-e). The short pause
# guarantees a visible gap while a backend is being recreated, which is how the
# unprivileged broker confirms a reset before reusing the backend.
sleep 1
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config

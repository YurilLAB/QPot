# Clusters

Pair several QPot nodes into a cluster that shares each node's health:
uptime, event counts and active attackers. Each node keeps its own events and
dashboard.

- [Quick start](#quick-start)
- [How joining works](#how-joining-works)
- [Trust and certificates](#trust-and-certificates)
- [Upgrading an older cluster](#upgrading-an-older-cluster)
- [Operations](#operations)

## Quick start

```bash
qpot cluster init --name production                                   # on the enrollment host: prompts for a password, prints the cluster ID
qpot cluster join --id qc_... --password '...' --seed 10.0.0.10:7946  # on each sensor
qpot cluster requests --password '...'                                # on the host: pending joiners
qpot cluster approve <request-id> --password '...'                    # or deny
qpot cluster status
```

Membership runs in the control plane, so restart the instance after `init`
or `join`: `qpot down`, then `qpot up -d`. The web UI's **Pairing** tab shows members and pending join
requests, with the exact approve or deny command to run on the host.

## How joining works

Joining needs the password **and** the host's approval (`require_approval`,
on by default).

- The host that ran `cluster init` is the **enrollment authority**: use it as
  the join seed. Ordinary members cannot enroll others.
- Each node generates its own private key locally. An admitted node receives
  only its signed certificate and a member key, never the cluster's CA key.
- A full cluster refuses new members.

## Trust and certificates

Traffic between nodes is TLS-encrypted automatically, with no certificates to
manage:

- `cluster init` makes a certificate authority for the cluster, and the
  cluster ID is its fingerprint.
- A node that knows the ID verifies every node it talks to, the join seed
  included.
- Nothing a node serves derives from the password, so the password cannot be
  tested offline, and the password alone cannot impersonate a node.

By default a joining node trusts only the cluster's own CA. If the seed serves
a certificate from your own or a public CA (`tls_cert_path` in
`cluster.json`), add `--operator-cert`, or `--ca-file <bundle.pem>` to check it
against a specific CA bundle.

Every approved member is trusted with the membership. A node's departure is
accepted only from the node itself, as far as its address shows. Nodes never
send each other their QPot IDs. The full trust model is in the CLI reference:
[who is trusted with membership](cli-reference.md#who-is-trusted-with-membership).

## Upgrading an older cluster

Clusters made before per-node certificates need an explicit upgrade:

1. Stop the old control planes.
2. Update QPot on every node.
3. Run `qpot cluster upgrade` once, on the chosen enrollment host.
4. On every other node, leave the old cluster and join again with the new ID.

The upgrade keeps the settings and the local instance, makes a private backup
of the exact old membership, and switches to a new CA, member key and cluster
ID only after its checks pass. Event stores are not touched, and this command
does not back them up. Incompatible protocol versions are refused, and old
signing keys are never trusted by the upgraded cluster.

## Operations

- **Protect the enrollment host.** Back up its private cluster state: it is
  the only place the CA key lives.
- **Certificates last one year.** Re-enroll members before expiry. The
  enrollment host renews its own certificate on startup when it has under 30
  days left.
- **The password** is stored in `~/.qpot/cluster/cluster.secret`, readable
  only by you, or read from the `QPOT_CLUSTER_PASSWORD` environment variable.
- **Nodes that leave** are remembered as left for 30 days, so gossip from a
  member that missed the leave cannot bring them back.

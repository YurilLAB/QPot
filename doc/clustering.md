# Clusters

Pair several QPot nodes into a cluster that shares each node's health:
uptime, event counts and active attackers. Each node also shares its 20 most
active sources of the last hour, which `GET /api/cluster` merges
(`shared_attackers`). Each node keeps its own events and dashboard.

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
qpot cluster remove <node-id>                                         # on the host: remove a node
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

Encrypted cluster API connections go directly to the configured peer addresses.
`HTTP_PROXY` and `HTTPS_PROXY` do not redirect cluster traffic; peers need a
directly reachable address.

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

Every request between nodes also carries the sender's own node certificate,
so a node knows which member is asking:

- A node that left, or that the host removed, is refused, whatever credentials
  it kept. Its leave (signed with its own key) or removal (signed by the
  cluster CA) spreads through gossip to members that were offline.
- A node contacting another checks that the node answering is the one it
  dialled.
- A node speaks only for itself: no member can remove another, or send gossip
  or intel in another's name.
- Only the enrollment host adds members. A member learns of a node from
  another's gossip only with that node's certificate from the cluster CA, so
  no member can add nodes the host never admitted. A node's name, address and
  statistics are taken only from the node itself.
- Removing a node is the enrollment host's decision: `qpot cluster remove
  <node-id>`, signed with the cluster CA so members can check it.

Nodes never send each other their QPot IDs. The full trust model is in the CLI
reference:
[who is trusted with membership](cli-reference.md#who-is-trusted-with-membership).

## Upgrading an older cluster

**From a release before node certificates were checked on every request**
(QPot 1.0.1 and earlier): update QPot on every node and restart the control
planes. Existing certificates already work for this, so nothing is re-enrolled
and the cluster ID stays. Until a node is updated, the updated nodes refuse its
requests, so update them all together. A cluster whose `cluster.json` has
`"enable_encryption": false` must turn it on, on every node
([QP-CLUSTER-010](setup-errors.md#qp-cluster-010)).

Update the enrollment host first, or with the others: updated nodes learn of a
newly admitted node only from the certificate the host hands out, which older
versions do not pass on. Members already in `cluster.json` are kept, and each
record takes its node's certificate the next time that node gossips. Older
versions added whatever a member gossiped, so check `qpot cluster nodes` on the
enrollment host and remove any node you never approved with
`qpot cluster remove <node-id>`.

**Clusters made before per-node certificates** need an explicit upgrade:

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
- **Nodes that leave or are removed** are remembered for a year and a day,
  longer than their certificates are valid, so gossip from a member that
  missed the leave cannot bring them back. At most 8,192 such records are
  kept, the newest first.
- **Remove a node** that is compromised or gone for good with
  `qpot cluster remove <node-id>` on the enrollment host. Every member refuses
  it from then on, also after restarts.

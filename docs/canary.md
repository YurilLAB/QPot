# Canaries (Honeytokens)

Canaries are QPot's second deception primitive, complementary to the honeypot
containers. A **honeypot** is a decoy *system* an attacker connects to from the
outside; a **canary** is a decoy *artifact* planted **inside** your real estate
— a fake AWS key in a CI runner, a tempting `Q4-salaries.html` on a file share,
a beacon URL hidden in a config comment — that fires the moment anyone touches
it.

Because nobody legitimately interacts with a canary, **a single trip is a
near-zero-false-positive, critical alert.** Honeypots tell you *the perimeter is
being scanned*; canaries tell you *someone is already inside and moving through
your data*. Run both.

```
        outside ───scan/connect──▶  HONEYPOT containers   (perimeter signal)
        inside  ───open/read/use──▶ CANARY artifacts      (post-breach signal)
                                       │ trip
                                       ▼
                         database.Event (honeypot="canary", severity=critical)
                         → events feed → IOC store → overview
```

A canary trip is just an event tagged `honeypot="canary"`, so it flows through
the *existing* pipeline — the attacker activity feed, IOC extraction and the
local overview — with no special-casing downstream.

## Canary kinds

| Kind   | What it is | How it trips | Plant it as… |
|--------|-----------|--------------|--------------|
| `web`  | A unique beacon URL (`/c/<token>`) | Any HTTP GET of the URL | a fake intranet bookmark, an "internal-admin" link, a URL in a config comment |
| `file` | An HTML document that beacons when opened/previewed | The embedded beacon URL is fetched | bait on a file share (`Q4-salaries.html`, `vpn-keys.html`) |
| `aws`  | A realistic but fake AWS access-key pair (`AKIA…` + 40-char secret) | The key id or secret appears in a captured honeypot session | a credential in `~/.aws/credentials`, a CI secret, a `.env` |
| `credential` | A password or token (planted by QPot only) | The value appears in a captured honeypot session | see [Canaries planted in the honeypots](#canaries-planted-in-the-honeypots) |
| `ssh-key` | An SSH key pair (planted by QPot only) | The public key or its fingerprint appears in a captured session: the key offered in a login | see below |

`web` and `file` trip via the **public beacon endpoint**. `aws` trips via the
**intelligence worker**, which scans every captured session for the planted
value — i.e. the attacker stole the key from wherever you planted it and is now
replaying it against your own deception estate. (AWS-credential matching
therefore requires `intelligence.enabled: true`, which is the default.)

Each kind is pre-mapped to a defensible ATT&CK technique so trips classify
consistently: `aws` → **T1078.004 Valid Accounts: Cloud Accounts**,
`file` → **T1530 Data from Cloud Storage**, `web` → **T1213 Data from
Information Repositories**, `credential` → **T1552.001 Unsecured Credentials:
Credentials In Files**, `ssh-key` → **T1552.004 Unsecured Credentials: Private
Keys**.

Web and file tokens are also watched in captured sessions: a beacon URL typed
or fetched on a honeypot trips its canary on the honeypot channel even when
the beacon endpoint itself is out of reach.

## Canaries planted in the honeypots

On its server personas (every Cowrie persona except the device ones) QPot gives
the fake host the working state of an ops box, and every secret in it is a
canary. Attackers who get a shell on a Linux server go for the same few places:
credential harvesters read `~/.ssh` (keys, `config`, `known_hosts`),
`.bash_history` (ssh/scp/rsync and database command lines), `/etc/hosts`,
`~/.aws/credentials`, `.git-credentials`, `.env` files and database dumps, then
log in to the hosts they found with the keys and passwords they found; people at
the keyboard look for user files and stay longer where the files look lived in.
A Cowrie persona from the image has none of that on its server personas, so the
bait is:

| Canary | Where the attacker finds it | It trips when |
|--------|-----------------------------|---------------|
| root's SSH key (`ssh-key`) | `/root/.ssh/id_ed25519`, with `config` and `known_hosts` naming the database host | it is offered in a public key login to a QPot honeypot (Cowrie logs the key and its fingerprint), or the public key shows up in a session |
| the database password (`credential`) | the backup script (in `/usr/local/sbin`, `/usr/local/bin` or `/root/bin`), run from `/etc/cron.d`, and root's `.bash_history` | it is typed in a command, at the password prompt of `ssh` on the honeypot, or used to log in to any QPot honeypot |
| the AWS key (`aws`, on some instances) | `/root/.aws/credentials` and `config` | the `aws` command on the honeypot uses it (Cowrie logs the key it would sign with), or either half shows up in a session |
| the healthcheck URL (`web`) | the backup script and root's `.bash_history` | its token shows up in a session (`curl` of the URL on the honeypot); with `canary.base_url` set, also a GET of `<base_url>/c/<token>` |
| the SMTP password (`credential`, on some instances) | the `settings` table of a gzipped database dump in `/var/backups` (root's home on Red Hat and CentOS) | it is used to log in to a QPot honeypot (a mail login on heralding, for one) or shows up in a session |
| a GitLab token (`credential`, Ubuntu and Raspberry Pi OS, some instances) | the login user's `.git-credentials` | it shows up in a session (a clone URL, an API header) or as a password |
| the login user's password (`credential`) | the user's `.bash_history`, typed at the `sudo` prompt by mistake | it is used to log in to a QPot honeypot or shows up in a session |

Everything agrees with the persona: the host name it drew, its users and their
home directories, its package manager, file owners and modes, and file times
placed between its installation and its boot (the last line of root's history
is the reboot). The names, hosts, addresses and which parts exist are drawn
from the instance's deception seed: a regenerated compose plants the same files
and canaries, another instance gets different ones. The patch layer also makes
the files usable the way an attacker uses them: `history` shows the history
file, `ssh` to one of the internal hosts times out like an unreachable host
(what is typed at its prompts is logged), `aws` answers like a CLI without
network, and `zcat` reads the dump.

**No trip needs the web UI to be reachable.** The planted canaries trip on the
honeypot channel: the value turns up in a session one of QPot's honeypots
captured, from any address, in any protocol. The healthcheck URL also trips on
the http channel, and only when `canary.base_url` says where the beacon is
reachable; without it the URL points into the persona's internal network.

The server registers the planted canaries in the store when it starts
(`planted: true` in the API), and follows the instance's config file while it
runs: enabling Cowrie, changing its persona or bait, or `canary.base_url` takes
effect within seconds, without a restart. They cannot be deleted (QPot would
plant them again); turn the bait off with `qpot honeypot set cowrie bait=off`. Trips need
`canary.enabled` and, for the honeypot channel, `intelligence.enabled`.

Sources: Sysdig TRT on SSH-Snake (2024) and on TeamTNT's AWS credential
stealers; AhnLab ASEC on Kinsing's `spre.sh` (report 66695); CISA and FBI on
AndroxGh0st (2024); Barron and Nikiforakis, "Picky Attackers" (ACSAC 2017);
SANS ISC diaries on Cowrie sessions and on leaked AWS keys.

## Configuration

```yaml
canary:
  enabled: true                       # serve the beacon + management API, run the matcher
  base_url: https://assets.example.com # public origin where THIS QPot is reachable
  decoy: notfound                     # response from /c/<token>: "notfound" (404) | "pixel" (1x1 GIF)
  max_trips: 500                      # bounded trip history kept in canaries.json
```

`base_url` is load-bearing: a planted token must phone home to *this* QPot's web
server. Point it at wherever the server is reachable (directly, or via a reverse
proxy that forwards `/c/` to it). Leave it unset and URLs render path-only
(`/c/<token>`) and the CLI warns you.

The beacon endpoint (`/c/<token>`) is **deliberately unauthenticated** — a
canary URL has to be reachable by whoever trips it. It always returns the same
innocuous decoy whether or not the token is real, so it is not a token-
enumeration oracle (and tokens carry ~160 bits of entropy regardless). The
attacker-controlled `X-Forwarded-For` is recorded for context but never trusted
as the source IP; the real TCP peer is.

## CLI

Canaries are runtime objects owned by a running instance, so `qpot up` must be
active. The CLI talks to the instance's local API (QPot-ID auth).

```bash
# Mint
qpot canary create --kind aws  --name ci-runner  --memo "planted in Jenkins"
qpot canary create --kind web  --name wiki-link  --memo "fake intranet bookmark"
qpot canary create --kind file --name q4-salaries --memo "HR share"

# Review
qpot canary list
qpot canary trips                 # the alerts; newest first

# File bait: download the document artifact and plant it
qpot canary artifact cnry_abc123 --out Q4-Salaries.html

# Retire
qpot canary rm cnry_abc123
```

`--memo` is the most important field operationally: it records **where** the
canary is planted and is echoed on every trip, so the alert is immediately
actionable ("the key from the Jenkins runner was just used from 203.0.113.50").

## HTTP API

All management routes require the QPot-ID (`X-QPot-ID` header or `?qpot_id=`).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/canaries` | GET | List canaries (with beacon URL / credential pair; planted ones with their values) |
| `/api/canaries` | POST | Create `{ "kind": "web\|file\|aws", "name": "...", "memo": "..." }` |
| `/api/canaries?id=<id>` | DELETE | Remove a canary (409 for a planted one) |
| `/api/canaries/trips?limit=N` | GET | Recent trips, newest first |
| `/api/canaries/artifact?id=<id>` | GET | Download a file canary's document |
| `/c/<token>` | GET | **Public** beacon — records a trip, returns the decoy |

## Storage

Canaries and their (bounded) trip history persist to
`<data_path>/canaries.json`, written atomically (temp + rename) so a crash mid-
write never truncates the file. The store is the source of truth; restarting the
instance reloads it.

## Operational notes & honest limitations

- **Web/file canaries need the beacon reachable.** If `/c/` is not reachable
  from where the token is planted (e.g. an air-gapped segment), a web/file
  canary cannot phone home. AWS canaries have no such requirement — they trip
  purely on value-matching inside captured sessions.
- **AWS canaries are decoys, not live credentials.** They will not authenticate
  to real AWS. They detect *theft + replay against QPot*, not direct use against
  AWS. (Detecting use against real AWS would require CloudTrail integration,
  which is out of scope here.)
- **The matcher runs on the intelligence worker's cadence** (`worker_interval`,
  default 15m) for stored-but-unclassified events. Beacon (web/file) trips are
  real-time; credential matches surface within one worker cycle.
- **Trip history is bounded** (`max_trips`); the lifetime per-canary trip
  counter keeps counting even after old trips age out of the visible history.

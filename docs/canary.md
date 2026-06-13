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
                         → events feed → IOC store → Yuril → ypanel
```

A canary trip is just an event tagged `honeypot="canary"`, so it flows through
the *existing* pipeline — the attacker activity feed, IOC extraction, the Yuril
forwarder, and the ypanel snapshot — with no special-casing downstream.

## Canary kinds

| Kind   | What it is | How it trips | Plant it as… |
|--------|-----------|--------------|--------------|
| `web`  | A unique beacon URL (`/c/<token>`) | Any HTTP GET of the URL | a fake intranet bookmark, an "internal-admin" link, a URL in a config comment |
| `file` | An HTML document that beacons when opened/previewed | The embedded beacon URL is fetched | bait on a file share (`Q4-salaries.html`, `vpn-keys.html`) |
| `aws`  | A realistic but fake AWS access-key pair (`AKIA…` + 40-char secret) | The key id or secret appears in a captured honeypot session | a credential in `~/.aws/credentials`, a CI secret, a `.env` |

`web` and `file` trip via the **public beacon endpoint**. `aws` trips via the
**intelligence worker**, which scans every captured session for the planted
value — i.e. the attacker stole the key from wherever you planted it and is now
replaying it against your own deception estate. (AWS-credential matching
therefore requires `intelligence.enabled: true`, which is the default.)

Each kind is pre-mapped to a defensible ATT&CK technique so trips classify
consistently: `aws` → **T1078.004 Valid Accounts: Cloud Accounts**,
`file` → **T1530 Data from Cloud Storage**, `web` → **T1213 Data from
Information Repositories**.

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
| `/api/canaries` | GET | List canaries (with beacon URL / credential pair) |
| `/api/canaries` | POST | Create `{ "kind": "web\|file\|aws", "name": "...", "memo": "..." }` |
| `/api/canaries?id=<id>` | DELETE | Remove a canary |
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

# Connecting QPot to ypanel

**ypanel** is Yuril Security's unified operator control panel — a single web app
(served at `https://yurillab.dev/ypanel`) for running the whole Yuril suite
(QPot, DireC, WEWAF, Kmap, GPTL) from one place. An operator signs in once and
each product surfaces its telemetry and controls, scoped to the licences they
own.

This document defines how a QPot instance connects to ypanel and what is (and
is not) wired today.

## The operator-plane model

ypanel never talks to a QPot host directly. Instead:

```
  QPot host ──phone-home──▶ DireC activation worker ──reads──▶ ypanel (browser)
  (instance API,            (Cloudflare Worker,             (operator session,
   X-QPot-ID auth)           the "operator plane")            licence-scoped)
```

1. **The instance** runs QPot and exposes its local control API (the same one
   the bundled WebUI uses): `GET /api/status`, `GET /api/stats`,
   `POST /api/honeypots`, authenticated with the per-instance **QPot-ID**.
2. **The operator plane** is the DireC activation worker
   (`https://direc-activation.stoney20-js.workers.dev`). The instance pushes
   periodic snapshots to it; ypanel reads those snapshots and issues
   **allow-listed** control jobs (e.g. `honeypot.enable` / `honeypot.disable`)
   that the instance applies on its next check-in.
3. **ypanel** (the browser) only ever holds an *operator session token* + the
   *client licence key*, sent as request headers. It reads through the worker.

### Security model (load-bearing)

- **The QPot-ID never leaves the host.** It is the instance's local API secret;
  it is not part of the operator-plane contract and never reaches the worker or
  the browser. ypanel mints/stores no QPot-ID.
- **HTTPS is enforced** end-to-end (a localhost carve-out exists for dev only).
- **Tenant isolation:** an operator session is scoped to the licences it owns; a
  client only ever sees their own instances.
- **Allow-listed control vocabulary:** the worker accepts only a fixed set of
  control verbs (honeypot enable/disable). Whole-instance lifecycle stays
  CLI-only. The panel cannot invent a command the worker won't honour.
- **Fail-closed:** a read that can't be served returns honestly empty/errored;
  ypanel never shows stale or fabricated telemetry when the link is down.

## Enrolling a host

From ypanel: **QPot → Set up a host** walks the three steps —

1. name the host and mint an enrolment credential,
2. run the one-line agent install on the host
   (`curl -fsSL https://get.qpot.yurillab.dev | sudo sh -s -- --enroll <token>`),
3. watch it check in (Waiting → Checking in → Online).

Once a host reports, it appears in **QPot → Instances** with live resources,
bandwidth, per-honeypot state, and a link to its WebUI.

## Status today (honest)

| Capability                                        | Status |
|---------------------------------------------------|--------|
| Instance local API (`/api/status`, `/api/honeypots`) | **implemented** (this repo, `internal/server`) |
| Per-instance QPot-ID auth, isKnownHoneypot guard  | **implemented** |
| ypanel QPot section (overview/instances/honeypots/clusters/events) | **implemented** — reads live when connected, honest demo otherwise |
| Worker operator-plane: enroll + snapshot push + read endpoints + control-job queue | **implemented in the activation-server worker and verified live end-to-end** (enroll → push → read → enqueue → apply against a real worker + D1). Production deploy of those routes is the remaining ship step (gated). |
| **QPot phone-home agent** (enroll → push snapshots → poll + apply jobs) | **the one piece QPot still needs** — see the checklist below |
| Captured-session feed (`/sessions`, attacker transcripts) | **not wired** — ypanel asks for it, the worker doesn't serve it yet; the Sessions tab degrades to an honest empty state. See *Further improvements*. |

When the QPot agent is pushing and a client is enrolled, ypanel's QPot screens
switch from demo to live automatically — no panel changes required.

---

## What QPot must have ON for ypanel to work

ypanel + the worker side are done. The remaining work is **in this repo**: a
phone-home **agent** that bridges a QPot instance to the operator plane. To make
ypanel light up live, QPot needs all four of these ON:

### 1. The instance local API — *already implemented*
`GET /api/status`, `GET /api/stats`, `GET /api/honeypots`,
`POST /api/honeypots` (toggle), QPot-ID auth. The agent reads from this; nothing
new needed here.

### 2. Enrolment — *required*
On `--enroll <token>`, the agent calls
`POST /v1/ypanel/qpot/instances/enroll` once to exchange the operator-issued
enrolment token for a long-lived **instance push credential** (an enrollment
token bound to the instance id). Store it on the host next to the QPot-ID; it is
the agent's identity to the worker. The QPot-ID itself is **never** sent.

> **Heads-up (auth model is evolving):** ypanel is moving to a **keyless** model
> — an operator signs up with just an *account* and enrols software against it,
> no licence key to buy or paste. For the agent this changes only *what the
> enrolment token represents* (an account-scoped enrolment, not a licence claim);
> the agent's job — enrol once, push snapshots, poll jobs — is identical. Build
> against the current `/instances/enroll` + `/push` contract; it stays
> backward-compatible when keyless lands.

### 3. Snapshot push (phone-home) — *required, the core of it*
Every ~10–30 s the agent maps QPot's live state to the worker's snapshot schema
and `POST`s it to `POST /v1/ypanel/qpot/push` (authenticated with the licence
JWS + the instance push credential). The worker stores the latest snapshot per
instance; every ypanel QPot read (`/overview`, `/instances`, `/instances/:id`,
`/events`) is served from it. **Exact payload the worker accepts** (mirror this
in the agent — see `activation-server/scripts/qpot-honeypot-sim.mjs::snapshot()`
for a reference producer):

```jsonc
{
  "v": 1,
  "instance_id": "qp_…",
  "host": "10.20.0.15", "status": "online", "version": "1.4.2",
  "bootedAt": "2026-06-01T00:00:00Z",
  "clusterId": "cl_atlas", "clusterName": "Atlas",
  "os": "linux", "arch": "amd64", "region": "EU · Frankfurt",
  "cpu":  { "pct": 18, "caption": "0.7 / 4 cores" },   // → resource gauges
  "mem":  { "pct": 44, "caption": "3.5 / 8 GB" },
  "disk": { "pct": 52 },
  "procs":{ "pct": 22, "caption": "441 / 1024" },
  "eventsPerSec": 4.2,
  "honeypots": [                                        // → Honeypots tab + tiles
    { "type": "cowrie", "enabled": true, "port": 22, "hits24h": 1840 }
    // type MUST be a known honeypot id (cowrie, dionaea, elasticpot, conpot, wordpot, …)
  ],
  "recentEvents": [                                     // → Events feed (keep ids STABLE + UNIQUE)
    { "id": "ev_a1", "ts": "2026-06-07T22:14:05Z", "severity": "critical",
      "honeypot": "cowrie", "srcIp": "203.0.113.66", "country": "RU", "port": 22,
      "intent": "ssh brute force", "tactic": "TA0006 Credential Access",
      "rawLine": "login attempt root/admin123" }
  ]
}
```

Gotchas the panel cares about:
- **`recentEvents[].id` must be stable + unique.** ypanel keys its live feed by
  id; a duplicate id across pushes throws (we hardened the feed to de-dupe, but
  fix it at the source). Use the QPot event's own id, not an array index.
- **`honeypots[].type` must be a known id** or the panel falls back to the raw
  string for its label/port. Keep them in sync with QPot's registry.
- **`severity` ∈ {critical, warn, info}**; **`hits24h` / `*.pct`** are numbers.
- Send the FULL current snapshot each push (it's a replace, not a delta).

### 4. Control-job polling — *required for the buttons to do anything*
ypanel's honeypot enable/disable enqueues an **allow-listed** job on the worker.
The agent must poll the worker for pending jobs on each check-in and apply them
locally via the instance API, then ack. Vocabulary today: `honeypot.enable` /
`honeypot.disable` (by type). Whole-instance power is intentionally **CLI-only**
— `POST /instances/:id/power` answers "not remotely controllable" by design, so
the agent does **not** need to honour a remote start/stop.

> Net: items 1 is done; **2–4 are the agent to build in QPot.** Until the agent
> ships, the worker endpoints are live but receive no data, so ypanel stays on
> honest demo for QPot.

---

## Further improvements to integrate

Ordered roughly by value once the agent is live:

1. **Captured sessions + transcripts (`/sessions`).** The single biggest gap.
   ypanel's *Sessions* tab and the threat-intel rollup call
   `GET /v1/ypanel/qpot/sessions` (and `/sessions/:id`), which the worker does
   not implement yet. Plan: the agent pushes captured engagements (cowrie shell
   transcripts, HTTP exploit logs, malware drops) as a `sessions[]` block (or a
   dedicated push), the worker stores + paginates them, and ypanel renders the
   full-transcript drawer it's already built. This is what makes a honeypot
   *valuable* in the panel, not just a hit count.
2. **Real-time push instead of poll.** Replace the snapshot poll with an
   agent→worker stream (or worker→panel SSE) so the Events feed and gauges move
   the instant something lands, not on the next interval.
3. **Per-honeypot + cluster controls.** Extend the allow-list (rotate creds,
   reset a honeypot, set engagement tier, cluster-wide enable/disable) — each new
   verb added to the worker's allow-list AND the agent's job applier.
4. **Accurate resources & bandwidth.** Wire `cpu/mem/disk/procs` + an
   ingress/egress series from the host's real counters (today the WebUI has
   these; the agent just needs to forward them) so the Instances page stops
   estimating.
5. **WebUI deep-link / SSO.** The Instances row links to the bundled WebUI; hand
   it a short-lived, QPot-ID-scoped token so the operator lands authenticated
   instead of re-logging-in.
6. **IOC / MITRE enrichment in events.** Push the ATT&CK technique + any IOC
   hashes per event so ypanel can pivot/filter on them (the fields exist in the
   feed; populate `tactic` consistently and add an optional `iocs[]`).
7. **Honeypot registry sync.** Expose QPot's honeypot catalogue (type → label,
   port, protocol) so ypanel labels new honeypot types without a panel release.

When any of these land, follow the same contract discipline: **add the verb/field
to the worker (allow-listed, validated, tenant-scoped) first, then the agent, then
ypanel reads it** — never let the panel invent a command the worker won't honour.

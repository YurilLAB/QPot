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
| ypanel QPot section (overview/instances/honeypots/clusters/events) | **implemented** (reads live when connected, demo otherwise) |
| Worker operator-plane snapshot push + job queue   | **planned** — the contract above is the target; until the worker's QPot endpoints are deployed, ypanel's QPot screens run on honest demo data |

When the operator-plane endpoints are live and a client is enrolled, ypanel's
QPot screens switch from demo to live automatically — no panel changes required.

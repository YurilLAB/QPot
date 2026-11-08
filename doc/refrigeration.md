# Refrigeration supervisor

`refrigeration` is a native Go honeypot presenting a bounded AK-SM 800A / StoreView
3.3.0 management interface. It has a working browser console and XML controls over
HTTP, with virtual refrigeration equipment. It is separate from Conpot and is
disabled by default, including when an existing instance is upgraded.

QPot 1.0.1 and later include this service.

## Start and configure

```bash
qpot setup --profile refrigeration       # a new instance with only this honeypot
qpot honeypot enable refrigeration       # add it to an existing instance
qpot honeypot set refrigeration site_profile=plasma
qpot honeypot list                       # inspect the configured host port
```

The dashboard's **Refrigeration and cold storage** card provides the same controls.
Its console link opens the configured HTTP host mapping when the container is
running. External routing and reachability still depend on the deployment.
QPot management authentication and the decoy's accounts are separate.

`site_profile` accepts `retail` or `plasma`; an empty value restores `retail`.
Retail presents food refrigeration equipment; plasma presents frozen plasma and
refrigerated blood-storage examples. These are synthetic scenarios, with no
claim of clinical suitability or a validated physical process model. Each scene
keeps its own settings and history when switching away and back. Saving while
the service is off does not enable it. A failed build or recreation leaves the
saved configuration distinguishable from the running process.

## Image and isolation

An installed QPot binary contains the exact Go sources and browser assets needed
to build this service. It emits a minimal Docker context under
`honeypots/refrigeration/build` in the instance data directory. No project checkout
or host Go installation is needed. First start needs Docker access to the pinned
official Go builder image; compiling this standard-library-only service needs no
Go module downloads. The image name includes a hash of its sources and assets.

The runtime image uses `scratch`, UID 65532, a read-only root filesystem, dropped
capabilities, and separate writable log/state mounts. It joins its own honeypot
network and retains QPot's egress guard and configured resource limits. The
container serves HTTP on port 8080; automatic allocation may publish a different
host port. Its health probe uses the ordinary browser entry point over loopback
and is excluded from attack telemetry only for that exact internal probe.

## Attacker-facing behavior

The console supports login, device status and detail, parameter reads and
setpoint writes, manual defrost, main switches, alarm acknowledgement, historical
graphs, configuration inspection and maintenance exports. Reads, controls,
history and exports share one state model. Temperature changes follow the
bounded simulation over time; polling faster does not accelerate it. An alarm
acknowledgement does not remove an active condition.

Parameter metadata from `read_parm_info` has working `read_dyn_list_info`
follow-up discovery for the advertised Off/On value list. `read_history` series
contain numeric values, with their units and actual sampling interval described
separately. `alarm_summary` and `alarm_detail` honor the documented day,
date/time format, state and navigation selectors; the long response uses
`expanded="2"`. Buffer rotation preserves active alarm references and their
acknowledgement state. This does not add proprietary EDF files or a complete
alarm configuration interface.

XML requests use `POST /xml.cgi`, accepting the legacy browser's form-encoded
`xml` body and documented raw XML transports. The finite implemented subset
includes controller/device discovery, parameter reads and writes, date/time,
manual controls, alarms and history. Unknown or invalid commands receive errors;
an advertised control is not a shell command or firmware-upload facility.

This persona uses pre-4.x body/header credentials. Authenticated browser XML
requests carry credentials, as the published 3.3 frontend does. The console keeps
them only in page memory and clears them on logout or rejected authentication;
they are not placed in URLs or browser storage. Documented `AKSM-Auth` Basic
authentication is also supported. Cookie sessions are an additional bounded
convenience, not a claim of the later strict HTTPS/token authentication mode.

Equipment controls stay disabled until the current session has loaded fresh
equipment data, including when changing from a supervisor to an observer over
a slow connection.

The configured **synthetic** accounts are:

| Account | Password | Role |
|---|---|---|
| `Supervisor` | `12345` | Supervisor controls |
| `Service` | `service123` | Read/export and alarm acknowledgement |
| `Monitor` | `monitor` | Observation |

These are decoy site accounts, not verified manufacturer factory defaults. A
per-instance synthetic maintenance account is also planted in the export archive.

## Files and canaries

Authenticated maintenance exports include `config.xml`, `devices.csv`,
`history.csv`, `alarms.csv`, a README and `.netrc` in `maintenance.zip`. The XML,
CSV and ZIP are genuine formats containing consistent snapshots. They are local
maintenance formats, not proprietary firmware, EDF files or vendor-importable
project backups. Only the finite export files are served.

The maintenance credential is watched whenever refrigeration is enabled, even
if Cowrie is off. Downloading an export or reading a file alone does not trip a
canary. Captured reuse of the watched credential does. Old values retain the
existing historical-watch policy after disabling or changing bait.

An optional Linux support-host copy shares the exact controller identity and
credential:

```bash
qpot honeypot set cowrie persona=debian-bookworm bait_profile=industrial bait_target=refrigeration
```

This does not enable either referenced service. Reapply the Cowrie file settings
after changing the scene to refresh the support copy, or use **Save and refresh
archives** in Cowrie's settings. `bait_target=` restores the Conpot reference;
`bait_profile=` restores ordinary ops files; `bait=off` suppresses Cowrie files.
The support archive uses a separate private reference address and does not claim
a live connection to the controller.

## Events and limits

JSON events under `honeypots/refrigeration/logs` feed the existing Vector/database
pipeline. They distinguish authentication, reads, exports, write attempts,
accepted or denied simulated writes, alarms, malformed requests and suspicious
input. Source addresses come from the connection, not untrusted forwarding
headers. Metadata is bounded and identifies state changes as simulated. An
ordinary read is not proof of exploitation; a command attempt is not proof of
physical harm.

History, alarms, sessions, connections, HTTP input, event logs and persisted state
have explicit bounds. Scene state is versioned and staged before replacement;
invalid state is reported rather than silently reset. The controller never
connects to real equipment or executes supplied operating-system commands.

Floods are bounded so they cannot wear out the host disk or hide other visitors:

- **Writes:** every accepted control write is saved to disk before it is
  acknowledged, so the service accepts at most 2 state-changing writes a second
  after a burst of 8. Writes over that are refused with a busy reply and logged
  as `write.denied` with reason `rate`. A write that changes nothing, such as
  setting the value a parameter already has, saves nothing and is never refused.
- **Connections:** one source address keeps at most 8 of the 64 connections open;
  further connections from it are closed at once.
- **Busy service:** when every request slot is taken, the first request each
  source has turned away in a second is logged as `refrigeration.overload`, so a
  flood from one address does not make the others disappear.

This is a documented management subset with original browser assets, not a
complete vendor firmware image. It does not reproduce every StoreView action,
proprietary backup format, fieldbus, hardware fingerprint or disclosed exploit.
Recognizable application/transport differences remain possible.

## Research and validation

The design uses the [official SC/SM XML interface manual](https://assets.danfoss.com/documents/latest/376199/AU342138209420en-000501.pdf),
read-only inspection of the publicly available 3.3 frontend, [Danfoss's current
security-generation documentation](https://www.danfoss.com/en-us/service-and-support/downloads/dcs/adap-kool-software/ak-sm-800a/),
and [Claroty's controller research](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers).
The [French CERT alert](https://cert.cyber.gouv.fr/alerte/CERTFR-2026-ALE-012/) identifies
affected controller families; it does not establish the exact exploit or the
controller model at every affected blood-storage site.

Run the actual packaged-image acceptance tests with Docker:

```bash
QPOT_TEST_REFRIGERATION=1 go test -race -count=1 -timeout 12m ./internal/instance -run '^TestRefrigerationLive'
```

The CI job builds the emitted context and exercises isolated instances. Local
managed Docker environments may still be unable to run the production nftables
guard or enforce cgroups; separate isolated tests do not replace those release
checks on a suitable Linux host.

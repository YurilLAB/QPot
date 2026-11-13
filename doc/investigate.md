# Investigating a session or a campaign

The Events, Threat Intel and Canaries tabs each show one kind of record. An
investigation puts them together for one visitor: open a session or a
campaign and follow it from the first connection to the last command, with
every statement leading back to the stored records it rests on.

```text
connection → credentials tried → commands run → files transferred → canaries tripped → related sessions
```

- [Opening a case](#opening-a-case)
- [What a case holds](#what-a-case-holds)
- [Records and references](#records-and-references)
- [Why sessions are one campaign](#why-sessions-are-one-campaign)
- [Gaps](#gaps)
- [Evidence bundles](#evidence-bundles)
- [Limits](#limits)

## Opening a case

| Where | How |
|---|---|
| Web UI | The **Investigate** tab lists campaigns and the most recent sessions; select one. A session in the Threat Intel tab opens its case too. `#investigate?session=<id>` and `#investigate?campaign=<fingerprint>` link to a case. |
| Terminal | `qpot investigate list`, then `qpot investigate session <session-id>` or `qpot investigate campaign <fingerprint>` |
| API | `GET /api/investigate`, `GET /api/investigate/case`, `GET /api/investigate/export` ([api.md](api.md#investigation)) |

The terminal commands read the instance's database directly, so the instance
must be up; `qpot serve` need not run. All three give the same case.

A session and a campaign are what the intelligence worker stored
([intelligence.md](intelligence.md#sessions-and-campaigns)): a session is one
activity episode of one source, a campaign the sessions that carry one
fingerprint.

## What a case holds

| Part | Contents |
|---|---|
| Summary | Sources, first and last event, events counted and read, honeypots reached, ATT&CK techniques, confidence, and how far the visitor got: connection, credentials, command, transfer, canary |
| Timeline | One per session, in time order. Each step is one event or a run of alike events |
| Files | Each transferred file by SHA-256, with the URLs and names it came by, its transfer records and the command that caused it |
| Campaign evidence | The payloads, download hosts and command sequence of the session, and whether another session shares them |
| Links | For a campaign: each piece of evidence two or more sessions share, and the records that show it in each |
| Canary trips | Trips by the session's source: during the session (also a timeline step), or at another time |
| Related sessions | The other sessions of the campaign, and earlier or later sessions of the same source |
| Gaps | What was cut, discarded, not captured or left out |
| Records | Every stored event the case cites |

How steps are formed:

- **Credentials.** A run of refused logins on one honeypot is one step that
  counts them, lists the first ten pairs tried and still names their records.
  An accepted login is always a step of its own.
- **Commands.** The command as typed. A HiFi SSH cell's command is one step
  from its start and finish records, with its exit code and what it printed
  (see below). Cowrie's "command not found" record is folded into the command
  it belongs to.
- **Transfers.** The URL, the SHA-256 and the stored file name. When an
  earlier command of the same honeypot connection names the transfer's URL,
  host or file, the step says which command and why. It claims nothing when
  no command does.
- **Everything else** is a step with its event type; a burst of the same
  event is one step with a count.

**Captured output.** A HiFi cell's OpenSSH capture is kept in the cell's
record folder, not in the database, so that a decoy credential printed by
`cat` is not mistaken for its reuse. A case reads up to 64 KiB of each
command's output and errors from there, 4 MiB for the whole case. Cowrie
records what was typed and one terminal recording per connection, not what
each command printed: its commands have no output, and the case lists that
under Gaps.

## Records and references

Every step, file, link and gap ends with the references of the records it
rests on. A reference names a stored event by its content: the first 32 hex
characters of the SHA-256 of the fields the collector stored (time, honeypot,
source address and ports, protocol, event type, user name, password, command,
payload and metadata). Classification is not part of it, so an event has the
same reference before and after the worker tags it.

In the web UI a reference is a button that opens the stored event. In the
terminal it is the text in `[brackets]`; `--json` prints the records with the
case. A reference can be recomputed from the record by anyone who holds it,
which is what `qpot investigate verify` does.

## Why sessions are one campaign

The worker links sessions of different sources only on strong shared
evidence and stores a hash of it, not the evidence. A case reads the evidence
again from each session's events, through the same code the worker used, and
shows it in the clear:

| Evidence | Shown as |
|---|---|
| Payload | The SHA-256 of the file, and each session's transfer records |
| Download host | The host, and each session's commands or requests that name it |
| Command sequence | The five commands, and each session's records of them |

A session that carries the campaign's fingerprint but shows no shared
evidence in the events read is reported as a gap: its link was made from
events beyond the limit or no longer stored, from an earlier session of the
same source, or with a session that has no timeline in the case.

## Gaps

A case says what it cannot show. Each gap names the records concerned where
there are any.

| Gap | Meaning |
|---|---|
| `event-limit` | The session has more events than were read. The timeline holds the first ones |
| `events-missing` | The session counted more events than are stored now: retention or disk cleanup removed them |
| `value-cut` | A value too long to store whole was cut. The record holds its beginning, and for a Cowrie command its full length and SHA-256 |
| `line-discarded` | The collector discarded a log line longer than it reads. The record holds the first part of the line |
| `capture-cut`, `capture-error` | A HiFi capture ran out of room or reported an error |
| `output-missing` | A command's output file is gone (disk cleanup) or cannot be read by this user |
| `output-not-captured` | The honeypot records no output per command |
| `command-unfinished` | A command has a start record and no finish |
| `unclassified` | Some events are not classified yet, so the session's techniques and evidence do not count them |
| `shared-source` | The source address is Docker's, not the visitor's: the session is one honeypot connection |
| `unknown-source` | The events have no usable source address and may come from many visitors |
| `same-instant` | Events were stored with the same time as another. The collector stamps an event when it reads it, so the order inside such an instant was not recorded; the timeline shows those events in the usual course of a connection |
| `canary-not-matched` | Canary trips happened during such a session and cannot be matched to it |
| `old-session` | The session was stored by a version that did not group events by source: it has no timeline |
| `session-limit` | A campaign has more sessions than get a timeline (25) |
| `session-scan` | Only the 5,000 most recent sessions are looked through |
| `no-shared-evidence` | See above |
| `source-list` | The source used more addresses than a session lists |

No gap listed means none of these was found. It does not mean the honeypot
saw everything the visitor did.

## Evidence bundles

**Export evidence bundle** in the web UI, or

```bash
qpot investigate export session <session-id> --out case.zip
qpot investigate export campaign <fingerprint> --out case.zip
```

writes the case as a zip archive:

| File | Contents |
|---|---|
| `case.json` | The case |
| `records.jsonl` | Every record the case cites, one JSON object a line |
| `timeline.txt` | The case as text |
| `output/<reference>.stdout`, `.stderr` | What captured commands printed, as bytes |
| `MANIFEST.sha256` | The SHA-256 of every other file, in `sha256sum` format |
| `README.txt` | What the files are and how to check them |

The same case gives the same archive, byte for byte. `qpot investigate
export` prints the archive's SHA-256 and never writes over an existing file.

```bash
qpot investigate verify case.zip
```

checks a bundle with no instance and no database: every file has the hash
the manifest gives, the manifest lists every file, every record has the
reference it is stored under, and every record the case cites is present. It
exits 1 when anything is wrong. `sha256sum -c MANIFEST.sha256` inside the
unpacked archive checks the files alone.

The manifest shows that a bundle is whole, not who made it. Keep the
archive's SHA-256 somewhere else if you may have to prove later that a bundle
is the one you exported.

A bundle holds what visitors sent to a decoy, passwords included, and what
decoy commands printed. It never holds the QPot ID or a canary's secret
value.

## Limits

| Limit | Value |
|---|---|
| Events read per session | 5,000 by default, up to 50,000 (`--max-events`, `max_events`, the selector in the web UI). A campaign's sessions share them |
| Sessions with a timeline in a campaign case | 25, the earliest |
| Sessions looked through | The 5,000 most recently active |
| Records named per step, link or gap | 20, with a count of the rest |
| Cases built at once by the web API | 2; a third request is answered 429 |

Text in a case is attacker input. The terminal output shows control
characters, escape sequences and text-direction marks as visible escapes
(`\x1b`, `\u{202e}`); the web UI inserts it as text only.

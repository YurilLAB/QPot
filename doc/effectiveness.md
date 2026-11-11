# Measuring deception effectiveness

A honeypot is effective when visitors stay, go deep and leave something
usable. `qpot engagement` measures that from stored events. It computes the
same numbers from the JSON log of any Cowrie deployment, so a QPot instance
can be set beside a simpler deployment that ran next to it.

The numbers describe what visitors did. They do not say why. Read the
section on fair comparison before reading anything into a difference.

## Sessions

Every metric is counted over sessions. A session is formed in one of two
ways, decided per event:

- **By session id.** When the honeypot gives its events a session id (Cowrie
  and ADBHoney do), all events of one honeypot with the same id are one
  session, however long the quiet time between them.
- **By source address.** Events without a session id are grouped by honeypot
  and source address. Two events belong to the same session when they are at
  most 30 minutes apart. A gap of more than 30 minutes starts a new session.

An event with neither a session id nor a source address is not used. An
event without a time is not used. The report counts both.

A honeypot that logs some events with a session id and some without gets a
session of each kind for the same visitor.

## Which events count

Events are classed by the honeypot's own event id:

| Class | Event ids |
|---|---|
| Login attempt | ending in `.login.failed`, `.login.success`, `.auth.failed`, `.auth.success` |
| Login | ending in `.login.success` or `.auth.success` |
| Command | ending in `.command.input`, `.command.start` or `.command`, with a non-empty input line |
| Payload | ending in `.file_download` or `.file_upload` |
| Failed fetch | ending in `.file_download.failed` |

Cowrie's `cowrie.command.failed` and QPot's `ssh-proxy.command.finish` repeat
a line that was already counted, so they are not commands. A failed fetch
gives a download URL and host. It is not a payload.

One Cowrie command event is one input line. A line such as
`uname -a; nproc` is one command.

## Metrics

All metrics are given for every honeypot together and per honeypot.

### Funnel

The number of sessions that reached each step, and its share of all
sessions:

- attempted a login;
- logged in;
- ran at least one command (an *interactive* session);
- fetched or uploaded a payload.

The steps are counted independently. A honeypot that needs no login can have
interactive sessions that never logged in.

### Engagement duration

The length of a session is the time of its last event minus the time of its
first event. When the honeypot states the length itself (Cowrie's
`cowrie.session.closed` has a `duration`), that value is used instead, and
the report says for how many sessions.

The reason is the clock. QPot stores the time at which the collector handled
an event, not the time in the honeypot's log. The two are close while the
collector follows the log, and far apart when it catches up after a stop:
then every waiting event gets nearly the same time. The stated duration does
not have this problem and is the same number in the database and in the log.

Given over all sessions and over the sessions that logged in:

- **median**: the middle value, or the mean of the two middle values;
- **p90**: the value at rank `ceil(0.9 n)` of the sorted lengths;
- **max**;
- **total**: the sum, in seconds.

### Session depth

The number of commands per interactive session: median, p90 and max.

### Command diversity

- **Distinct commands**: the number of different input lines, after white
  space at the ends is removed and every run of white space is made one
  space.
- **Distinct commands per interactive session**: the median.
- **Command stem entropy**: the Shannon entropy, in bits, of the command
  stems: `H = -sum(p_i * log2(p_i))`, where `p_i` is the share of input lines
  with stem `i`. A stem is the first word of the line after leading
  `VAR=value` assignments, `sudo` and its options, and the directory part are
  removed, in lower case. `LC_ALL=C sudo /usr/bin/Wget http://...` has the
  stem `wget`. Zero bits means every line used the same command.
- **Top stems**: the ten most used, with counts.

### Left after a probe

Of the interactive sessions, the share with at most 3 commands whose last
command is an environment or fingerprint probe.

A line is a probe when every command on it is one of these:

- `uname`, `nproc`, `free`, `lscpu`, `id`, `whoami`, `w`, `ps`, `dmesg`,
  `df`, with any arguments;
- `mount` and `hostname` without an operand;
- `cat` of `/proc/cpuinfo`, `/proc/version`, `/proc/meminfo`, `/etc/issue`,
  `/etc/os-release` or `/etc/passwd` only;
- `echo` that prints to the terminal, such as `echo ok` or
  `echo -e "\x6F\x6B"`;
- `busybox` alone, `busybox` with one made-up applet name in upper case
  (`/bin/busybox ECCHI`), or `busybox` followed by one of the commands above;
- `ls`, but only in a session without a payload.

In a pipeline the first command must be a probe and the rest must be text
filters (`grep`, `head`, `tail`, `wc`, `awk`, `cut`, `sort`, `uniq`, `tr`,
`sed`, `cat`, `more`, `less`). A command that writes to a file or uses
command substitution is not a probe. When several commands share the last
timestamp of a session, all of them must be probes.

**This is a proxy.** A session that probes and leaves may have recognised a
honeypot. It may also belong to a bot that only ever probes, or to one that
found the wrong architecture. The events look the same. The number is useful
when two deployments with the same exposure are compared: the same bots
visit both, so a higher share on one side points at something that side
shows them.

### Returning sources

Of the source addresses with at least one interactive session, the share
that started another session at least 1 hour after one of their interactive
sessions ended. Sessions without a source address are left out.

### Actionable intelligence

Distinct counts, and each per 1000 sessions:

- **payload hashes**: SHA-256 hashes of fetched or uploaded files;
- **download URLs** and **download hosts**, from fetches, failed ones
  included;
- **credential pairs that logged in**: username and password together;
- **ATT&CK techniques**, where the events carry them. A raw Cowrie log does
  not: classification is QPot's. Leave this row out of a comparison with a
  log.

## Limits

Memory stays bounded on any input. Each limit is fixed, and the report says
when one was reached:

| What | Limit | Effect when reached |
|---|---|---|
| Each set of distinct values (commands, hashes, URLs, hosts, credential pairs, techniques), per scope | 50000 | the count stops at the limit and is a lower bound |
| Command stems, per scope | 10000 | the kept stems keep exact counts; the others count as one stem in the entropy, which is then a lower bound |
| Distinct commands remembered per session | 64 | the session counts as 64 |
| Session keys: (honeypot, session id) pairs plus (honeypot, source) pairs | 2000000 | sessions, funnel, duration, depth, left after a probe and returning sources cover a fixed sample of keys; diversity and intelligence still cover every event |
| Cowrie log line | 1 MiB | the line is skipped and counted |

A scope is one honeypot, or all honeypots together. The result does not
depend on the order of the events, with or without a limit reached.

## Running it

```
qpot engagement -i sensor1                       # the last 7 days
qpot engagement -i sensor1 --since 30d
qpot engagement -i sensor1 --honeypot cowrie     # one honeypot
qpot engagement -i sensor1 --json
```

The instance's database must be running. The command reads the stored events
of the window in batches and prints a table: one row per metric, with the
direction that is better for a deception honeypot. Rows that depend on
exposure or on a single session (session counts, totals, maxima) have no
direction.

`--since` takes days (`7d`), weeks (`2w`) or a duration (`36h`).

### Comparing with a Cowrie log

`--cowrie-log` reads a Cowrie JSON log: one JSON object per line with
`eventid`, `timestamp`, `src_ip`, `session` and, where they apply,
`username`, `password`, `input`, `url`, `shasum` and `duration`. This is the
file stock Cowrie writes as `cowrie.json` and T-Pot keeps under its Cowrie
log folder.

```
qpot engagement -i sensor1 --honeypot cowrie \
    --cowrie-log /data/stock/cowrie.json --label stock
```

This prints the instance and the log side by side, with the difference
(second minus first). Give `--cowrie-log` more than once to add columns;
each `--label` names the log at the same position. Without a label the
column is named after the file.

With only `--cowrie-log` the command needs no instance and no Docker:

```
qpot engagement --cowrie-log a.json --cowrie-log b.json
```

A log is read whole unless `--since` is given. With `--since`, events
outside the window are left out and counted. A line that is not a Cowrie
event is counted and skipped; it never stops the run.

`--json` prints the reports and, for more than one, the comparison of the
first with each of the others.

## A fair live comparison

Two deployments can only be compared when the same visitors could reach
both in the same way. Otherwise the difference measures the exposure, not
the honeypot.

- **Same network.** Put both on addresses in the same range, at the same
  provider. Scanners treat address ranges differently, and some ranges are
  known to host honeypots.
- **Same ports and exposure.** The same service on the same port on both,
  with the same firewall rules. SSH on port 22 and SSH on port 2222 see
  different visitors.
- **Same period.** Run both over the same days. Campaigns come and go; a
  week with a large campaign and a week without are not comparable.
- **Long enough.** At least a few weeks. One campaign can dominate a short
  window.
- **Compare medians and funnels, never single sessions.** One long session
  moves a maximum or a total and says nothing about the deployment. The
  table gives maxima and totals no direction for this reason.
- **Compare the same honeypot.** Use `--honeypot cowrie` on the instance
  when the other side is a Cowrie log.
- **Look at the session counts first.** If one side has many times the
  sessions of the other, their exposure differed, and the rates are not
  comparable either.

**Source addresses can collapse.** A honeypot behind NAT, or behind Docker's
userland port proxy, can see every connection arrive from one address: the
gateway's or the proxy's. Then the logged source is not the visitor. Session
ids still separate the sessions, so the funnel, duration, depth and
diversity stay right. But sessions formed by source address merge into a
few long ones, and returning sources becomes meaningless: one "source"
always returns. Check that both deployments log real, varied source
addresses before trusting those numbers. If one side does not, compare only
honeypots that log a session id, and ignore returning sources.

Also keep in mind what each side records. A stock Cowrie with no outbound
network access cannot fetch a payload, so its payload step stays at zero
whatever the visitor intended; its download URLs still count.

## Results of the last recorded run

No comparison against a stock Cowrie has been recorded: that needs both
deployments exposed to the internet side by side for weeks, as described
above. What has been recorded is a check of the tool itself against traffic
whose answers are known.

2026-11-11: `qpot engagement -i <instance> --since 1d --honeypot cowrie` on
the instance of the three-hour failure soak ([reliability.md](reliability.md)).
The soak's load is scripted: about 57,000 connections that only exchange
SSH version strings, and 1,113 login attempts of which 1,077 got in and each
ran the same three commands (`uname -a`, an `echo … > file`, an `nmap`).
All of it arrives from one address, Docker's gateway.

| Metric | Reported | Expected from the load |
|---|---|---|
| Sessions | 57,542 | about 57,556: 56,781 accepted connections and 1,113 logins, less the 338 the soak lost to a full disk |
| Attempted a login | 1.9% | 1,113 of 57,542 = 1.9% |
| Logged in, ran a command | 1.9% | 1,077 of 57,542 = 1.9% |
| Commands per interactive session, median and p90 | 3 | 3 |
| Commands per interactive session, max | 6 | 3; three sessions were stored twice by a fault the soak injected, which the soak itself reported |
| Top command stems | `echo`, `nmap`, `uname`, 1,080 each | 1,077 each, plus the same three duplicates |
| Command stem entropy | 1.58 bits | log2(3) = 1.58 |
| Payload hashes | 1,077 | one file written per session |
| Download URLs and hosts | 0 | 0: the URL was echoed, not fetched |
| Left after a probe | 0.0% | 0: the last command is `nmap`, not a probe |
| Returning sources | 100% | meaningless here: one source, as the section above warns |
| Session duration, logged in, median | 0.3 s | a scripted client; says nothing about people |

Every figure matches what the load did. These are not attacker numbers and
say nothing about how well the deception works.

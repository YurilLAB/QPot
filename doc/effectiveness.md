# Measuring deception effectiveness

A honeypot is effective when visitors stay, go deep and leave something
usable. `qpot engagement` measures that from stored events. It computes the
same numbers from the JSON log of any Cowrie deployment, so a QPot instance
can be set beside a simpler deployment that ran next to it.

The numbers describe what visitors did. They do not say why. Read the
sections on reading a comparison and on fair comparison before reading
anything into a difference.

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

### Intervals

A report covers the sessions that happened to arrive. Another week would
give other sessions and slightly different numbers. A **95% interval** is a
range around a number that allows for this: if the same deployment were
measured many times, 95 of 100 such ranges would hold the true value.

Every share and every median has one:

- **Shares** (the four funnel steps, left after a probe, returning sources):
  the Wilson score interval. It stays inside 0% to 100% and works for small
  counts and for shares near 0% or 100%.
- **Medians** (session duration over all sessions and over the sessions that
  logged in, commands per interactive session, distinct commands per
  interactive session): two of the sorted values, the `r`-th smallest and
  the `r`-th largest. `r` is the largest rank for which fewer than `r` of
  `n` fair coin flips come up heads with a chance of at most 2.5%. For 10
  sessions these are the 2nd and the 9th value; for 100 sessions, the 40th
  and the 61st. This needs no assumption about how the values are spread.
  With fewer than 6 values there is no interval.

Counts, maxima, totals, p90 values, the stem entropy and the rates per 1000
sessions have no interval.

An interval allows for chance only. It treats the sessions as independent.
One bot that opens a thousand sessions makes the interval narrower than it
should be.

### Source addresses

A report counts the distinct source addresses of its sessions, for all
honeypots together:

- An IPv4 address counts as itself.
- An IPv6 address counts as its /64, the smallest block one host is usually
  given. Two addresses in the same /64 are one source.
- An IPv4 address written as IPv6 (`::ffff:203.0.113.5`) counts as the IPv4
  address.

A source is **reserved** when it cannot be a visitor from the internet:
private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`),
loopback, link-local, carrier-grade NAT (`100.64.0.0/10`), multicast,
unspecified, `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, or
text that is not an address. Every other source is **public**. The
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`) count as public: real traffic cannot come from them, and
examples and tests use them.

The report gives the number of sources, how many are public and how many
reserved, the sessions without any source address, the sessions from
reserved sources, and the **busiest source**: the number of sessions of the
source with the most, and its share of all sessions.

Sources count as **collapsed** when one source has more than 50% of the
sessions, or the reserved sources together have more than 50%. The logged
address is then probably a gateway or a proxy, not the visitor. The section
on fair comparison says how this happens.

Returning sources (above) still uses each address exactly as logged.

## Limits

Memory stays bounded on any input. Each limit is fixed, and the report says
when one was reached:

| What | Limit | Effect when reached |
|---|---|---|
| Each set of distinct values (commands, hashes, URLs, hosts, credential pairs, techniques), per scope | 50000 | the count stops at the limit and is a lower bound |
| Command stems, per scope | 10000 | the kept stems keep exact counts; the others count as one stem in the entropy, which is then a lower bound |
| Distinct commands remembered per session | 64 | the session counts as 64 |
| Session keys: (honeypot, session id) pairs plus (honeypot, source) pairs | 2000000 | sessions, funnel, duration, depth, left after a probe and returning sources cover a fixed sample of keys; diversity and intelligence still cover every event |
| Sessions kept for each rank test of a comparison | 100000 | the test runs on a fixed sample of that many sessions; medians and their intervals still cover every session |
| Source addresses kept for the source overlap and the shared-source analysis of a comparison | 200000 | both cover a fixed part of the address space, the same on both sides; the source counts of each report still cover every source |
| Cowrie log line | 1 MiB | the line is skipped and counted |

A scope is one honeypot, or all honeypots together. The result does not
depend on the order of the events, with or without a limit reached.

The two samples are not picked at random and not by what a session did.
Each session and each source gets a number computed from its key (a hash),
and the ones with the smallest numbers are kept. The same input always
gives the same sample. Two reports keep the same sources, so their overlap
can still be counted.

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

Under the table come the 95% intervals of the shares and medians, and for
each report its source addresses.

### Comparing two instances

`--against` names another instance on this host:

```
qpot engagement -i treat --against control --honeypot cowrie
```

Both databases must be running. Both instances are read over the same
`--since` window and with the same `--honeypot` filter. The instance named
by `-i` is the first report. Give `--against` more than once to compare the
first instance with several others. `--against` needs `-i`.

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

`--against` and `--cowrie-log` can be used together. The reports come in
this order: the instance named by `-i`, the `--against` instances, the logs.

## Reading a comparison

With more than one report, the first report is compared with each of the
others. The first report is side **A**. The other is side **B**. Every
difference is B minus A.

A comparison has four parts: an exposure check, intervals, verdicts, and a
table of shared sources. Read them in that order.

### The exposure check

The exposure check is printed before the table. It answers one question:
did the two sides see about the same amount of traffic over the same time?
If not, a difference in the table comes from the exposure, not from the
deployment.

It prints, for each side:

- the number of sessions;
- the number of source addresses, and how many of them are public;
- the first and the last event, and the time between them (the period).

And for the two together:

- the **session ratio** and the **source ratio**: the larger number divided
  by the smaller;
- the **period overlap**: the time both periods cover, as a share of the
  combined period (from the earlier first event to the later last event);
- the public sources seen by both sides, and the **Jaccard index**: that
  number divided by the number of public sources seen by either side. 1
  means both saw exactly the same sources. 0 means they share none.

The check fails, and prints `NOT COMPARABLE`, when:

- the session ratio is above 3;
- the period overlap is below 80%;
- one side has no sessions.

The numbers are printed either way. After a failed check, read the table as
a description of each side. Do not read it as the effect of the deployment.

A passed check is not proof. It shows that the volume and the days match.
It does not show that the same visitors came, or that both sides were
reachable in the same way. The section "A fair live comparison" lists what
must also hold.

A low Jaccard index does not fail the check. Scanners pick addresses at
random, so two honeypots next to each other often see different sources in
a short period. A low index only means that the shared-source table rests
on few sources.

### Intervals

Each share and each median has a 95% interval per side (see Intervals
above). They are printed in their own table under the main one.

A wide interval means the number is not known well: there were few sessions
behind it. Two intervals that overlap a lot mean the two sides may well be
the same.

For a share, the comparison also gives a 95% interval for the difference B
minus A, in percentage points (Newcombe's hybrid score interval, built from
the two Wilson intervals). If this interval holds 0, the data fit "no
difference". The interval also shows how large the difference may be, which
a verdict alone does not.

### Verdicts

A **tested row** is a row with a direction and a test:

| Rows | Test |
|---|---|
| Logged in, ran a command, fetched or uploaded a payload, left after a probe, returning sources | Fisher's exact test of two shares |
| Session duration (all sessions, logged-in sessions), commands per interactive session, distinct commands per interactive session | Mann-Whitney U test, with the normal approximation, tie correction and continuity correction |

A test gives a **p-value**: the chance of a difference at least this large
if the two sides were in truth the same. A small p-value means chance is a
poor explanation.

Several rows are tested at once. With many tests, one of them looks
unusual by chance alone. So the p-values are corrected together with
**Holm's method**: the smallest is multiplied by the number of tested rows,
the next by one less, and so on. The result is the **adjusted p-value**.
With it, the chance of even one false "clear difference" in the whole table
stays at 5% or below.

Each tested row then gets a verdict:

- **clear difference**: the adjusted p-value is 0.05 or less. Chance alone
  is unlikely to give a difference this large.
- **no clear difference**: the adjusted p-value is above 0.05. Chance could
  have done it. This does not mean the two sides are the same. It means the
  data cannot tell them apart. Look at the interval to see how large a
  difference is still possible.
- **too few to compare**: one side has fewer than 30 sessions in the base
  of the row (for returning sources: fewer than 30 sources with an
  interactive session). No test is made.

The base of a row is what its share or median is taken over: all sessions,
the sessions that logged in, or the interactive sessions.

The verdict does not say which side is better. The sign of the difference
and the BETTER column of the main table say that.

For a median row, the table shows `B>A 62.0% of pairs` instead of an
interval. Take every pair of one session from A and one from B. This is the
share of pairs in which the session from B has the larger value. A tie
counts as half. 50% means neither side tends to be larger. The Mann-Whitney
test asks whether this share differs from 50%. So it compares the sessions
as a whole, not only the two medians: the medians can be equal while one
side still has clearly more long sessions.

Rows without a direction (counts, totals, maxima) are not tested. The p90
rows, the stem entropy and the rates per 1000 sessions are not tested
either: there is no simple exact test for them here. "Attempted a login"
has no direction, so it gets intervals and no verdict.

The interval of a difference and the verdict can disagree near the border.
The interval is for one row alone and is approximate. The verdict uses an
exact test and allows for all tested rows. When they disagree, trust the
verdict.

### Shared sources

A **shared source** is a public source that both sides saw. It is the
strongest control there is: the same visitor met both deployments, so a
difference in what it did is not a difference between visitors.

For each shared source, five things are compared between the sides:

- whether it logged in;
- whether it ran a command;
- whether it fetched or uploaded a payload;
- its largest number of commands in one session;
- its longest session.

For each of the five, the table counts the shared sources that went
**further on A**, **further on B**, and that **tied**. Then it tests whether
"further on A" and "further on B" are balanced, with the exact sign test:
if the deployment made no difference, each source that did not tie would
fall on either side with the same chance. For the three yes/no measures
this is the exact McNemar test. The five p-values are corrected with Holm's
method, as above but separately from the main table, and each row gets the
verdict "clear difference" or "no clear difference".

Reserved sources are never paired. An address such as `10.0.0.1` on both
sides is not the same visitor.

The table is left out, with the reason printed, when:

- sources have collapsed on one side (see Source addresses above): the
  address is then not the visitor;
- no public source was seen by both sides.

### What a comparison does not prove

- **A verdict is about chance, not about cause.** "Clear difference" means
  chance is a poor explanation. It does not say the deployment caused the
  difference. A different port, address range or week can cause it too.
- **The tests treat sessions as independent.** One bot with a thousand
  sessions counts as a thousand visitors. A clear difference can then come
  from a single source. The shared-source table counts each source once, so
  check whether it agrees.
- **A shared source is an address, not a person.** Behind one address there
  can be many machines, and an address can change hands. A source may also
  act differently on its second visit, whichever side that is.
- **Shared sources are not all visitors.** They are the ones that reached
  both sides, often the broad scanners. What holds for them may not hold
  for the rest.
- **"No clear difference" is not "no difference".** With few sessions, even
  a large difference stays unclear.
- **Limits.** When a report says a limit was reached, the tests and the
  overlap cover a sample, as the Limits table says.

### In the JSON

Each report has:

| Field | Meaning |
|---|---|
| `source_addresses` | the source figures: `sources`, `public_sources`, `reserved_sources`, `sessions_without_source`, `sessions_from_reserved_sources`, `busiest_source_sessions`, `busiest_source_percent`, `collapsed`, `collapsed_reason` |
| `overall.intervals_95` and `honeypots[].intervals_95` | one entry per share or median: `key` (the row), `low`, `high`, `n` (the base) and `method` (`wilson` or `order-statistics`) |
| `limits.rank_test_sessions`, `limits.rank_test_sessions_reached` | the sample limit of the rank tests, and whether the report has more sessions |
| `limits.paired_sources`, `limits.paired_sources_reached` | the limit on sources kept for the overlap, and whether the report has more |

Each comparison has:

| Field | Meaning |
|---|---|
| `exposure` | the exposure check: `a` and `b` (label, sessions, sources, public sources, first and last event, period in seconds), `session_ratio`, `source_ratio`, `period_overlap_seconds`, `period_overlap_percent`, `shared_sources`, `source_jaccard`, `comparable`, `problems` |
| `exposure.sources_known` | false when a report has no source table, which happens only when a report is read back from JSON |
| `exposure.sources_sampled`, `compared_public_sources_a`, `compared_public_sources_b` | whether a source limit was reached, and how many public sources of each side the overlap covers |
| `deltas[]` | one entry per row. Beside the old fields: `a_interval`, `b_interval`, `difference_interval` (`low`, `high`, for shares), `a_n`, `b_n` (the bases), `test` (`fisher-exact` or `mann-whitney`), `a_sample`, `b_sample` (sessions used by the rank test), `b_larger_probability` (the share of pairs, as 0 to 1), `p_value`, `p_adjusted`, `verdict` |
| `tested_rows` | the number of rows Holm's method was applied over |
| `paired` | the shared sources: `shared_sources`, `skipped`, `reason`, `sampled`, and `measures[]` with `key`, `name`, `a_further`, `b_further`, `tied`, `p_value`, `p_adjusted`, `verdict` |
| `notes` | what limits the reading of this comparison |

A field of a row is left out when it does not apply: a row that is not
tested has no `p_value` and no `verdict`.

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
- **Long enough.** At least four weeks. One campaign can dominate a short
  window.
- **Compare medians and funnels, never single sessions.** One long session
  moves a maximum or a total and says nothing about the deployment. The
  table gives maxima and totals no direction for this reason.
- **Compare the same honeypot.** Use `--honeypot cowrie` on the instance
  when the other side is a Cowrie log.
- **Look at the exposure check first.** If it says the sides are not
  comparable, the rest of the table is not evidence.

**Source addresses can collapse.** A honeypot behind NAT, or behind Docker's
port proxy, can see every connection arrive from one address: the gateway's
or the proxy's. Then the logged source is not the visitor. QPot marks such
events and `qpot doctor` reports them as "source addresses" (QP-NET-015).
Session ids still separate the sessions, so the funnel, duration, depth and
diversity stay right. But returning sources and the shared-source table
mean nothing. Both sides must show "source addresses: the visitors' own" in
`qpot doctor` before a run counts. [release.md](release.md#source-addresses)
lists the Docker setups where this holds.

Also keep in mind what each side records. A stock Cowrie with no outbound
network access cannot fetch a payload, so its payload step stays at zero
whatever the visitor intended; its download URLs still count.

## The controlled experiment

This is the procedure for the comparison that the numbers on this page are
for: QPot's Cowrie against a simpler deployment, on real traffic, with
everything else equal. It has two arms.

| Arm | What runs | How |
|---|---|---|
| Treatment | QPot's Cowrie: the T-Pot image with QPot's corrected commands, state and bait | The default |
| Control | The T-Pot image's Cowrie as shipped | `qpot honeypot set cowrie deception=stock` |

Both arms are QPot instances of the same version. So the host hardening,
the network path, the collector and the analysis are the same on both
sides, and the only difference is what QPot adds to Cowrie. `deception=stock`
mounts nothing of QPot's over the image's source and plants no bait. It
exists for this purpose only.

### What you need

- Two hosts with one public IPv4 address each, at the same provider, in the
  same address range, with the same size, operating system and Docker
  version. Use addresses that have not hosted a honeypot before.
- Docker Engine on Linux with default settings on both
  ([release.md](release.md#source-addresses)).
- Four weeks.

Two hosts are needed because both arms must answer on port 22, and one
address has one port 22.

### Before the run

Write down, before any traffic arrives, which rows decide the result, and
how many sessions each arm needs. This page suggests three rows:

1. "Ran a command" in the funnel: the share of sessions that became
   interactive.
2. "Commands per interactive session, median".
3. "Left after a probe": lower is better.

Everything else is context. A row picked after looking at the table is not
a result.

How many sessions are enough depends on how often visitors already do the
thing on the control arm and on how small a difference should be found. The
comparison tests up to nine rows and corrects for that (Holm), so the
smallest p value must be under 0.05 / 9. For a share such as "Ran a
command", the usual normal approximation for two proportions at that level,
with an 80% chance of finding a difference that is really there, gives
these sessions per arm (a calculation, not a measurement):

| Share on the control arm | Difference to find | Sessions per arm |
|---|---|---|
| 5% | 2 points | 3,678 |
| 5% | 5 points | 719 |
| 10% | 2 points | 6,389 |
| 10% | 5 points | 1,137 |
| 20% | 5 points | 1,816 |
| 20% | 10 points | 483 |
| 40% | 5 points | 2,548 |

Read the control arm's share after the first week, pick the row, and keep
both arms running for the four weeks or until both have that many
sessions, whichever is later. The shared-source table needs sources that
reached both arms, and only a run can say how many there are; the report
says "too few to compare" where a row has fewer than 30 sessions on a side.

### Setting up each arm

On both hosts:

```bash
qpot instance create arm
qpot honeypot list -i arm                 # see what is enabled
qpot honeypot disable <name> -i arm       # for each one except cowrie
```

Keep the backups for longer than the run, in `~/.qpot/instances/arm/config.yaml`:

```yaml
cleanup:
  max_age_days: 60
  max_backup_mb: 20000
```

On both hosts, the same persona (any ID that `qpot honeypot set` lists for
`persona`; `ubuntu-noble` here):

```bash
qpot honeypot set cowrie persona=ubuntu-noble -i arm
```

Without it each instance draws its own persona from its seed, and the two
arms would present different machines (another OpenSSH release, another
distribution, other files): a difference that has nothing to do with QPot's
layer.

On the control host only:

```bash
qpot honeypot set cowrie deception=stock -i arm
```

Then, on both hosts within the same hour:

```bash
qpot up -d -i arm
qpot doctor -i arm
```

Check on both that Cowrie answers on port 22 (`qpot status -i arm`), and do
not connect to either honeypot yourself again. After the first day,
`qpot doctor -i arm` must show "source addresses: the visitors' own" on
both.

### After the run

Bring the control arm's events to the treatment host. The log backups hold
every event; `qpot db restore` loads them into an instance of their own.

```bash
# on the control host
qpot down -i arm
sudo tar -czf control-logs.tgz -C ~/.qpot/instances/arm/backup logs
# copy control-logs.tgz to the treatment host, then there:
mkdir control-logs && tar -xzf control-logs.tgz -C control-logs
qpot instance create control
qpot honeypot disable <name> -i control   # every honeypot: this instance only holds data
qpot up -d -i control
qpot db restore -i control --from control-logs/logs
qpot engagement -i arm --against control --honeypot cowrie --since 28d
```

Read the output in the order of ["Reading a comparison"](#reading-a-comparison):
the exposure check, then the three rows chosen beforehand with their
verdicts, then the shared-source table. The shared-source table is the
strongest part: it compares what the same visitor did on each arm.

Record the full `--json` output with the result, so that someone else can
check it.

### What the result can and cannot say

It can say that, over these four weeks, visitors who reached both arms went
further on one than on the other, with a stated error rate.

It cannot say why. It cannot say the same holds for another address range,
another month or another service. And it compares against T-Pot's Cowrie,
which is already a tuned deployment: a plain upstream Cowrie may differ
more. To compare with one, run it on a third address and pass its
`cowrie.json` with `--cowrie-log`.

## Results of the last recorded run

**The controlled experiment has not been run.** It needs two public
addresses exposed for four weeks. There are no attacker numbers on this
page yet, and nothing here says how well the deception works.

### The procedure, checked in a lab (2026-11-13)

The setup above was followed on one Linux host (Docker 26.1.5), with both
arms bound to that host only and ordinary SSH sessions as the only traffic,
to check that an operator can carry it out and that the report works:

- **Two arms.** `qpot instance create`, every honeypot but Cowrie disabled,
  `persona=ubuntu-noble` on both and `deception=stock` on the control,
  `qpot up -d`, `qpot doctor`: all checks passed on both.
- **They differ only in QPot's layer.** With the instance name, the
  credentials, the ports, the network names and the addresses masked, the
  two generated compose files differ in 23 lines, all of them in the
  treatment's Cowrie service: the 22 read-only mounts of QPot's corrected
  source files and the bait plan. The collector configurations are the
  same. The running containers have the same image digest, the same
  environment, the same read-only root, capabilities, memory, PID and CPU limits and
  runtime. The control's `etc` folder lacks the treatment's
  `qpot-jsonlog.spill`, which belongs to QPot's log writer.
- **Traffic.** 40 sessions to each arm at the same time, each logging in as
  root, running `echo hello N`, `ls`, `uname -a` and `exit` in a shell. The
  image lets a source log in only after two to five different passwords;
  instead of trying passwords, the lab put the one password into the
  image's login cache of both arms beforehand, so every session logged in
  at its first try (40 of 40 on each arm). Earlier attempts of the lab's
  own script are in the same window, the same on both arms: 240 refused
  password logins and 40 key logins its SSH client could not complete.
- **Report.** `qpot engagement -i treatment --against control --honeypot
  cowrie --since 1d`: 320 sessions and 1,920 events on each side, the
  exposure check passed, every row equal or within 0.3 s, and every tested
  row "no clear difference" (adjusted p 1.000). Returning sources and the
  shared-source table were reported as meaningless, rightly: all sessions
  came from one address, Docker's gateway.
- **Transfer.** The control was stopped, its `backup/logs` packed with
  `tar` (as the instance's user; `sudo` was not needed there), unpacked,
  and restored into a third instance with every honeypot disabled:
  `qpot db restore` stored 1,920 events, 0 unreadable. The comparison
  against that instance gave the same table as against the running control.

`TestCompareHarmlessTraffic` checks the other half on synthetic sessions of
the same shape: the same visitors doing the same thing on both arms give no
clear difference, and the same visitors running one command instead of
three on one arm give a clear one. `TestCompareVerdicts` and
`TestCompareIdenticalArms` cover the rest of the tests.

What the lab did not check: anything about real visitors, the shared-source
table with real public addresses, and a run of four weeks (backup sizes and
the database over that time).

What has been recorded is a check of the tool itself against traffic whose
answers are known.

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

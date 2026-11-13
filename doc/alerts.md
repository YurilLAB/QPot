# Alerts and response hooks

QPot raises two kinds of alert:

- a **volume alert** when the events per minute cross a threshold;
- **behaviour alerts** on what a visitor does: a new payload, a session that
  moves on to persistence, a planted credential carried to another service,
  sources that share a playbook, a visitor who comes back.

Both can post to a webhook and run your own commands. Canary trips are
reported as critical alerts too; see [canary.md](canary.md).

- [Volume alert](#volume-alert)
- [Behaviour alerts](#behaviour-alerts)
- [Response hooks](#response-hooks)

## Volume alert

```yaml
alerts:
  enabled: true
  webhook_url: https://hooks.slack.com/services/...   # Slack, Discord or any URL
  threshold: 100      # events per minute
  cooldown: 5m

response:
  enabled: true
  on_attack_detected:
    - name: block-top-attacker
      command: 'iptables -I INPUT -s "$QPOT_TOP_SOURCE_IP" -j DROP'
      timeout: 10s
```

### Webhook payload

The webhook receives a JSON body with these fields:

- `instance`, `timestamp`;
- `total_events`, `unique_ips`;
- `message`, and `top_honeypot` when known.

It never contains the QPot ID, which is the web UI's login credential.

## Behaviour alerts

Behaviour alerts need no settings: they are on whenever the intelligence
worker is (`intelligence.enabled`), and each thing alerts once.

| Rule | Severity | Raised when |
|---|---|---|
| `new-payload` | high | A file was downloaded or uploaded whose SHA-256 this instance has not recorded before |
| `progression` | high | One session reached discovery and, after it, persistence: it looked around and then tried to stay (a cron job, an SSH key, a new account or service) |
| `credential-reuse` | critical | A credential QPot planted in one honeypot was captured in a session of another: it was read there and carried over |
| `shared-playbook` | medium | Different sources carry one campaign: the same payload, download host or command sequence. Raised when a second source joins, and again at 5, 10, 25, 50, 100, 250, 500 and 1,000 sources |
| `returning-visitor` | medium | A source that ran commands in an earlier session comes back at least an hour later and runs commands again |

What a rule reads:

- sessions, their stages and campaigns are the intelligence worker's
  ([intelligence.md](intelligence.md#sessions-and-campaigns)), so a rule can
  fire up to one worker run plus one minute after the events;
- the stages of `progression` are the ATT&CK tactics of the session's
  events, in the order the session first reached them;
- `credential-reuse` reads canary trips: it needs the planted bait
  ([canary.md](canary.md)) and fires only when the honeypot of the trip is
  not the one the credential was planted in;
- a session whose source address is Docker's own, or that has none, is no
  single visitor: it never returns and joins no campaign.

**The first look is a baseline.** What is stored when the rules first run is
remembered and does not alert, so turning them on never reports the past. The
same holds for a rule that was off: what happened meanwhile does not alert
when it is turned on again.

One look raises at most 25 alerts, the most severe first; the rest follow a
minute later. The 500 most recent alerts are kept in the instance's data
folder (`behaviour.json`), with what has been alerted on. If that file cannot
be read, the rules stop and say so rather than start over from a new
baseline: move the file away to start again.

### Where an alert goes

- The list: the **Investigate** tab of the web UI and `qpot alerts`. An alert
  about a session or a campaign opens its case
  ([investigate.md](investigate.md)).
- The control plane's log, as a warning.
- `alerts.webhook_url`, when one is set (the volume alert need not be
  enabled). The body is JSON:
  `instance`, `timestamp`, `kind` (`"behaviour"`), `rule`, `severity`,
  `message`, `detail`, and where known `session_id`, `campaign_fingerprint`,
  `source_ips` and `evidence`. It never contains the QPot ID.
- The `response.on_behaviour` hooks, once per alert.

### Turning rules on and off

```bash
qpot alerts                            # the rules and the most recent alerts
qpot alerts disable returning-visitor
qpot alerts enable all
```

The same switches are on the Investigate tab. They are saved in the
instance's settings file:

```yaml
alerts:
  behaviour:
    disabled: false          # true turns every rule off
    off: [returning-visitor] # the rules that are off

response:
  enabled: true
  on_behaviour:
    - name: page-on-call
      command: '/usr/local/bin/page "$QPOT_ALERT_SEVERITY: $QPOT_ALERT_TITLE"'
      timeout: 10s
```

A change takes effect at the next look, within a minute.

## Response hooks

`on_attack_detected` hooks run on a volume alert, `on_behaviour` hooks on
each behaviour alert. Volume hooks get these environment variables:

- `QPOT_SENSOR_ID`, `QPOT_INSTANCE`, `QPOT_TIMESTAMP`;
- `QPOT_ID`, the API credential, for a hook that calls the API. Use
  `QPOT_SENSOR_ID` to label what a hook sends elsewhere;
- `QPOT_TOTAL_EVENTS`, `QPOT_UNIQUE_IPS`, `QPOT_THRESHOLD`;
- `QPOT_TOP_SOURCE_IP`, `QPOT_TOP_HONEYPOT`.

Behaviour hooks get `QPOT_SENSOR_ID`, `QPOT_INSTANCE`, `QPOT_TIMESTAMP` and
`QPOT_ID` as well, and:

- `QPOT_ALERT_RULE`, `QPOT_ALERT_SEVERITY`, `QPOT_ALERT_TITLE`;
- `QPOT_ALERT_SESSION` and `QPOT_ALERT_CAMPAIGN`, empty when the alert names
  none;
- `QPOT_ALERT_SOURCE_IP`, the first source address, when there is one.

The values are never interpolated into the command. Each hook runs with its
timeout, in its own process group, as the user that runs the control plane.
Anyone who can edit the instance's `config.yaml` can therefore run commands as
that user, so keep the file private. An alert's title and addresses come from
what visitors did: quote the variables in a hook, as above.

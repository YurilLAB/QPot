# Alerts and response hooks

QPot can post an alert to a webhook when attack volume crosses a threshold,
and run your own commands in response.

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

## Webhook payload

The webhook receives a JSON body with these fields:

- `instance`, `timestamp`;
- `total_events`, `unique_ips`;
- `message`, and `top_honeypot` when known.

It never contains the QPot ID, which is the web UI's login credential.

## Response hooks

Hooks get these environment variables:

- `QPOT_SENSOR_ID`, `QPOT_INSTANCE`, `QPOT_TIMESTAMP`;
- `QPOT_ID`, the API credential, for a hook that calls the API. Use
  `QPOT_SENSOR_ID` to label what a hook sends elsewhere;
- `QPOT_TOTAL_EVENTS`, `QPOT_UNIQUE_IPS`, `QPOT_THRESHOLD`;
- `QPOT_TOP_SOURCE_IP`, `QPOT_TOP_HONEYPOT`.

The values are never interpolated into the command. Each hook runs with its
timeout, in its own process group, as the user that runs the control plane.
Anyone who can edit the instance's `config.yaml` can therefore run commands as
that user, so keep the file private.

Canary trips are reported as critical alerts too; see [canary.md](canary.md).

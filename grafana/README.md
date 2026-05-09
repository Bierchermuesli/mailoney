# Grafana dashboard for Mailoney

A drop-in Grafana dashboard covering the Prometheus metrics and the
JSON event-log feed.

## What's in `dashboards/mailoney.json`

12 panels in four rows:

**Row 1 — quick stats**
- Active sessions (`mailoney_smtp_active_sessions`)
- Connections total (`mailoney_smtp_connections_total`)
- Credentials captured (`mailoney_smtp_credentials_captured_total`)
- Uptime (`time() - mailoney_start_time_seconds`)

**Row 2 — rates and durations**
- Connection / session-end / banner-only rates (5m)
- Session duration percentiles (p50/p95/p99)

**Row 3 — distributions**
- Sessions by outcome (donut)
- SMTP commands by verb (bar gauge)
- Banner-only ratio over time

**Row 4 — logs**
- Live `mailoney.events` feed
- Captured credentials table
- Sessions with mail body table

The dashboard also annotates the timeline with the honeypot's start
time, so you can see across restarts at a glance.

## Importing

1. **Grafana → Dashboards → New → Import**
2. Upload `mailoney.json` (or paste the contents)
3. When prompted, pick:
   - `Prometheus` → your Prometheus / VictoriaMetrics datasource
   - `Loki` → your Loki / VictoriaLogs datasource
4. Save

The dashboard uses datasource *variables*, so swapping datasources
later is a one-click change at the top of the page.

## Wiring the metrics side

Prometheus / VictoriaMetrics scrape config:

```yaml
scrape_configs:
  - job_name: mailoney
    static_configs:
      - targets:
          - mailoney:9025      # MAILONEY_METRICS_PORT
```

Nothing else to do — the dashboard's PromQL queries work as-is on
both Prometheus and VictoriaMetrics (VM speaks the Prom protocol).

## Wiring the logs side

The dashboard log panels assume the JSON event lines from the
`mailoney.events` logger end up in your log store with `job="mailoney"`
as a stream label and the JSON payload accessible via `| json`.

The mailoney container emits these to **stdout** when
`MAILONEY_LOG_JSON=true` is set. From there you have several common
paths:

### Loki / Grafana Agent / promtail

```yaml
# promtail-config.yml — minimal
scrape_configs:
  - job_name: mailoney
    static_configs:
      - targets: [localhost]
        labels:
          job: mailoney
          __path__: /var/lib/docker/containers/<id>/<id>-json.log
    pipeline_stages:
      - docker: {}
      - json:
          expressions:
            event: event
            src_ip: src_ip
      - labels:
          event:
```

### VictoriaLogs

VictoriaLogs ships with a Loki-compatible API, so the dashboard's
LogQL queries *do work* against it without rewriting — point the
`Loki` datasource at `http://victoria-logs:9428/select/loki/api/v1/`
and you're set.

If you'd rather use native LogsQL, the equivalents are:

| LogQL (in dashboard) | LogsQL (native) |
|---|---|
| `{job="mailoney"} \| json` | `_stream:{job="mailoney"} \| unpack_json` |
| `\| event = "credential_captured"` | `event:credential_captured` |
| `\| event = "session_ended" \| mail_size != ""` | `event:session_ended AND mail_size:>0` |

You'll need to swap the datasource type from `loki` to whatever
VictoriaLogs registers as in your Grafana, and rewrite the queries
in the JSON. The structure (panel layout, transformations) stays the
same.

### Vector / Fluent Bit / OpenTelemetry collector

Any of these can tail the docker logs and ship to Loki / VictoriaLogs.
A reasonable Vector config snippet:

```toml
[sources.mailoney]
type = "docker_logs"
include_containers = ["mailoney"]

[transforms.mailoney_json]
type = "remap"
inputs = ["mailoney"]
source = '''
  parsed, err = parse_json(.message)
  if err == null { . = merge!(., parsed) }
'''

[sinks.loki]
type = "loki"
inputs = ["mailoney_json"]
endpoint = "http://loki:3100"
labels = { job = "mailoney" }
```

## Adapting the queries

A few panel-level things you'll want to skim if you're customizing:

- **`{job="mailoney"}`** assumes that label. Change it everywhere if
  you tag differently (e.g. `app="mailoney"`, `service="honeypot"`).
- **`mail_size`** in the "Sessions with mail body" panel is the
  flattened-JSON name of `mail.size` after `extractFields` runs.
  If your log shipper flattens differently, adjust the field name.
- **Auth strings** are stored as captured (base64). To decode in-place,
  you can add a transformation panel that runs
  `auth_string | base64decode` if your Grafana version supports it,
  or decode externally.

## Notes

- The dashboard's UID is `mailoney-overview` — change it before
  importing if you're already using that UID.
- Metric queries are time-range aware (`$__range`) so the donut and
  bar gauge update with the time picker.
- The "Connection / session-end rate" panel intentionally overlays
  three series so you can spot weird ratios (e.g. lots of sessions
  ending error vs total connects = config issue or an attacker pattern
  worth investigating).

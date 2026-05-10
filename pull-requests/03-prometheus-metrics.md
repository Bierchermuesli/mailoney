# feat: Prometheus `/metrics` endpoint + Grafana dashboard

Add an opt-in Prometheus exposition endpoint and a drop-in Grafana
dashboard for monitoring the honeypot.

## Motivation

A honeypot's value is in the patterns it sees over time. The existing
deployment offers no native observability — you'd have to query the
database to know whether anything is even hitting the listener. This
PR adds a `/metrics` endpoint with cardinality-safe counters and
gauges that mean something for honeypot operators.

## What changed

### `/metrics` endpoint (opt-in)

- `MAILONEY_METRICS_PORT` unset → disabled (default)
- Set to a port → server starts a small HTTP listener on
  `[::]:<port>` (dual-stack)
- `MAILONEY_METRICS_BIND` overrides the bind address
- CLI flags `--metrics-port` / `--metrics-bind` mirror the env vars

### Metrics exposed

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mailoney_smtp_connections_total` | Counter | — | Accepted connections |
| `mailoney_smtp_sessions_total` | Counter | `result` (`ok`/`error`) | Completed sessions |
| `mailoney_smtp_credentials_captured_total` | Counter | — | AUTH PLAIN captures |
| `mailoney_smtp_commands_total` | Counter | `command` (ehlo/helo/auth/mail/rcpt/data/quit/unknown) | SMTP command verbs |
| `mailoney_smtp_active_sessions` | Gauge | — | In-flight sessions |
| `mailoney_smtp_session_duration_seconds` | Histogram | — | Session duration |
| `mailoney_smtp_banner_only_sessions_total` | Counter | — | Sessions where client never sent a command (port-scanner signal) |
| `mailoney_start_time_seconds` | Gauge | — | Unix timestamp at process start; compute uptime via `time() - mailoney_start_time_seconds` |
| `mailoney_build_info` | Info | `version` | Build info |

Known label values are pre-warmed so they appear at zero in the
exposition rather than only after the first event — friendlier for
dashboards and alert rules.

**Cardinality decisions:**
- No source IP / port labels (cardinality bomb under botnet load)
- No captured credentials as labels (privacy + cardinality)
- No GeoIP/ASN buckets (runtime dependency, operators do this in
  their SIEM)

### Grafana dashboard

`grafana/dashboards/mailoney.json` — 12 panels in four rows:

- **Stats** — active sessions, total connections, credentials
  captured, uptime
- **Time series** — connection/session-end/banner-only rates,
  session-duration percentiles (p50/p95/p99)
- **Distributions** — sessions by outcome (donut), commands by verb
  (bar gauge), banner-only ratio over time
- **Logs** — live event feed, captured credentials table, sessions
  with mail body

Datasources templated as `${DS_PROMETHEUS}` / `${DS_LOKI}` so the
single dashboard works with Prom + Loki, VictoriaMetrics +
VictoriaLogs (Loki-compatible API), or any mix.
`grafana/README.md` walks through importing and three common
log-shipping setups (promtail, Vector, vlogs ingest).

## Backward compatibility

- `MAILONEY_METRICS_PORT` unset → no listener, no behaviour change
- `prometheus-client` added to `requirements.txt` (small, pure
  Python, no native deps)
- Existing deployments need no config changes

## Tests

27 tests including:
- All metric increments + label partitions
- Pre-warmed labels visible in exposition output
- Real HTTP server test (binds a free port, fetches `/metrics`)
- Command classification (ehlo/helo/auth/mail/rcpt/data/quit/unknown)
- Histogram observations + start-time gauge sanity

# feat: optional database + structured event logging

Make the SQL database an **opt-out** sink and add a structured event
stream that's useful for any modern log-shipping pipeline (Loki,
VictoriaLogs, ELK, SIEM ingest).

## Motivation

The current code makes a SQL database mandatory: every session writes
to `smtp_sessions` and `credentials`, and the only way to consume the
data is to query the database. For deployments that already ship
container logs to a central store, this is friction without benefit —
you're operating a Postgres instance just to hold append-only event
data that the log pipeline could carry natively.

This PR makes the database optional and adds first-class structured
event output, without breaking existing deployments.

## What changed

### 1. Database opt-out via empty `MAILONEY_DB_URL`

- Unset env var → unchanged behaviour (`sqlite:///mailoney.db` default)
- `MAILONEY_DB_URL=` (explicit empty) → database disabled
  - No engine, no migrations, no DB driver required at runtime
  - `init_db()` short-circuits; `create_session` / `log_credential` /
    `update_session_data` become no-ops
  - Distinguished from "unset" so the legacy default survives

### 2. `mailoney.events` structured logger

Three event types emit per session:
- `session_started` — at accept, with src/dest/server_name
- `credential_captured` — on every AUTH PLAIN, with `auth_string`
- `session_ended` — at close, with a flat per-session summary record

The session-end record replaces the old per-command transcript with
a single summary:

```json
{
  "event": "session_ended",
  "session_uuid": "...",
  "src_ip": "...", "src_port": ..., "dest_ip": "...", "dest_port": ...,
  "duration_seconds": 1.234,
  "command_count": 5,
  "commands": ["ehlo wall-e", "mail from:...", "rcpt to:...", "data", "quit"],
  "last_response_code": 221,
  "outcome": "ok",
  "credentials": ["..."]
}
```

This scales much better than the old per-line timestamped transcript,
which grew linearly with attacker chattiness.

### 3. `MAILONEY_LOG_JSON` for uniform JSON output

When the flag is on, **every** log line on stdout is JSON Lines —
both the structured events and the operational records from
`mailoney.core` / `mailoney.mail_storage` / etc.:

```json
{"logger":"mailoney.core","event":"log","level":"INFO","message":"Connection from ..."}
{"logger":"mailoney.events","event":"session_started",...}
```

Single shipper rule (`logger ~= "^mailoney\\."`) catches the entire
stream. Default (flag unset) is unchanged: human-readable text
everywhere.

### 4. Per-session correlation via `contextvars`

A `session_context(session_uuid)` context manager binds the session
UUID to the current execution context. The operational JSON formatter
copies it onto every log record emitted from within. Result: every
line for one connection — events *and* operational — carries the same
`session_uuid`. "All logs for session X" becomes a one-line LogQL
filter.

### 5. Side bug-fix in `mailoney/migrations/env.py`

Alembic's `fileConfig()` defaults to
`disable_existing_loggers=True`, which silently kills any loggers
configured before `init_db()` ran. Pass `False` so existing loggers
survive the migration run.

## Backward compatibility

- No env vars set → behaviour identical to current main
- Existing SQLite/Postgres deployments → unchanged
- The DB schema is unchanged

## Tests

23 tests, all green. Coverage:
- DB-disabled paths in `test_db_disabled.py`
- Event format (text + JSON, summary flattening, ts-not-included,
  bulky fields dropped in text, session_uuid contextvar correlation)
  in `test_events.py`
- Config (default settings, empty-DB env var, log_json env var,
  json_format root-logger swap) in `test_config.py`

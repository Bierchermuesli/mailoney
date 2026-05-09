"""
Structured event logging for Mailoney.

Emits one log record per honeypot event (session start/end, credential
capture). Records flow through a dedicated `mailoney.events` logger so
operators can route them independently of operational logs.

Output format is controlled by `init_event_logging(json_format=...)`:
  - text (default): one-line `<ts> <event> k=v ...` summary; bulky
    nested fields (commands list, captured credentials, mail body
    contents) are omitted to keep the line readable.
  - JSON Lines: one JSON object per event, including all fields.

Events always emit; the database is a separate, optional sink.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

EVENT_LOGGER_NAME = "mailoney.events"

_logger = logging.getLogger(EVENT_LOGGER_NAME)


def _record_iso_timestamp(record: logging.LogRecord) -> str:
    return datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()


class JsonEventFormatter(logging.Formatter):
    """One JSON object per line, including all event fields."""

    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "ts": _record_iso_timestamp(record),
            "event": getattr(record, "event_type", record.getMessage()),
        }
        event_data = getattr(record, "event_data", {}) or {}
        # Flatten a nested ``summary`` field so all summary keys live at
        # the top level of the JSON Lines record. Keeps queries flat.
        summary = event_data.get("summary")
        if isinstance(summary, dict):
            for k, v in event_data.items():
                if k != "summary":
                    data[k] = v
            data.update(summary)
        else:
            data.update(event_data)
        return json.dumps(data, default=str)


class TextEventFormatter(logging.Formatter):
    """Human-readable single line. Drops bulky fields."""

    # Top-level fields whose values can be large (lists, nested dicts) and
    # would blow up the single-line text format. JSON mode keeps them.
    _SKIP_IN_TEXT = {"commands", "credentials", "mail", "transcript"}

    def format(self, record: logging.LogRecord) -> str:
        event_type = getattr(record, "event_type", record.getMessage())
        data = dict(getattr(record, "event_data", {}) or {})
        # Flatten a nested summary into top-level k=v pairs for readability,
        # then drop bulky nested fields from that flat view.
        summary = data.pop("summary", None)
        if isinstance(summary, dict):
            for k, v in summary.items():
                data.setdefault(k, v)
        for key in self._SKIP_IN_TEXT:
            data.pop(key, None)
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        )
        kv = " ".join(f"{k}={v}" for k, v in data.items())
        return f"{ts} {event_type} {kv}".rstrip()


def init_event_logging(json_format: bool = False) -> None:
    """Configure the events logger. Safe to call multiple times."""
    for handler in list(_logger.handlers):
        _logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(JsonEventFormatter() if json_format else TextEventFormatter())
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    # Don't double-log via the root logger.
    _logger.propagate = False


def emit_event(event_type: str, **fields: Any) -> None:
    _logger.info(event_type, extra={"event_type": event_type, "event_data": fields})


def session_started(
    session_uuid: str,
    src_ip: str,
    src_port: int,
    server_name: str,
    dest_ip: Optional[str],
    dest_port: Optional[int],
) -> None:
    emit_event(
        "session_started",
        session_uuid=session_uuid,
        src_ip=src_ip,
        src_port=src_port,
        server_name=server_name,
        dest_ip=dest_ip,
        dest_port=dest_port,
    )


def credential_captured(session_uuid: str, auth_string: str) -> None:
    emit_event(
        "credential_captured",
        session_uuid=session_uuid,
        auth_string=auth_string,
    )


def session_ended(
    session_uuid: str,
    summary: Dict[str, Any],
) -> None:
    """Emit a session-end event.

    ``summary`` is a flat dict carrying the per-session record (src/dest,
    duration, command list, last response code, captured credentials,
    optional mail body reference). In JSON mode all summary fields appear
    at the top level of the event; in text mode bulky nested fields
    (commands, credentials, mail) are dropped for readability.
    """
    emit_event(
        "session_ended",
        session_uuid=session_uuid,
        summary=summary,
    )

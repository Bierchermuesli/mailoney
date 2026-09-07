"""
Structured event logging for Mailoney.

Two flavours of records flow through this module:

  * Honeypot **events** (session_started, credential_captured,
    session_ended) emitted by the dedicated ``mailoney.events`` logger.
    These carry an ``event_type`` and a structured ``event_data`` dict.
  * **Operational** log records emitted by every other logger
    (``mailoney.core``, ``mailoney.mail_storage``, ``mailoney.db``,
    plus third-party libraries). These are plain ``logging.LogRecord``s.

When ``MAILONEY_LOG_JSON=true``, both flavours are serialized as
JSON Lines so the entire stdout stream parses with a single rule. When
the flag is off, both render as human-readable text.

Neither format includes an internal timestamp field. Log shippers
(docker, journald, promtail, vector, vlogs ingest) attach their own
ingestion timestamp, and a duplicate ``ts`` in the message body just
adds noise.

Events always emit; the database is a separate, optional sink.
"""
import contextlib
import contextvars
import json
import logging
import sys
from typing import Any, Dict, Iterator, Optional

EVENT_LOGGER_NAME = "mailoney.events"

# Per-thread session correlation id. Set by ``session_context`` while a
# connection is being handled; the operational JSON formatter copies it
# onto every log record emitted from that context. Lets a single Loki /
# vlogs query pull *all* lines (events + operational) for one session.
_session_uuid_var: "contextvars.ContextVar[Optional[str]]" = contextvars.ContextVar(
    "mailoney_session_uuid", default=None
)


@contextlib.contextmanager
def session_context(session_uuid: str) -> Iterator[None]:
    """Bind ``session_uuid`` to the current execution context.

    All JSON log records emitted from within the ``with`` block — both
    structured events and plain operational log lines — automatically
    carry the ``session_uuid`` field, with no manual plumbing through
    call chains. Reset cleanly on exit even if the body raises.
    """
    token = _session_uuid_var.set(session_uuid)
    try:
        yield
    finally:
        _session_uuid_var.reset(token)


_logger = logging.getLogger(EVENT_LOGGER_NAME)


class JsonEventFormatter(logging.Formatter):
    """JSON Lines formatter for honeypot events.

    Every record carries a ``logger`` field (always ``mailoney.events``)
    so log shippers can match all mailoney output — events and
    operational alike — with a single ``logger =~ "^mailoney\\."`` rule.
    """

    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "logger": record.name,
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


class JsonOperationalFormatter(logging.Formatter):
    """JSON Lines formatter for non-event (operational) log records.

    Wraps each ``logging.LogRecord`` from ``mailoney.core`` etc. in a
    flat JSON object with a fixed shape so the whole stdout stream is
    uniformly parseable when ``MAILONEY_LOG_JSON=true``.

    Picks up the active ``session_uuid`` (when one is bound via
    ``session_context``) so operational lines can be correlated with
    structured events.
    """

    def format(self, record: logging.LogRecord) -> str:
        data: Dict[str, Any] = {
            "logger": record.name,
            "event": "log",
            "level": record.levelname,
            "message": record.getMessage(),
        }
        session_uuid = _session_uuid_var.get()
        if session_uuid is not None:
            data["session_uuid"] = session_uuid
        return json.dumps(data, default=str)


class TextEventFormatter(logging.Formatter):
    """Human-readable single line. Drops bulky fields."""

    # Top-level fields whose values can be large (lists, nested dicts) and
    # would blow up the single-line text format. JSON mode keeps them.
    _SKIP_IN_TEXT = {"commands", "credentials"}

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
        kv = " ".join(f"{k}={v}" for k, v in data.items())
        return f"{event_type} {kv}".rstrip()


def init_event_logging(json_format: bool = False) -> None:
    """Configure the events logger. Safe to call multiple times."""
    for handler in list(_logger.handlers):
        _logger.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
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
    duration, command list, last response code, captured credentials).
    In JSON mode all summary fields appear at the top level of the
    event; in text mode bulky nested fields (commands, credentials) are
    dropped for readability.
    """
    emit_event(
        "session_ended",
        session_uuid=session_uuid,
        summary=summary,
    )

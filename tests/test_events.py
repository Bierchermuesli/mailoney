"""
Tests for the structured event logger.
"""
import io
import json
import logging

import pytest

from mailoney import events


@pytest.fixture
def capture_events():
    """Replace the events handler with a stream we can inspect."""
    stream = io.StringIO()
    logger = logging.getLogger(events.EVENT_LOGGER_NAME)
    saved_handlers = list(logger.handlers)
    saved_propagate = logger.propagate
    for h in saved_handlers:
        logger.removeHandler(h)
    handler = logging.StreamHandler(stream)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        yield stream, handler
    finally:
        for h in list(logger.handlers):
            logger.removeHandler(h)
        for h in saved_handlers:
            logger.addHandler(h)
        logger.propagate = saved_propagate


def test_text_format_session_started(capture_events):
    stream, handler = capture_events
    handler.setFormatter(events.TextEventFormatter())

    events.session_started(
        session_uuid="abc-123",
        src_ip="10.0.0.1",
        src_port=4444,
        server_name="mail.example.com",
        dest_ip="10.0.0.2",
        dest_port=25,
    )

    out = stream.getvalue()
    assert "session_started" in out
    assert "session_uuid=abc-123" in out
    assert "src_ip=10.0.0.1" in out
    assert "dest_port=25" in out


def test_text_format_session_ended_summary_flat(capture_events):
    """Summary fields are flattened to top-level k=v in text mode."""
    stream, handler = capture_events
    handler.setFormatter(events.TextEventFormatter())

    events.session_ended(
        session_uuid="abc-123",
        summary={
            "src_ip": "10.0.0.1",
            "duration_seconds": 1.234,
            "command_count": 3,
            "commands": ["ehlo", "mail from:<a@b>", "quit"],
            "credentials": ["dGVzdA=="],
            "last_response_code": 221,
        },
    )

    out = stream.getvalue()
    assert "session_ended" in out
    assert "src_ip=10.0.0.1" in out
    assert "duration_seconds=1.234" in out
    assert "last_response_code=221" in out
    assert "command_count=3" in out
    # Bulky nested fields are dropped from text mode for readability.
    assert "commands=" not in out
    assert "credentials=" not in out
    assert "mail=" not in out


def test_json_format_includes_all_fields(capture_events):
    stream, handler = capture_events
    handler.setFormatter(events.JsonEventFormatter())

    events.credential_captured("abc-123", "dGVzdDp0ZXN0")

    line = stream.getvalue().strip()
    payload = json.loads(line)
    assert payload["event"] == "credential_captured"
    assert payload["session_uuid"] == "abc-123"
    assert payload["auth_string"] == "dGVzdDp0ZXN0"
    # Log shipper / docker / journald supplies the ingestion timestamp;
    # we don't include a duplicate ``ts`` field in the message body.
    assert "ts" not in payload
    # Every JSON record carries ``logger`` so a single ``logger ~= mailoney.*``
    # rule matches both event and operational lines.
    assert payload["logger"] == events.EVENT_LOGGER_NAME


def test_json_format_session_ended_summary_flattened(capture_events):
    """Summary fields appear at the top level in JSON mode."""
    stream, handler = capture_events
    handler.setFormatter(events.JsonEventFormatter())

    summary = {
        "src_ip": "10.0.0.1",
        "duration_seconds": 1.234,
        "command_count": 3,
        "commands": ["ehlo localhost", "mail from:<a@b>", "quit"],
        "credentials": ["dGVzdA=="],
        "last_response_code": 221,
        "mail": {"size": 42, "body_path": "2026-05-09/10.0.0.1/abc.eml"},
    }
    events.session_ended(session_uuid="abc-123", summary=summary)

    payload = json.loads(stream.getvalue().strip())
    assert payload["event"] == "session_ended"
    assert payload["session_uuid"] == "abc-123"
    # Summary is flattened, not nested under a 'summary' key.
    assert "summary" not in payload
    assert payload["src_ip"] == "10.0.0.1"
    assert payload["duration_seconds"] == 1.234
    assert payload["commands"] == summary["commands"]
    assert payload["credentials"] == summary["credentials"]
    assert payload["last_response_code"] == 221
    assert payload["mail"] == summary["mail"]


def _make_log_record(name="mailoney.core", msg="Connection from %s:%d", args=("1.2.3.4", 4444)):
    return logging.LogRecord(
        name=name,
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=msg,
        args=args,
        exc_info=None,
    )


def test_json_operational_formatter_renders_log_record():
    """Operational records (mailoney.core etc.) get a uniform JSON shape."""
    formatter = events.JsonOperationalFormatter()
    payload = json.loads(formatter.format(_make_log_record()))
    assert payload == {
        "logger": "mailoney.core",
        "event": "log",
        "level": "INFO",
        "message": "Connection from 1.2.3.4:4444",
    }


def test_json_operational_formatter_picks_up_session_context():
    """Inside ``session_context``, operational records carry session_uuid."""
    formatter = events.JsonOperationalFormatter()
    record = _make_log_record(name="mailoney.mail_storage", msg="stored", args=())

    # Outside the context: no session_uuid field.
    payload = json.loads(formatter.format(record))
    assert "session_uuid" not in payload

    with events.session_context("abc-123"):
        payload = json.loads(formatter.format(record))
    assert payload["session_uuid"] == "abc-123"

    # Cleanly removed after the with block.
    payload = json.loads(formatter.format(record))
    assert "session_uuid" not in payload


def test_init_event_logging_is_idempotent():
    """Calling init repeatedly should not stack handlers."""
    events.init_event_logging(json_format=False)
    events.init_event_logging(json_format=True)
    events.init_event_logging(json_format=False)
    logger = logging.getLogger(events.EVENT_LOGGER_NAME)
    assert len(logger.handlers) == 1
    assert logger.propagate is False

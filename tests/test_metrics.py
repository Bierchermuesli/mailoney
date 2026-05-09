"""
Tests for the Prometheus metrics module.
"""
import socket
import urllib.request
from contextlib import closing

import pytest
from prometheus_client import generate_latest

from mailoney import metrics
from mailoney.metrics import (
    ACTIVE_SESSIONS,
    BANNER_ONLY_SESSIONS_TOTAL,
    COMMANDS_TOTAL,
    CONNECTIONS_TOTAL,
    CREDENTIALS_CAPTURED_TOTAL,
    SESSION_DURATION_SECONDS,
    SESSIONS_TOTAL,
    START_TIME_SECONDS,
    classify_command,
    start_metrics_server,
)


@pytest.mark.parametrize(
    "request_line,expected",
    [
        ("ehlo localhost", "ehlo"),
        ("HELO mx", "helo"),  # classify_command receives lowercased input
        ("auth plain dGVzdA==", "auth"),
        ("mail from:<a@b>", "mail"),
        ("rcpt to:<c@d>", "rcpt"),
        ("data", "data"),
        ("quit", "quit"),
        ("xyzzy", "unknown"),
    ],
)
def test_classify_command(request_line, expected):
    # core.py lowercases requests before passing to classify_command;
    # mirror that here.
    assert classify_command(request_line.lower()) == expected


def _counter_value(counter, **labels) -> float:
    """Read the current numeric value of a (possibly labelled) counter."""
    if labels:
        return counter.labels(**labels)._value.get()
    return counter._value.get()


def test_connections_counter_increments():
    before = _counter_value(CONNECTIONS_TOTAL)
    CONNECTIONS_TOTAL.inc()
    CONNECTIONS_TOTAL.inc()
    assert _counter_value(CONNECTIONS_TOTAL) == before + 2


def test_credentials_counter_increments():
    before = _counter_value(CREDENTIALS_CAPTURED_TOTAL)
    CREDENTIALS_CAPTURED_TOTAL.inc()
    assert _counter_value(CREDENTIALS_CAPTURED_TOTAL) == before + 1


def test_sessions_counter_partitions_by_result():
    before_ok = _counter_value(SESSIONS_TOTAL, result="ok")
    before_err = _counter_value(SESSIONS_TOTAL, result="error")
    SESSIONS_TOTAL.labels(result="ok").inc()
    SESSIONS_TOTAL.labels(result="error").inc()
    assert _counter_value(SESSIONS_TOTAL, result="ok") == before_ok + 1
    assert _counter_value(SESSIONS_TOTAL, result="error") == before_err + 1


def test_commands_counter_partitions_by_verb():
    before_ehlo = _counter_value(COMMANDS_TOTAL, command="ehlo")
    before_unknown = _counter_value(COMMANDS_TOTAL, command="unknown")
    COMMANDS_TOTAL.labels(command="ehlo").inc()
    COMMANDS_TOTAL.labels(command="unknown").inc()
    COMMANDS_TOTAL.labels(command="unknown").inc()
    assert _counter_value(COMMANDS_TOTAL, command="ehlo") == before_ehlo + 1
    assert _counter_value(COMMANDS_TOTAL, command="unknown") == before_unknown + 2


def test_active_sessions_gauge_inc_dec():
    before = ACTIVE_SESSIONS._value.get()
    ACTIVE_SESSIONS.inc()
    ACTIVE_SESSIONS.inc()
    ACTIVE_SESSIONS.dec()
    assert ACTIVE_SESSIONS._value.get() == before + 1
    ACTIVE_SESSIONS.dec()  # cleanup
    assert ACTIVE_SESSIONS._value.get() == before


def test_banner_only_counter_increments():
    before = _counter_value(BANNER_ONLY_SESSIONS_TOTAL)
    BANNER_ONLY_SESSIONS_TOTAL.inc()
    assert _counter_value(BANNER_ONLY_SESSIONS_TOTAL) == before + 1


def test_session_duration_histogram_records_observations():
    """Observe a few durations and confirm the histogram absorbs them."""
    before_count = SESSION_DURATION_SECONDS._sum.get()
    SESSION_DURATION_SECONDS.observe(0.05)
    SESSION_DURATION_SECONDS.observe(2.5)
    SESSION_DURATION_SECONDS.observe(120.0)
    assert SESSION_DURATION_SECONDS._sum.get() == before_count + 0.05 + 2.5 + 120.0


def test_start_time_gauge_is_set_at_import():
    """Sanity: gauge holds a unix timestamp from this process's lifetime."""
    import time as _time
    value = START_TIME_SECONDS._value.get()
    # Set during module import; must be in the past and within the last day.
    assert 0 < value <= _time.time()
    assert _time.time() - value < 86400


def test_metric_names_appear_in_exposition():
    output = generate_latest().decode()
    assert "mailoney_smtp_connections_total" in output
    assert "mailoney_smtp_sessions_total" in output
    assert "mailoney_smtp_credentials_captured_total" in output
    assert "mailoney_smtp_commands_total" in output
    assert "mailoney_smtp_active_sessions" in output
    assert "mailoney_smtp_session_duration_seconds" in output
    assert "mailoney_smtp_banner_only_sessions_total" in output
    assert "mailoney_start_time_seconds" in output
    assert "mailoney_build_info" in output


def test_known_command_labels_are_prewarmed():
    """Pre-warmed labels appear in exposition even at zero count."""
    output = generate_latest().decode()
    for verb in ("ehlo", "helo", "auth", "mail", "rcpt", "data", "quit", "unknown"):
        assert f'command="{verb}"' in output


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_metrics_server_serves_exposition():
    """Spin up the real HTTP server and fetch /metrics."""
    port = _free_port()
    # Bind to localhost specifically (don't bind dual-stack in tests, to
    # avoid permission/firewall surprises).
    start_metrics_server(port=port, bind="127.0.0.1")
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=2) as resp:
        body = resp.read().decode()
    assert "mailoney_smtp_connections_total" in body
    assert resp.status == 200

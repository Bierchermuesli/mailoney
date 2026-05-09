"""
Prometheus metrics for Mailoney.

Exposes a small, opinionated set of counters and gauges describing
honeypot activity. The /metrics HTTP endpoint is opt-in: nothing is
served unless ``MAILONEY_METRICS_PORT`` is set (or ``--metrics-port``
is passed).
"""
import logging
from typing import Optional

from prometheus_client import Counter, Gauge, Info, start_http_server

from . import __version__

logger = logging.getLogger(__name__)


MAILONEY_INFO = Info("mailoney_build", "Mailoney honeypot build info")
MAILONEY_INFO.info({"version": __version__})

CONNECTIONS_TOTAL = Counter(
    "mailoney_smtp_connections_total",
    "SMTP connections accepted by the honeypot.",
)

SESSIONS_TOTAL = Counter(
    "mailoney_smtp_sessions_total",
    "SMTP sessions that ran to completion, partitioned by outcome.",
    ["result"],  # ok | error | timeout
)

CREDENTIALS_CAPTURED_TOTAL = Counter(
    "mailoney_smtp_credentials_captured_total",
    "AUTH PLAIN credential strings captured from clients.",
)

COMMANDS_TOTAL = Counter(
    "mailoney_smtp_commands_total",
    "SMTP commands received from clients, partitioned by command verb.",
    ["command"],  # ehlo | helo | auth | mail | rcpt | data | quit | unknown
)

ACTIVE_SESSIONS = Gauge(
    "mailoney_smtp_active_sessions",
    "SMTP sessions currently in flight.",
)


# Pre-warm known command labels so they appear in /metrics output even
# when count is zero — makes Prometheus rules and dashboards saner.
for _verb in ("ehlo", "helo", "auth", "mail", "rcpt", "data", "quit", "unknown"):
    COMMANDS_TOTAL.labels(command=_verb)
for _result in ("ok", "error", "timeout"):
    SESSIONS_TOTAL.labels(result=_result)


def classify_command(request: str) -> str:
    """Map a raw SMTP request line to one of the known command labels."""
    request = request.lstrip()
    if request.startswith("ehlo"):
        return "ehlo"
    if request.startswith("helo"):
        return "helo"
    if request.startswith("auth"):
        return "auth"
    if request.startswith("mail from:"):
        return "mail"
    if request.startswith("rcpt to:"):
        return "rcpt"
    if request.startswith("data"):
        return "data"
    if request.startswith("quit"):
        return "quit"
    return "unknown"


def start_metrics_server(port: int, bind: str = "::") -> None:
    """Start the Prometheus /metrics HTTP endpoint as a daemon thread.

    ``bind`` defaults to ``::`` so the listener accepts both IPv4 (mapped)
    and IPv6 connections on Linux's default dual-stack configuration.
    """
    logger.info(f"Starting Prometheus /metrics endpoint on [{bind}]:{port}")
    start_http_server(port, addr=bind)

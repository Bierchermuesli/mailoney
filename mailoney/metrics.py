"""
Prometheus metrics for Mailoney.

Exposes a small, opinionated set of counters and gauges describing
honeypot activity. The /metrics HTTP endpoint is opt-in: nothing is
served unless ``MAILONEY_METRICS_PORT`` is set (or ``--metrics-port``
is passed).
"""
import logging
import time

from prometheus_client import Counter, Gauge, Histogram, Info, start_http_server

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
    ["command"],  # ehlo | helo | auth | starttls | mail | rcpt | data | quit | unknown
)

ACTIVE_SESSIONS = Gauge(
    "mailoney_smtp_active_sessions",
    "SMTP sessions currently in flight.",
)

SESSION_DURATION_SECONDS = Histogram(
    "mailoney_smtp_session_duration_seconds",
    "Duration of SMTP sessions in seconds, from accept to close.",
    buckets=(0.1, 0.5, 1, 2, 5, 10, 30, 60, 300, 600),
)

BANNER_ONLY_SESSIONS_TOTAL = Counter(
    "mailoney_smtp_banner_only_sessions_total",
    "Sessions where the client connected but never sent a command "
    "(typical of port scanners).",
)

START_TIME_SECONDS = Gauge(
    "mailoney_start_time_seconds",
    "Unix timestamp at which the honeypot process started. "
    "Compute uptime in PromQL with `time() - mailoney_start_time_seconds`.",
)
START_TIME_SECONDS.set(time.time())


# Pre-warm known command labels so they appear in /metrics output even
# when count is zero — makes Prometheus rules and dashboards saner.
for _verb in ("ehlo", "helo", "auth", "starttls", "mail", "rcpt", "data", "quit", "unknown"):
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
    if request.startswith("starttls"):
        return "starttls"
    if request.startswith("mail from:"):
        return "mail"
    if request.startswith("rcpt to:"):
        return "rcpt"
    if request.startswith("data"):
        return "data"
    if request.startswith("quit"):
        return "quit"
    return "unknown"


# Bind addresses that keep the endpoint on the local host only.
_LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1", "localhost"})


def start_metrics_server(port: int, bind: str = "127.0.0.1") -> None:
    """Start the Prometheus /metrics HTTP endpoint as a daemon thread.

    ``bind`` defaults to loopback. The exposition includes
    ``mailoney_build_info`` (software name + version) and is served
    without authentication on every path, so a wildcard bind on a host
    that is also internet-exposed hands attackers a one-request honeypot
    fingerprint. Operators who scrape from another host or container
    opt in with ``0.0.0.0`` / ``::`` and must keep the port off the
    public interface.
    """
    if bind not in _LOOPBACK_BINDS:
        logger.warning(
            f"Prometheus /metrics endpoint is bound to {bind}:{port}, which is "
            "reachable from the network. The exposition identifies this host as "
            "a Mailoney honeypot; make sure this port is not exposed to the "
            "same networks as the SMTP listener."
        )
    logger.info(f"Starting Prometheus /metrics endpoint on [{bind}]:{port}")
    start_http_server(port, addr=bind)

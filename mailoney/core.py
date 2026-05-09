"""
Core functionality for the Mailoney SMTP Honeypot
"""
import re
import socket
import ssl
import threading
import logging
import json
import sys
import time
import uuid
import argparse
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging
from .mail_storage import store_mail_body
from . import events
from . import metrics

# Seconds to allow for the TLS handshake on STARTTLS. Without this, a
# malicious peer can stall a worker thread indefinitely by opening a
# connection and never completing the handshake.
TLS_HANDSHAKE_TIMEOUT_SECONDS = 10

logger = logging.getLogger(__name__)

# Cap on accumulated SMTP message body size. Real spam fits comfortably
# under this; honeypot value drops fast above 1 MiB and unbounded reads
# turn into a denial-of-service vector.
MAX_MAIL_BODY_BYTES = 1_048_576

# End-of-data terminator per RFC 5321 §4.1.1.4. ``\A`` lets an empty
# body (``.\r\n`` immediately after the 354) terminate correctly. ``\r?``
# tolerates LF-only clients.
_DATA_TERMINATOR_RE = re.compile(rb"(?:\r?\n|\A)\.\r?\n")
# Maximum bytes of overlap to keep when searching across recv() boundaries.
_DATA_TERMINATOR_TAIL = 4

class SMTPHoneypot:
    """
    SMTP Honeypot Server class
    """
    
    def __init__(
        self,
        bind_ip: str = '0.0.0.0',
        bind_port: int = 25,
        server_name: str = 'mail.example.com',
        mail_dir: Optional[str] = None,
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
    ):
        """
        Initialize the SMTP honeypot server.

        Args:
            bind_ip: IP address to bind to
            bind_port: Port to listen on
            server_name: Server name to display in SMTP responses
            mail_dir: When set, captured message bodies are written to disk
                under this directory; the session log records the relative
                path. When None, bodies stay inline in the session log.
            tls_cert: Path to PEM cert/chain. Both ``tls_cert`` and
                ``tls_key`` must be provided to enable STARTTLS.
            tls_key: Path to PEM private key.
        """
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_name = server_name
        self.mail_dir = mail_dir
        self.socket = None

        if tls_cert and tls_key:
            self.tls_context = self._build_tls_context(tls_cert, tls_key)
        else:
            self.tls_context = None

        # Pre-TLS EHLO advertises STARTTLS only when we can actually serve
        # it; post-TLS EHLO (sent after a successful upgrade) drops the
        # STARTTLS line per RFC 3207 §4.2.
        capabilities = ["PIPELINING", "SIZE 10240000", "VRFY", "ETRN"]
        if self.tls_context is not None:
            capabilities.append("STARTTLS")
        capabilities.extend(["AUTH LOGIN PLAIN", "8BITMIME"])
        self.ehlo_response = self._format_ehlo_response(capabilities)
        self.ehlo_response_post_tls = self._format_ehlo_response(
            [c for c in capabilities if c != "STARTTLS"]
        )

    def _format_ehlo_response(self, capabilities: List[str]) -> str:
        """Render an EHLO response with proper continuation markers.

        All lines except the last use ``250-`` as the prefix; the final
        line uses ``250 `` (space) per RFC 5321 §4.2.1.
        """
        lines = [self.server_name, *capabilities]
        formatted = []
        for i, line in enumerate(lines):
            sep = "-" if i < len(lines) - 1 else " "
            formatted.append(f"250{sep}{line}")
        return "\n".join(formatted) + "\n"

    @staticmethod
    def _build_tls_context(cert_path: str, key_path: str) -> ssl.SSLContext:
        """Build an SSLContext for STARTTLS upgrades.

        Pinned to TLS 1.2+ (1.0/1.1 are deprecated and offer no upside
        for a honeypot). Cert and key are loaded once at startup.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return ctx
        
    def start(self) -> None:
        """
        Start the SMTP honeypot server.

        Supports IPv4 (e.g. ``0.0.0.0``), IPv6 (e.g. ``::1``), and
        dual-stack (``::``) bind addresses. Uses ``socket.create_server``
        so dual-stack mode works transparently when the platform allows.
        """
        try:
            if ":" in self.bind_ip:
                family = socket.AF_INET6
                # '::' is the IPv6 wildcard; pair it with dualstack_ipv6
                # so the listener also accepts IPv4-mapped connections.
                dualstack = (
                    self.bind_ip in ("::", "::0")
                    and socket.has_dualstack_ipv6()
                )
            else:
                family = socket.AF_INET
                dualstack = False

            self.socket = socket.create_server(
                (self.bind_ip, self.bind_port),
                family=family,
                backlog=10,
                dualstack_ipv6=dualstack,
            )
            
            logger.info(f"SMTP Honeypot listening on {self.bind_ip}:{self.bind_port}")
            print(f"[*] SMTP Honeypot listening on {self.bind_ip}:{self.bind_port}")
            
            self._accept_connections()
        except Exception as e:
            logger.error(f"Error starting server: {e}")
            if self.socket:
                self.socket.close()
            raise
    
    def _accept_connections(self) -> None:
        """
        Accept and handle incoming connections
        """
        while True:
            try:
                client, addr = self.socket.accept()
                logger.info(f"Connection from {addr[0]}:{addr[1]} to {self.bind_ip}:{self.bind_port}")
                print(f"[*] Connection from {addr[0]}:{addr[1]} to {self.bind_ip}:{self.bind_port}")
                
                client_handler = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr)
                )
                client_handler.daemon = True
                client_handler.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                
    def _receive_mail_body(
        self,
        recv_fn,
        max_bytes: int = MAX_MAIL_BODY_BYTES,
    ) -> Tuple[bytes, bool]:
        """
        Read SMTP message body bytes after a 354 response.

        Reads via ``recv_fn(buffer_size)`` until the standard end-of-data
        terminator (``<CRLF>.<CRLF>`` or the permissive ``\\n.\\n``) is
        seen, or until ``max_bytes`` have been accumulated, or the peer
        closes the connection.

        The terminator search spans the chunk boundary by carrying over a
        small tail from the previous read, so a terminator that lands
        across two ``recv()`` calls is still detected.

        Returns:
            (body, terminator_found) — body excludes the terminator if
            one was matched.
        """
        body = bytearray()
        while len(body) < max_bytes:
            remaining = max_bytes - len(body)
            chunk = recv_fn(min(4096, remaining))
            if not chunk:
                break
            search_start = max(0, len(body) - _DATA_TERMINATOR_TAIL)
            body.extend(chunk)
            m = _DATA_TERMINATOR_RE.search(bytes(body), search_start)
            if m:
                return bytes(body[:m.start()]), True
        return bytes(body), False

    def _handle_client(self, client_socket: socket.socket, addr: Tuple[str, int]) -> None:
        """
        Handle client connection

        Args:
            client_socket: Client socket
            addr: Client address tuple (ip, port)
        """
        session_uuid = str(uuid.uuid4())
        session_outcome = "ok"
        metrics.CONNECTIONS_TOTAL.inc()
        metrics.ACTIVE_SESSIONS.inc()
        session_started = time.monotonic()
        events.session_started(
            session_uuid=session_uuid,
            src_ip=addr[0],
            src_port=addr[1],
            server_name=self.server_name,
            dest_ip=self.bind_ip,
            dest_port=self.bind_port,
        )
        session_record = create_session(
            addr[0], addr[1], self.server_name,
            dest_ip=self.bind_ip,
            dest_port=self.bind_port
        )

        # Per-session summary state. We emit a single end-of-session record
        # rather than a timestamped per-command transcript: the latter scales
        # linearly with attacker chattiness and buries the actionable signal
        # under noise.
        commands: List[str] = []
        credentials: List[str] = []
        mail_info: Optional[Dict[str, Any]] = None
        tls_info: Optional[Dict[str, Any]] = None
        last_response_code: Optional[int] = None
        tls_active = False

        def send(response: str) -> None:
            nonlocal last_response_code
            client_socket.send(response.encode())
            try:
                last_response_code = int(response[:3])
            except ValueError:
                pass

        try:
            send(f"220 {self.server_name} ESMTP Service Ready\n")

            # Handle client commands
            error_count = 0
            while error_count < 10:
                try:
                    request = client_socket.recv(4096).decode().strip().lower()
                    if not request:
                        break

                    commands.append(request)
                    logger.debug(f"Client: {request}")
                    metrics.COMMANDS_TOTAL.labels(
                        command=metrics.classify_command(request)
                    ).inc()

                    # EHLO/HELO. Post-TLS variant drops STARTTLS per RFC 3207 §4.2.
                    if request.startswith('ehlo') or request.startswith('helo'):
                        send(self.ehlo_response_post_tls if tls_active else self.ehlo_response)
                        error_count = 0

                    # STARTTLS — upgrade the connection in place.
                    elif request.startswith('starttls'):
                        if self.tls_context is None:
                            send("454 4.7.0 TLS not available\n")
                            error_count += 1
                        elif tls_active:
                            send("503 5.5.1 STARTTLS already active\n")
                            error_count += 1
                        else:
                            send("220 2.0.0 Ready to start TLS\n")
                            try:
                                client_socket.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
                                client_socket = self.tls_context.wrap_socket(
                                    client_socket,
                                    server_side=True,
                                )
                                client_socket.settimeout(None)
                                tls_active = True
                                tls_info = {
                                    "active": True,
                                    "version": client_socket.version(),
                                    "cipher": client_socket.cipher()[0] if client_socket.cipher() else None,
                                }
                                error_count = 0
                            except (ssl.SSLError, OSError, socket.timeout) as e:
                                logger.warning(f"TLS handshake failed for {addr[0]}:{addr[1]}: {e}")
                                tls_info = {"active": False, "error": str(e)}
                                break

                    # AUTH PLAIN
                    elif request.startswith('auth plain'):
                        parts = request.split()
                        if len(parts) >= 3:
                            auth_string = parts[2]
                            credentials.append(auth_string)
                            metrics.CREDENTIALS_CAPTURED_TOTAL.inc()
                            events.credential_captured(session_uuid, auth_string)
                            log_credential(session_record.id, auth_string)
                            logger.info(f"Captured credential: {auth_string}")
                        send("235 2.7.0 Authentication failed\n")

                    # QUIT
                    elif request.startswith('quit'):
                        send("221 2.0.0 Goodbye\n")
                        break

                    # MAIL FROM: / RCPT TO: — accept envelope, no body involved.
                    elif request.startswith(('mail from:', 'rcpt to:')):
                        send("250 2.1.0 OK\n")
                        error_count = 0

                    # DATA — enter body-receive mode, read until terminator
                    # or size cap, then return to command mode.
                    elif request.startswith('data'):
                        send("354 End data with <CR><LF>.<CR><LF>\n")
                        body, terminator_found = self._receive_mail_body(client_socket.recv)

                        mail_info = {
                            "size": len(body),
                            "truncated": not terminator_found,
                        }
                        if self.mail_dir:
                            try:
                                mail_info["body_path"] = store_mail_body(
                                    self.mail_dir, addr[0], session_uuid, body,
                                )
                            except OSError as e:
                                logger.error(f"Failed to write mail body: {e}")
                                # Fall back to inline so we don't lose the data.
                                mail_info["data"] = body.decode("utf-8", errors="replace")
                                mail_info["body_path_error"] = str(e)
                        else:
                            mail_info["data"] = body.decode("utf-8", errors="replace")

                        if terminator_found:
                            send("250 2.0.0 Ok\n")
                        elif len(body) >= MAX_MAIL_BODY_BYTES:
                            send("552 5.3.4 Message size limit exceeded\n")
                        else:
                            send("421 4.4.2 Connection closed\n")
                            break
                        error_count = 0

                    # Unknown command
                    else:
                        send("502 5.5.2 Error: command not recognized\n")
                        error_count += 1

                except Exception as e:
                    logger.error(f"Error handling client request: {e}")
                    error_count += 1

        except Exception as e:
            logger.error(f"Error in client handler: {e}")
            session_outcome = "error"
        finally:
            duration = time.monotonic() - session_started
            summary: Dict[str, Any] = {
                "src_ip": addr[0],
                "src_port": addr[1],
                "dest_ip": self.bind_ip,
                "dest_port": self.bind_port,
                "duration_seconds": round(duration, 3),
                "command_count": len(commands),
                "commands": commands,
                "last_response_code": last_response_code,
                "outcome": session_outcome,
            }
            if credentials:
                summary["credentials"] = credentials
            if mail_info is not None:
                summary["mail"] = mail_info
            if tls_info is not None:
                summary["tls"] = tls_info

            events.session_ended(session_uuid=session_uuid, summary=summary)
            update_session_data(session_record.id, json.dumps(summary))

            metrics.SESSIONS_TOTAL.labels(result=session_outcome).inc()
            metrics.SESSION_DURATION_SECONDS.observe(duration)
            if not commands:
                metrics.BANNER_ONLY_SESSIONS_TOTAL.inc()
            metrics.ACTIVE_SESSIONS.dec()
            try:
                client_socket.close()
            except OSError:
                pass
            logger.info(f"Connection closed for {addr[0]}:{addr[1]} (dest: {self.bind_ip}:{self.bind_port})")
            
    def stop(self) -> None:
        """
        Stop the SMTP honeypot server
        """
        if self.socket:
            self.socket.close()
            logger.info("SMTP Honeypot server stopped")


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="Mailoney - A Simple SMTP Honeypot")
    
    parser.add_argument(
        '-i', '--ip', 
        default=get_settings().bind_ip,
        help='IP address to bind to (default: 0.0.0.0)'
    )
    
    parser.add_argument(
        '-p', '--port', 
        type=int, 
        default=get_settings().bind_port,
        help='Port to listen on (default: 25)'
    )
    
    parser.add_argument(
        '-s', '--server-name', 
        default=get_settings().server_name,
        help='Server name to display in SMTP responses'
    )
    
    parser.add_argument(
        '-d', '--db-url',
        default=get_settings().db_url,
        help=(
            'Database URL (default: sqlite:///mailoney.db). '
            'Pass an empty string to disable the database and run in '
            'event-logging-only mode.'
        )
    )

    parser.add_argument(
        '--mail-dir',
        default=get_settings().mail_dir,
        help=(
            'Directory under which captured SMTP message bodies are written '
            'as <YYYY-MM-DD>/<src-ip>/<session>.eml. '
            'When unset, bodies stay inline in the session log.'
        )
    )

    parser.add_argument(
        '--tls-cert',
        default=get_settings().tls_cert,
        help=(
            'Path to a PEM cert/chain. Both --tls-cert and --tls-key '
            'must be set to enable STARTTLS.'
        )
    )

    parser.add_argument(
        '--tls-key',
        default=get_settings().tls_key,
        help='Path to the PEM private key for --tls-cert.'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default=get_settings().log_level,
        help='Log level'
    )

    parser.add_argument(
        '--log-json',
        action='store_true',
        default=get_settings().log_json,
        help=(
            'Emit every log line — both honeypot events and operational '
            'records — as JSON Lines on stdout. Default is human-readable '
            'text for both.'
        )
    )

    parser.add_argument(
        '--metrics-port',
        type=int,
        default=get_settings().metrics_port,
        help=(
            'Port to serve Prometheus /metrics on. '
            'If unset, the metrics endpoint is disabled.'
        )
    )

    parser.add_argument(
        '--metrics-bind',
        default=get_settings().metrics_bind,
        help='Bind address for the /metrics endpoint (default: ::, dual-stack)'
    )

    return parser.parse_args()


def display_banner() -> None:
    """Display the Mailoney banner"""
    from . import __version__
    
    banner = f"""
    ****************************************************************
    *    Mailoney - A Simple SMTP Honeypot - Version: {__version__}    *
    ****************************************************************
    """
    print(banner)


def run_server() -> None:
    """
    Run the SMTP Honeypot server.
    This is the main entry point for the application.
    """
    # Parse command-line arguments
    args = parse_args()
    
    # Configure logging. The same flag drives both the operational
    # (root) logger and the events logger so the entire stdout stream
    # is uniformly text or uniformly JSON.
    configure_logging(args.log_level, json_format=args.log_json)
    events.init_event_logging(json_format=args.log_json)

    # Display banner
    display_banner()

    # Initialize database (empty URL disables it; events still flow to logs).
    if args.db_url == "":
        logger.info("Database disabled; running in event-logging-only mode")
    else:
        logger.info(f"Initializing database with URL: {args.db_url}")
    init_db(args.db_url)

    # Start Prometheus /metrics endpoint if requested
    if args.metrics_port:
        metrics.start_metrics_server(args.metrics_port, args.metrics_bind)

    # Create and start server
    try:
        server = SMTPHoneypot(
            bind_ip=args.ip,
            bind_port=args.port,
            server_name=args.server_name,
            mail_dir=args.mail_dir,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
        
        logger.info(f"Starting SMTP Honeypot on {args.ip}:{args.port}")
        server.start()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Error running server: {e}")
        sys.exit(1)

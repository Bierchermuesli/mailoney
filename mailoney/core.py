"""
Core functionality for the Mailoney SMTP Honeypot
"""
import socket
import ssl
import threading
import logging
import json
import sys
import argparse
from time import strftime
from typing import Optional, Tuple, Dict, Any, List

from .db import create_session, update_session_data, log_credential, init_db
from .config import get_settings, configure_logging

# Seconds to allow for the TLS handshake on STARTTLS. Without this, a
# malicious peer can stall a worker thread indefinitely by opening a
# connection and never completing the handshake.
TLS_HANDSHAKE_TIMEOUT_SECONDS = 10

logger = logging.getLogger(__name__)

class SMTPHoneypot:
    """
    SMTP Honeypot Server class
    """
    
    def __init__(
        self,
        bind_ip: str = '0.0.0.0',
        bind_port: int = 25,
        server_name: str = 'mail.example.com',
        tls_cert: Optional[str] = None,
        tls_key: Optional[str] = None,
    ):
        """
        Initialize the SMTP honeypot server.

        Args:
            bind_ip: IP address to bind to
            bind_port: Port to listen on
            server_name: Server name to display in SMTP responses
            tls_cert: Path to PEM cert/chain. Both ``tls_cert`` and
                ``tls_key`` must be provided to enable STARTTLS.
            tls_key: Path to PEM private key.
        """
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.server_name = server_name
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
        Start the SMTP honeypot server
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.bind_ip, self.bind_port))
            self.socket.listen(10)
            
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
                
    def _handle_client(self, client_socket: socket.socket, addr: Tuple[str, int]) -> None:
        """
        Handle client connection
        
        Args:
            client_socket: Client socket
            addr: Client address tuple (ip, port)
        """
        session_record = create_session(
            addr[0], addr[1], self.server_name,
            dest_ip=self.bind_ip,
            dest_port=self.bind_port
        )
        session_log = []
        tls_active = False

        try:
            # Send banner
            banner = f"220 {self.server_name} ESMTP Service Ready\n"
            client_socket.send(banner.encode())
            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": banner})

            # Handle client commands
            error_count = 0
            while error_count < 10:
                try:
                    request = client_socket.recv(4096).decode().strip().lower()
                    if not request:
                        break

                    session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "in", "data": request})
                    logger.debug(f"Client: {request}")

                    # Handle EHLO/HELO. Use the post-TLS variant once a
                    # STARTTLS upgrade has succeeded (no STARTTLS line).
                    if request.startswith('ehlo') or request.startswith('helo'):
                        ehlo = self.ehlo_response_post_tls if tls_active else self.ehlo_response
                        client_socket.send(ehlo.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": ehlo})
                        error_count = 0

                    # STARTTLS — upgrade the connection in place.
                    elif request.startswith('starttls'):
                        if self.tls_context is None:
                            response = "454 4.7.0 TLS not available\n"
                            client_socket.send(response.encode())
                            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                            error_count += 1
                        elif tls_active:
                            response = "503 5.5.1 STARTTLS already active\n"
                            client_socket.send(response.encode())
                            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                            error_count += 1
                        else:
                            response = "220 2.0.0 Ready to start TLS\n"
                            client_socket.send(response.encode())
                            session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                            try:
                                client_socket.settimeout(TLS_HANDSHAKE_TIMEOUT_SECONDS)
                                client_socket = self.tls_context.wrap_socket(
                                    client_socket,
                                    server_side=True,
                                )
                                client_socket.settimeout(None)
                                tls_active = True
                                session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "tls-upgrade", "tls_version": client_socket.version()})
                                error_count = 0
                            except (ssl.SSLError, OSError, socket.timeout) as e:
                                logger.warning(f"TLS handshake failed for {addr[0]}:{addr[1]}: {e}")
                                session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "tls-failed", "error": str(e)})
                                break

                    # Handle AUTH
                    elif request.startswith('auth plain'):
                        # Extract auth string
                        parts = request.split()
                        if len(parts) >= 3:
                            auth_string = parts[2]
                            log_credential(session_record.id, auth_string)
                            logger.info(f"Captured credential: {auth_string}")

                        response = "235 2.7.0 Authentication failed\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})

                    # Handle QUIT
                    elif request.startswith('quit'):
                        response = "221 2.0.0 Goodbye\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        break

                    # Handle other SMTP commands (simplistic simulation)
                    elif request.startswith(('mail from:', 'rcpt to:', 'data')):
                        response = "250 2.1.0 OK\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        error_count = 0

                    # Unknown command
                    else:
                        response = "502 5.5.2 Error: command not recognized\n"
                        client_socket.send(response.encode())
                        session_log.append({"timestamp": strftime("%Y-%m-%d %H:%M:%S"), "direction": "out", "data": response})
                        error_count += 1

                except Exception as e:
                    logger.error(f"Error handling client request: {e}")
                    error_count += 1

            # Store the session log
            update_session_data(session_record.id, json.dumps(session_log))

        except Exception as e:
            logger.error(f"Error in client handler: {e}")
        finally:
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
        help='Database URL (default: sqlite:///mailoney.db)'
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
    
    # Configure logging
    configure_logging(args.log_level)
    
    # Display banner
    display_banner()
    
    # Initialize database
    logger.info(f"Initializing database with URL: {args.db_url}")
    init_db(args.db_url)
    
    # Create and start server
    try:
        server = SMTPHoneypot(
            bind_ip=args.ip,
            bind_port=args.port,
            server_name=args.server_name,
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

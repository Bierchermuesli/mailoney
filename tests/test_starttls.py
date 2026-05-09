"""
Tests for STARTTLS support.

The protocol-level upgrade is a one-line ``ssl.SSLContext.wrap_socket``
call; what's worth testing here is the *wiring*: that the EHLO response
advertises STARTTLS only when a context is configured, that the
post-upgrade EHLO drops STARTTLS, that the command-handler takes the
right branches, and that ``ssl.SSLContext`` actually loads a real cert
pair.
"""
import socket
import ssl
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mailoney.core import SMTPHoneypot


@pytest.fixture(scope="session")
def tls_cert_pair(tmp_path_factory):
    """Generate a self-signed cert/key pair for the session via openssl."""
    tmp = tmp_path_factory.mktemp("tls")
    cert = tmp / "cert.pem"
    key = tmp / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes",
            "-subj", "/CN=test.example.com",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


def test_no_tls_context_when_paths_unset():
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    assert h.tls_context is None


def test_no_tls_context_when_only_one_path_set():
    """Both cert AND key must be present to enable TLS."""
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025, tls_cert="/some/path")
    assert h.tls_context is None
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025, tls_key="/some/path")
    assert h.tls_context is None


def test_tls_context_built_from_real_cert(tls_cert_pair):
    cert, key = tls_cert_pair
    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        tls_cert=cert, tls_key=key,
    )
    assert isinstance(h.tls_context, ssl.SSLContext)
    assert h.tls_context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_ehlo_advertises_starttls_when_configured(tls_cert_pair):
    cert, key = tls_cert_pair
    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        tls_cert=cert, tls_key=key,
    )
    assert "250-STARTTLS" in h.ehlo_response
    # Post-TLS EHLO drops the STARTTLS line per RFC 3207 §4.2.
    assert "STARTTLS" not in h.ehlo_response_post_tls


def test_ehlo_omits_starttls_when_not_configured():
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    assert "STARTTLS" not in h.ehlo_response
    assert "STARTTLS" not in h.ehlo_response_post_tls


def test_ehlo_response_uses_proper_continuation_markers(tls_cert_pair):
    """All but the last line use 250-, the last uses 250 (space)."""
    cert, key = tls_cert_pair
    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        server_name="mx.example.com",
        tls_cert=cert, tls_key=key,
    )
    lines = h.ehlo_response.rstrip("\n").split("\n")
    assert lines[0] == "250-mx.example.com"
    for line in lines[:-1]:
        assert line.startswith("250-"), f"line {line!r} should be a continuation"
    assert lines[-1].startswith("250 "), f"last line {lines[-1]!r} should not be a continuation"


def test_starttls_command_replies_454_when_unconfigured():
    """Without a cert, STARTTLS is rejected with 454."""
    h = SMTPHoneypot(bind_ip="127.0.0.1", bind_port=8025)
    sent = []

    sock = MagicMock(spec=socket.socket)
    sock.recv.side_effect = [b"starttls\r\n", b""]
    sock.send.side_effect = lambda b: sent.append(b)

    h._handle_client(sock, ("10.0.0.1", 4444))

    sent_str = b"".join(sent).decode()
    assert "454" in sent_str
    assert "TLS not available" in sent_str


def _build_wrapped_socket(*, recv_chunks, sent_collector):
    """Build a MagicMock that emulates a wrapped SSLSocket."""
    wrapped = MagicMock(spec=ssl.SSLSocket)
    wrapped.recv.side_effect = recv_chunks
    wrapped.send.side_effect = lambda b: sent_collector.append(b)
    wrapped.version.return_value = "TLSv1.3"
    # cipher() returns (name, protocol_version, secret_bits) per stdlib docs.
    wrapped.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    return wrapped


def test_starttls_command_invokes_wrap_socket_when_configured(tls_cert_pair):
    """With a cert, STARTTLS sends 220 and calls wrap_socket on the peer socket."""
    cert, key = tls_cert_pair
    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        tls_cert=cert, tls_key=key,
    )
    sent = []

    sock = MagicMock(spec=socket.socket)
    # First recv: STARTTLS. Second (after wrap): empty -> end loop.
    sock.recv.side_effect = [b"starttls\r\n", b""]
    sock.send.side_effect = lambda b: sent.append(b)

    # Replace the SSLContext with one whose wrap_socket returns a fresh
    # mock so we don't actually do TLS but we can prove we tried.
    wrapped = _build_wrapped_socket(recv_chunks=[b""], sent_collector=sent)
    h.tls_context = MagicMock(spec=ssl.SSLContext)
    h.tls_context.wrap_socket.return_value = wrapped

    h._handle_client(sock, ("10.0.0.1", 4444))

    sent_str = b"".join(sent).decode()
    assert "220 2.0.0 Ready to start TLS" in sent_str
    h.tls_context.wrap_socket.assert_called_once()
    # Handshake timeout was set before the upgrade.
    sock.settimeout.assert_any_call(10)


def test_starttls_already_active_replies_503(tls_cert_pair):
    """Issuing STARTTLS twice gets 503."""
    cert, key = tls_cert_pair
    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        tls_cert=cert, tls_key=key,
    )
    sent = []

    sock = MagicMock(spec=socket.socket)
    sock.recv.side_effect = [b"starttls\r\n", b""]
    sock.send.side_effect = lambda b: sent.append(b)

    # On the wrapped socket, the client sends another STARTTLS, then closes.
    wrapped = _build_wrapped_socket(
        recv_chunks=[b"starttls\r\n", b""], sent_collector=sent,
    )
    h.tls_context = MagicMock(spec=ssl.SSLContext)
    h.tls_context.wrap_socket.return_value = wrapped

    h._handle_client(sock, ("10.0.0.1", 4444))

    sent_str = b"".join(sent).decode()
    assert "220 2.0.0 Ready to start TLS" in sent_str
    assert "503" in sent_str
    assert "already active" in sent_str

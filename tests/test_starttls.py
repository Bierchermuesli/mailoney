"""
Tests for STARTTLS support.

The protocol-level upgrade is a one-line ``ssl.SSLContext.wrap_socket``
call; what's worth testing here is the *wiring*: that the EHLO response
advertises STARTTLS only when a context is configured, that the
post-upgrade EHLO drops STARTTLS, that the command-handler takes the
right branches, and that ``ssl.SSLContext`` actually loads a real cert
pair.
"""
import os
import socket
import ssl
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from mailoney.core import SMTPHoneypot, TLSConfigError, preflight_tls


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


def test_starttls_command_invokes_wrap_socket_when_configured(tls_cert_pair, event_stream):
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
    wrapped = MagicMock(spec=ssl.SSLSocket)
    wrapped.recv.return_value = b""
    wrapped.version.return_value = "TLSv1.3"
    h.tls_context = MagicMock(spec=ssl.SSLContext)
    h.tls_context.wrap_socket.return_value = wrapped

    h._handle_client(sock, ("10.0.0.1", 4444))

    sent_str = b"".join(sent).decode()
    assert "220 2.0.0 Ready to start TLS" in sent_str
    h.tls_context.wrap_socket.assert_called_once()
    # Handshake timeout was set before the upgrade.
    sock.settimeout.assert_any_call(10)
    # The negotiated version is carried on the session summary.
    ended = [e for e in event_stream() if e["event"] == "session_ended"]
    assert ended and ended[0]["tls_version"] == "TLSv1.3"


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

    wrapped = MagicMock(spec=ssl.SSLSocket)
    # On the wrapped socket, the client sends another STARTTLS, then closes.
    wrapped.recv.side_effect = [b"starttls\r\n", b""]
    wrapped.send.side_effect = lambda b: sent.append(b)
    wrapped.version.return_value = "TLSv1.3"
    h.tls_context = MagicMock(spec=ssl.SSLContext)
    h.tls_context.wrap_socket.return_value = wrapped

    h._handle_client(sock, ("10.0.0.1", 4444))

    sent_str = b"".join(sent).decode()
    assert "220 2.0.0 Ready to start TLS" in sent_str
    assert "503" in sent_str
    assert "already active" in sent_str
    # The 503 must have gone out over the *wrapped* socket: proves the
    # reply helper follows the rebinding done by wrap_socket().
    assert any(b"503" in c.args[0] for c in wrapped.send.call_args_list)
    assert not any(b"503" in c.args[0] for c in sock.send.call_args_list)


# --- startup validation -----------------------------------------------
#
# The cert/key paths are operator-supplied, and the two mistakes that
# actually happen in the field are a wrong path and a key the process
# cannot read (certbot and Debian's snakeoil key are both root-owned).
# preflight_tls runs before init_db so these never masquerade as a
# database error, and it writes to stderr so the message survives
# Alembic's logging reconfiguration during migrations.


def test_preflight_noop_when_tls_unconfigured(capsys):
    preflight_tls(None, None)
    assert capsys.readouterr().err == ""


def test_preflight_warns_but_continues_when_only_cert_set(capsys):
    """Half-configured is a typo, not a reason to refuse to start."""
    preflight_tls("/some/cert.pem", None)
    err = capsys.readouterr().err
    assert "MAILONEY_TLS_KEY" in err
    assert "plaintext" in err


def test_preflight_warns_but_continues_when_only_key_set(capsys):
    preflight_tls(None, "/some/key.pem")
    err = capsys.readouterr().err
    assert "MAILONEY_TLS_CERT" in err


def test_preflight_exits_when_cert_missing(capsys):
    with pytest.raises(SystemExit) as exc:
        preflight_tls("/nonexistent/fullchain.pem", "/nonexistent/privkey.pem")
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err
    assert "/nonexistent/fullchain.pem" in err


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root bypasses file permission checks, so the key stays readable",
)
def test_preflight_exits_when_key_unreadable(tls_cert_pair, tmp_path, capsys):
    """The certbot / snakeoil case: cert is world-readable, key is not."""
    cert, key = tls_cert_pair
    unreadable = tmp_path / "privkey.pem"
    unreadable.write_bytes(open(key, "rb").read())
    unreadable.chmod(0o000)

    with pytest.raises(SystemExit) as exc:
        preflight_tls(cert, str(unreadable))
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not readable" in err
    assert "privkey.pem" in err
    # Names the likely cause rather than leaving the operator guessing.
    assert "mailoney" in err


def test_preflight_exits_on_mismatched_pair(tls_cert_pair, tmp_path, capsys):
    """A readable but wrong key is caught at startup, not at handshake."""
    cert, _ = tls_cert_pair
    other_key = tmp_path / "other-key.pem"
    other_cert = tmp_path / "other-cert.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(other_key), "-out", str(other_cert),
            "-days", "1", "-nodes", "-subj", "/CN=other.example.com",
        ],
        check=True,
        capture_output=True,
    )

    with pytest.raises(SystemExit) as exc:
        preflight_tls(cert, str(other_key))
    assert exc.value.code == 2
    assert "could not load TLS cert/key pair" in capsys.readouterr().err


def test_preflight_accepts_a_valid_pair(tls_cert_pair, capsys):
    cert, key = tls_cert_pair
    preflight_tls(cert, key)
    assert capsys.readouterr().err == ""


def test_build_tls_context_raises_tls_config_error(tmp_path):
    """Bad input surfaces as TLSConfigError, not a bare OSError."""
    bogus = tmp_path / "not-a-cert.pem"
    bogus.write_text("this is not PEM\n")
    with pytest.raises(TLSConfigError):
        SMTPHoneypot._build_tls_context(str(bogus), str(bogus))


def test_snakeoil_style_pair_is_accepted(tmp_path):
    """Debian's ssl-cert snakeoil pair is an ordinary self-signed pair."""
    cert = tmp_path / "ssl-cert-snakeoil.pem"
    key = tmp_path / "ssl-cert-snakeoil.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "3650", "-nodes", "-subj", "/CN=honeypot.local",
        ],
        check=True,
        capture_output=True,
    )
    key.chmod(0o640)

    h = SMTPHoneypot(
        bind_ip="127.0.0.1", bind_port=8025,
        tls_cert=str(cert), tls_key=str(key),
    )
    assert isinstance(h.tls_context, ssl.SSLContext)
    assert "STARTTLS" in h.ehlo_response

"""
Tests for the configuration module
"""
import os
import pytest
from mailoney.config import get_settings, configure_logging, Settings

def test_default_settings():
    """Test default settings"""
    settings = get_settings()

    assert settings.bind_ip == "0.0.0.0"
    assert settings.bind_port == 25
    assert settings.server_name == "mail.example.com"
    assert settings.db_url == "sqlite:///mailoney.db"
    assert settings.log_level == "INFO"
    assert settings.log_json is False
    assert settings.metrics_port is None
    assert settings.metrics_bind == "127.0.0.1"


def test_empty_db_url_env_disables_db(monkeypatch):
    """An explicit empty MAILONEY_DB_URL means 'no DB', distinct from unset."""
    monkeypatch.setenv("MAILONEY_DB_URL", "")
    settings = Settings()
    assert settings.db_url == ""


def test_log_json_env(monkeypatch):
    monkeypatch.setenv("MAILONEY_LOG_JSON", "true")
    settings = Settings()
    assert settings.log_json is True


def test_metrics_env(monkeypatch):
    monkeypatch.setenv("MAILONEY_METRICS_PORT", "9025")
    monkeypatch.setenv("MAILONEY_METRICS_BIND", "127.0.0.1")
    settings = Settings()
    assert settings.metrics_port == 9025
    assert settings.metrics_bind == "127.0.0.1"

def test_env_settings(monkeypatch):
    """Test settings from environment variables"""
    # Set environment variables
    monkeypatch.setenv("MAILONEY_BIND_IP", "127.0.0.1")
    monkeypatch.setenv("MAILONEY_BIND_PORT", "2525")
    monkeypatch.setenv("MAILONEY_SERVER_NAME", "honeypot.local")
    monkeypatch.setenv("MAILONEY_DB_URL", "postgresql://user:pass@localhost/honeypot")
    monkeypatch.setenv("MAILONEY_LOG_LEVEL", "DEBUG")
    
    # Recreate settings to pick up environment variables
    settings = Settings()
    
    assert settings.bind_ip == "127.0.0.1"
    assert settings.bind_port == 2525
    assert settings.server_name == "honeypot.local"
    assert settings.db_url == "postgresql://user:pass@localhost/honeypot"
    assert settings.log_level == "DEBUG"

def test_configure_logging():
    """Test logging configuration"""
    # This is more of a smoke test since it's hard to test logging configuration
    configure_logging("DEBUG")
    configure_logging("INFO")

    # Test with invalid level
    with pytest.raises(ValueError):
        configure_logging("NOT_A_LEVEL")


def test_configure_logging_json_format_switches_root_formatter():
    """When json_format=True, the root logger handler emits JSON Lines."""
    import io
    import json as _json
    import logging as _logging

    configure_logging("INFO", json_format=True)
    root = _logging.getLogger()
    # Plain StreamHandler only: pytest's capture handlers subclass it.
    handler = next(h for h in root.handlers if type(h) is _logging.StreamHandler)
    saved_stream = handler.stream
    handler.stream = io.StringIO()
    try:
        _logging.getLogger("mailoney.core").info("hello %s", "world")
        line = handler.stream.getvalue().strip()
    finally:
        handler.stream = saved_stream
        # Restore the default text formatter to avoid leaking JSON config
        # into other tests.
        configure_logging("INFO", json_format=False)

    payload = _json.loads(line)
    assert payload["event"] == "log"
    assert payload["logger"] == "mailoney.core"
    assert payload["level"] == "INFO"
    assert payload["message"] == "hello world"


def test_configure_logging_writes_to_stdout():
    """Operational records go to stdout (documented contract for shippers)."""
    import logging as _logging
    import sys as _sys
    configure_logging("INFO", json_format=False)
    handler = next(h for h in _logging.getLogger().handlers if type(h) is _logging.StreamHandler)
    assert handler.stream is _sys.stdout


def test_configure_logging_keeps_file_handlers(tmp_path):
    """Re-configuring must not drop a user-installed FileHandler."""
    import logging as _logging
    root = _logging.getLogger()
    fh = _logging.FileHandler(tmp_path / "ops.log")
    root.addHandler(fh)
    try:
        configure_logging("INFO", json_format=False)
        assert fh in root.handlers
    finally:
        root.removeHandler(fh)
        fh.close()

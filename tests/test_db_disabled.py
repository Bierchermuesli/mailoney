"""
Tests for the DB-optional / disabled mode.

When ``MAILONEY_DB_URL`` is explicitly empty, the database layer must:
  * leave ``engine`` and ``Session`` unset (None),
  * make ``create_session`` return an unpersisted ``SMTPSession`` (id=None),
  * make ``update_session_data`` and ``log_credential`` no-ops.

These tests stash and restore the module-level ``engine``/``Session`` so they
do not interfere with the session-scoped fixture in ``conftest.py``.
"""
import pytest

import mailoney.db as db_module
from mailoney.db import (
    SMTPSession,
    create_session,
    init_db,
    is_db_enabled,
    log_credential,
    update_session_data,
)


@pytest.fixture
def disabled_db():
    saved_engine = db_module.engine
    saved_session = db_module.Session
    saved_flag = db_module._db_disabled
    try:
        init_db("")
        yield
    finally:
        db_module.engine = saved_engine
        db_module.Session = saved_session
        db_module._db_disabled = saved_flag


def test_init_db_empty_url_disables(disabled_db):
    assert db_module.engine is None
    assert db_module.Session is None
    assert is_db_enabled() is False


def test_create_session_returns_unpersisted_record(disabled_db):
    record = create_session(
        "10.0.0.1", 4444, "mail.example.com",
        dest_ip="10.0.0.2", dest_port=25,
    )
    assert isinstance(record, SMTPSession)
    assert record.id is None
    assert record.ip_address == "10.0.0.1"
    assert record.port == 4444
    assert record.dest_ip == "10.0.0.2"
    assert record.dest_port == 25


def test_log_credential_is_noop_when_disabled(disabled_db):
    # Must not raise even with a None session id.
    log_credential(None, "dGVzdDp0ZXN0")
    log_credential(123, "dGVzdDp0ZXN0")


def test_update_session_data_is_noop_when_disabled(disabled_db):
    update_session_data(None, '{"foo": "bar"}')
    update_session_data(123, '{"foo": "bar"}')


def test_init_db_unset_env_falls_back_to_sqlite(monkeypatch):
    """Backward compat: env var entirely unset still defaults to SQLite."""
    monkeypatch.delenv("MAILONEY_DB_URL", raising=False)
    saved_engine = db_module.engine
    saved_session = db_module.Session
    try:
        init_db(None)
        assert db_module.engine is not None
        assert db_module.Session is not None
    finally:
        db_module.engine = saved_engine
        db_module.Session = saved_session


def test_init_db_empty_env_disables(monkeypatch):
    """Empty env var (MAILONEY_DB_URL=) disables, distinct from unset."""
    monkeypatch.setenv("MAILONEY_DB_URL", "")
    saved_engine = db_module.engine
    saved_session = db_module.Session
    try:
        init_db(None)
        assert db_module.engine is None
        assert db_module.Session is None
    finally:
        db_module.engine = saved_engine
        db_module.Session = saved_session


# --- fail-closed semantics ---------------------------------------------
#
# "Nobody called init_db()" and "the operator disabled the database" must
# not look the same: the former keeps the legacy lazy initialisation so a
# library caller never silently loses sessions; only the latter no-ops.


def test_lazy_init_when_not_explicitly_disabled(monkeypatch):
    """Session is None but nobody opted out: the helpers must call init_db().

    init_db is stubbed to re-install the test engine from conftest, so the
    test checks the lazy-call contract without touching a real database
    configuration.
    """
    saved_engine, saved_session = db_module.engine, db_module.Session
    saved_flag = db_module._db_disabled
    calls = []

    def fake_init_db(db_url=None):
        calls.append(db_url)
        db_module.engine, db_module.Session = saved_engine, saved_session

    monkeypatch.setattr(db_module, "init_db", fake_init_db)
    try:
        db_module.engine = None
        db_module.Session = None
        db_module._db_disabled = False
        record = create_session("10.0.0.1", 4444, "mail.example.com")
        assert calls == [None], "init_db() should have run lazily, once"
        assert record.id is not None, "session must be persisted, not silently dropped"
        assert is_db_enabled() is True
    finally:
        db_module.engine, db_module.Session = saved_engine, saved_session
        db_module._db_disabled = saved_flag


def test_no_lazy_init_after_explicit_disable(disabled_db, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("init_db must not run after an explicit opt-out")
    monkeypatch.setattr(db_module, "init_db", boom)
    record = create_session("10.0.0.1", 4444, "mail.example.com")
    assert record.id is None
    log_credential(None, "x")
    update_session_data(None, "{}")

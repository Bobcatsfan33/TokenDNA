from __future__ import annotations

import pytest

from modules.storage.migrations import Migration, apply_migrations, migration_status


def test_apply_migrations_records_revision_once(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKENDNA_DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATA_BACKEND", raising=False)
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "migrations.db"))

    calls: list[str] = []
    migration = Migration(
        revision="test_202605220001",
        description="test migration",
        apply=lambda: calls.append("applied"),
    )

    first = apply_migrations([migration])
    second = apply_migrations([migration])
    status = migration_status([migration])

    assert calls == ["applied"]
    assert first["applied_now"] == ["test_202605220001"]
    assert second["applied_now"] == []
    assert status["up_to_date"] is True
    assert status["current"] == "test_202605220001"
    assert status["pending"] == []


def test_failed_migration_is_not_marked_applied(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKENDNA_DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATA_BACKEND", raising=False)
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "migrations.db"))

    def fail() -> None:
        raise RuntimeError("boom")

    migration = Migration(
        revision="test_202605220002",
        description="failing migration",
        apply=fail,
    )

    with pytest.raises(RuntimeError, match="boom"):
        apply_migrations([migration])

    status = migration_status([migration])
    assert status["up_to_date"] is False
    assert status["pending"] == [
        {"revision": "test_202605220002", "description": "failing migration"}
    ]


def test_api_key_role_migration_backfills_readonly(tmp_path, monkeypatch):
    monkeypatch.setenv("TOKENDNA_DB_BACKEND", "sqlite")
    monkeypatch.delenv("DATA_BACKEND", raising=False)
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "legacy-keys.db"))

    from modules.storage.migrations import _api_key_roles
    from modules.storage.pg_connection import get_adapted_db_conn

    with get_adapted_db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE api_keys (
                id           TEXT PRIMARY KEY,
                tenant_id    TEXT NOT NULL,
                name         TEXT NOT NULL,
                key_prefix   TEXT NOT NULL,
                key_hash     TEXT NOT NULL UNIQUE,
                is_active    INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL,
                last_used    TEXT
            )
            """
        )
        conn.execute(
            """INSERT INTO api_keys
               (id, tenant_id, name, key_prefix, key_hash, is_active, created_at, last_used)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            ("key-1", "tenant-1", "legacy", "tdna_legacy", "hash", 1, "2026-01-01T00:00:00", None),
        )

    _api_key_roles()
    _api_key_roles()

    with get_adapted_db_conn() as conn:
        row = conn.execute("SELECT role FROM api_keys WHERE id=?", ("key-1",)).fetchone()
    assert row["role"] == "readonly"

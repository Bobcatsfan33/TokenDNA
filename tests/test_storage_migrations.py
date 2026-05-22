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

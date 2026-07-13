from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3

from modules.storage.ddl_runner import run_ddl, split_ddl


def test_split_ddl_breaks_on_top_level_semicolons():
    schema = """
    CREATE TABLE foo (id TEXT);
    CREATE INDEX idx_foo ON foo(id);
    """
    parts = split_ddl(schema)
    assert len(parts) == 2
    assert parts[0].startswith("CREATE TABLE foo")
    assert parts[1].startswith("CREATE INDEX idx_foo")


def test_split_ddl_ignores_quoted_semicolons():
    schema = """
    CREATE TABLE foo (id TEXT, default_str TEXT DEFAULT ';');
    CREATE INDEX idx_foo ON foo(id);
    """
    parts = split_ddl(schema)
    assert len(parts) == 2
    assert "DEFAULT ';'" in parts[0]


def test_split_ddl_handles_empty_input():
    assert split_ddl("") == []
    assert split_ddl(";;;") == []
    assert split_ddl("   \n  ") == []


def test_run_ddl_applies_against_sqlite(tmp_path):
    db = str(tmp_path / "ddl_test.db")
    schema = """
    CREATE TABLE IF NOT EXISTS animals (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_animals_name ON animals(name);
    """
    run_ddl(schema, db_path=db)
    run_ddl(schema, db_path=db)  # idempotent

    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index') ORDER BY name"
        ).fetchall()
        names = {r[0] for r in rows}
        assert "animals" in names
        assert "idx_animals_name" in names
    finally:
        conn.close()


def test_run_ddl_accepts_iterable_of_statements(tmp_path):
    db = str(tmp_path / "ddl_iter.db")
    statements = [
        "CREATE TABLE IF NOT EXISTS widgets (id TEXT PRIMARY KEY)",
        "CREATE INDEX IF NOT EXISTS idx_widgets_id ON widgets(id)",
    ]
    run_ddl(statements, db_path=db)
    conn = sqlite3.connect(db)
    try:
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index')"
        ).fetchall()}
        assert "widgets" in names
        assert "idx_widgets_id" in names
    finally:
        conn.close()

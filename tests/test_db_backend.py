from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.storage import db_backend


def test_db_backend_defaults_to_sqlite_without_dual_write():
    for key in ("TOKENDNA_DB_BACKEND", "TOKENDNA_DB_DUAL_WRITE", "TOKENDNA_PG_DSN"):
        os.environ.pop(key, None)
    cfg = db_backend.get_backend_config()
    assert cfg.backend == "sqlite"
    assert cfg.dual_write is False
    assert cfg.postgres_dsn is None
    assert db_backend.should_use_postgres() is False
    assert db_backend.should_dual_write() is False


def test_db_backend_postgres_and_dual_write_flags():
    os.environ["TOKENDNA_DB_BACKEND"] = "postgres"
    os.environ["TOKENDNA_DB_DUAL_WRITE"] = "true"
    os.environ["TOKENDNA_PG_DSN"] = "postgresql://localhost:5432/tokendna"
    cfg = db_backend.get_backend_config()
    assert cfg.backend == "postgres"
    assert cfg.dual_write is True
    assert cfg.postgres_dsn
    assert db_backend.should_use_postgres() is True
    assert db_backend.should_dual_write() is True
    for key in ("TOKENDNA_DB_BACKEND", "TOKENDNA_DB_DUAL_WRITE", "TOKENDNA_PG_DSN"):
        os.environ.pop(key, None)

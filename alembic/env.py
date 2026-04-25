"""
TokenDNA — Alembic environment configuration.

The connection URL is resolved in this priority order:

  1. ``TOKENDNA_PG_DSN``        — production / staging Postgres
  2. ``TOKENDNA_ALEMBIC_URL``   — explicit override (used in tests)
  3. ``sqlalchemy.url`` in alembic.ini — dev fallback (sqlite:///./local.db)

We do NOT auto-generate migrations from a metadata object: TokenDNA's
schema is defined as raw DDL in each module, not as SQLAlchemy models. The
baseline migration applies that DDL through the same ``run_ddl`` helper used
at runtime, so module DDL and Alembic stay in sync without a duplicated
declarative layer.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make the repo importable so migrations can call into modules.* helpers.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.tokendna")


def _resolve_url() -> str:
    """Resolve DB URL: env vars → alembic.ini default."""
    for var in ("TOKENDNA_PG_DSN", "TOKENDNA_ALEMBIC_URL"):
        raw = os.getenv(var, "").strip()
        if raw:
            return raw
    return config.get_main_option("sqlalchemy.url") or "sqlite:///./local.db"


_url = _resolve_url()
config.set_main_option("sqlalchemy.url", _url)


target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL, no engine)."""
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against a real engine."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section) or {},
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

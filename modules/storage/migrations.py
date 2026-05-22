from __future__ import annotations

"""
TokenDNA storage migrations.

This module is intentionally lightweight: it uses the same shared storage
connection factory as the application, records applied revisions in
``tokendna_schema_migrations``, and fails closed when a migration cannot be
applied. It is used by the local appliance gate, CI Postgres gate, and API
startup so all paths agree on schema state.
"""

import importlib
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Iterator
from typing import Callable, Iterable

from modules.storage import db_backend
from modules.storage.pg_connection import get_adapted_db_conn

logger = logging.getLogger(__name__)

MIGRATION_TABLE = "tokendna_schema_migrations"
MIGRATION_LOCK_KEY = 773_266_001


@dataclass(frozen=True)
class Migration:
    revision: str
    description: str
    apply: Callable[[], None]


INIT_TARGETS: tuple[tuple[str, str], ...] = (
    ("modules.tenants.store", "init_db"),
    ("modules.identity.attestation_store", "init_db"),
    ("modules.identity.uis_store", "init_db"),
    ("modules.identity.trust_graph", "init_db"),
    ("modules.identity.intent_correlation", "init_db"),
    ("modules.identity.policy_guard", "init_db"),
    ("modules.identity.permission_drift", "init_db"),
    ("modules.identity.agent_lifecycle", "init_db"),
    ("modules.identity.mcp_inspector", "init_db"),
    ("modules.identity.mcp_gateway", "init_db"),
    ("modules.identity.agent_discovery", "init_db"),
    ("modules.identity.enforcement_plane", "init_db"),
    ("modules.identity.behavioral_dna", "init_db"),
    ("modules.identity.compliance_engine", "init_db"),
    ("modules.identity.cert_dashboard", "init_db"),
    ("modules.identity.policy_advisor", "init_db"),
    ("modules.identity.passport", "init_passport_db"),
    ("modules.identity.verifier_reputation", "init_reputation_db"),
    ("modules.identity.proof_of_control", "init_db"),
    ("modules.identity.certificate_transparency", "init_db"),
    ("modules.identity.network_intel", "init_db"),
    ("modules.identity.compliance", "init_db"),
    ("modules.identity.policy_bundles", "init_db"),
    ("modules.identity.decision_audit", "init_db"),
    ("modules.identity.trust_federation", "init_db"),
    ("modules.product.metering", "init_db"),
    ("modules.product.threat_sharing", "init_db"),
    ("modules.product.threat_sharing_flywheel", "init_db"),
    ("modules.product.staged_rollout", "init_db"),
    ("modules.identity.delegation_receipt", "init_db"),
    ("modules.identity.workflow_attestation", "init_db"),
    ("modules.identity.compliance_posture", "init_db"),
    ("modules.identity.honeypot_mesh", "init_db"),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_migration_table() -> None:
    with get_adapted_db_conn() as conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {MIGRATION_TABLE} (
                revision      TEXT PRIMARY KEY,
                description   TEXT NOT NULL,
                applied_at    TEXT NOT NULL
            )
            """
        )


@contextmanager
def _migration_lock() -> Iterator[None]:
    if not db_backend.should_use_postgres():
        yield
        return
    with get_adapted_db_conn() as conn:
        conn.execute("SELECT pg_advisory_lock(?)", (MIGRATION_LOCK_KEY,))
        try:
            yield
        finally:
            conn.execute("SELECT pg_advisory_unlock(?)", (MIGRATION_LOCK_KEY,))


def applied_revisions() -> list[dict[str, str]]:
    _ensure_migration_table()
    with get_adapted_db_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT revision, description, applied_at
            FROM {MIGRATION_TABLE}
            ORDER BY applied_at ASC, revision ASC
            """
        ).fetchall()
    return [
        {
            "revision": str(row["revision"]),
            "description": str(row["description"]),
            "applied_at": str(row["applied_at"]),
        }
        for row in rows
    ]


def migration_status(migrations: Iterable[Migration] | None = None) -> dict[str, object]:
    configured = list(migrations or MIGRATIONS)
    applied = {row["revision"]: row for row in applied_revisions()}
    pending = [
        {"revision": item.revision, "description": item.description}
        for item in configured
        if item.revision not in applied
    ]
    return {
        "table": MIGRATION_TABLE,
        "applied": list(applied.values()),
        "pending": pending,
        "head": configured[-1].revision if configured else None,
        "current": list(applied)[-1] if applied else None,
        "up_to_date": not pending,
    }


def _record_migration(item: Migration) -> None:
    with get_adapted_db_conn() as conn:
        conn.execute(
            f"""
            INSERT INTO {MIGRATION_TABLE}(revision, description, applied_at)
            VALUES (?, ?, ?)
            """,
            (item.revision, item.description, _utc_now()),
        )


def _has_revision(revision: str) -> bool:
    with get_adapted_db_conn() as conn:
        row = conn.execute(
            f"SELECT 1 FROM {MIGRATION_TABLE} WHERE revision=?",
            (revision,),
        ).fetchone()
    return row is not None


def _baseline_schema() -> None:
    failures: list[str] = []
    for dotted, attr in INIT_TARGETS:
        try:
            module = importlib.import_module(dotted)
            init = getattr(module, attr)
            init()
            logger.info("migration baseline applied %s.%s", dotted, attr)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{dotted}.{attr}: {exc}")
    if failures:
        joined = "\n  - ".join(failures)
        raise RuntimeError(f"baseline migration failed:\n  - {joined}")


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        revision="202605220001_baseline",
        description="Initialize TokenDNA control-plane schemas",
        apply=_baseline_schema,
    ),
)


def apply_migrations(migrations: Iterable[Migration] | None = None) -> dict[str, object]:
    configured = list(migrations or MIGRATIONS)
    _ensure_migration_table()
    applied_now: list[str] = []
    with _migration_lock():
        for item in configured:
            if _has_revision(item.revision):
                continue
            logger.info("applying storage migration %s: %s", item.revision, item.description)
            item.apply()
            _record_migration(item)
            applied_now.append(item.revision)
    status = migration_status(configured)
    status["applied_now"] = applied_now
    return status

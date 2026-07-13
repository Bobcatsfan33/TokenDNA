"""baseline — initialize all TokenDNA module schemas

Revision ID: 0001_baseline
Revises:
Create Date: 2026-04-24

This migration walks every TokenDNA module that owns its own schema and
calls its ``init_db()`` against the active Alembic connection. The DDL
itself stays defined in each module so application code and migrations
share the same source of truth.

Subsequent migrations are conventional Alembic — ``op.create_table``,
``op.add_column``, etc. — and reference table names defined here.
"""

from __future__ import annotations

import logging
from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


logger = logging.getLogger("alembic.tokendna.baseline")


# Modules whose schema initializer is the source of truth for baseline DDL.
_INIT_TARGETS: tuple[tuple[str, str], ...] = (
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


def upgrade() -> None:
    """Apply each module's init_db() against the Alembic connection.

    We import lazily inside the function so failures identify the offending
    module clearly. Any failure aborts the migration.
    """
    failures: list[tuple[str, str]] = []
    for dotted, attr in _INIT_TARGETS:
        try:
            module = __import__(dotted, fromlist=[attr])
            init = getattr(module, attr)
            init()
            logger.info("baseline: %s.%s() applied", dotted, attr)
        except Exception as exc:  # noqa: BLE001
            logger.error("baseline: %s.%s failed — %s", dotted, attr, exc)
            failures.append((f"{dotted}.{attr}", str(exc)))

    if failures:
        joined = "\n  - ".join(f"{m}: {e}" for m, e in failures)
        raise RuntimeError(f"baseline migration failed:\n  - {joined}")


def downgrade() -> None:
    """Baseline is non-reversible by design.

    Dropping every TokenDNA table on a downgrade would destroy production
    data. If you need to rebuild a database from scratch, use ``alembic
    stamp head`` against an empty database instead of ``downgrade``.
    """
    raise NotImplementedError(
        "baseline is non-reversible. Use `alembic stamp head` against a fresh database."
    )

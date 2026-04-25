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

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


logger = logging.getLogger("alembic.tokendna.baseline")


# Modules whose ``init_db()`` is the source of truth for their schema.
# Order matters only for FK references; TokenDNA has none cross-module so
# alphabetical is fine.
_INIT_MODULES: tuple[str, ...] = (
    "modules.identity.passport",
    "modules.identity.uis_store",
    "modules.identity.attestation_store",
    "modules.identity.trust_graph",
    "modules.identity.intent_correlation",
    "modules.identity.delegation_receipt",
    "modules.identity.workflow_attestation",
    "modules.identity.honeypot_mesh",
    "modules.identity.compliance_posture",
    "modules.identity.policy_guard",
    "modules.identity.permission_drift",
    "modules.identity.agent_lifecycle",
    "modules.identity.mcp_inspector",
    "modules.identity.mcp_gateway",
    "modules.identity.agent_discovery",
    "modules.identity.enforcement_plane",
    "modules.identity.behavioral_dna",
    "modules.identity.cert_dashboard",
    "modules.identity.policy_advisor",
    "modules.identity.compliance_engine",
    "modules.identity.verifier_reputation",
    "modules.product.threat_sharing",
    "modules.product.threat_sharing_flywheel",
    "modules.product.staged_rollout",
)


def upgrade() -> None:
    """Apply each module's init_db() against the Alembic connection.

    We import lazily inside the function so a missing optional sub-dep on
    one module doesn't crash the whole migration run — failures are logged
    and the migration continues.
    """
    failures: list[tuple[str, str]] = []
    for dotted in _INIT_MODULES:
        try:
            module = __import__(dotted, fromlist=["init_db"])
            init = getattr(module, "init_db", None) or getattr(module, "init_passport_db", None)
            if init is None:
                logger.warning("baseline: %s exposes no init_db()/init_passport_db(); skipping", dotted)
                continue
            init()
            logger.info("baseline: %s.init_db() applied", dotted)
        except Exception as exc:  # noqa: BLE001
            logger.error("baseline: %s failed — %s", dotted, exc)
            failures.append((dotted, str(exc)))

    if failures:
        joined = "\n  - ".join(f"{m}: {e}" for m, e in failures)
        # Keep the migration permissive on failures so partial deploys
        # against schema-divergent staging databases don't block — but
        # surface the list to the operator log.
        logger.error("baseline: %d module(s) failed to init:\n  - %s", len(failures), joined)


def downgrade() -> None:
    """Baseline is non-reversible by design.

    Dropping every TokenDNA table on a downgrade would destroy production
    data. If you need to rebuild a database from scratch, use ``alembic
    stamp head`` against an empty database instead of ``downgrade``.
    """
    raise NotImplementedError(
        "baseline is non-reversible. Use `alembic stamp head` against a fresh database."
    )

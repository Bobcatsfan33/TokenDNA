from __future__ import annotations

"""
Postgres production smoke test for the local TokenDNA control plane.

This intentionally exercises the storage-backed identity/product paths that
operators depend on during first deployment. It expects production-like env:

  TOKENDNA_DB_BACKEND=postgres
  TOKENDNA_PG_DSN=postgresql://...

It exits non-zero on the first failed operation so CI or an operator shell can
use it as a deployment gate.
"""

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _require_postgres_env() -> None:
    backend = (os.getenv("TOKENDNA_DB_BACKEND") or os.getenv("DATA_BACKEND") or "").strip().lower()
    dsn = (os.getenv("TOKENDNA_PG_DSN") or os.getenv("DATABASE_URL") or "").strip()
    if backend != "postgres":
        raise RuntimeError("TOKENDNA_DB_BACKEND=postgres is required for postgres_smoke.py")
    if not dsn:
        raise RuntimeError("TOKENDNA_PG_DSN or DATABASE_URL is required for postgres_smoke.py")


def _uis_event(event_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": event_id,
        "event_timestamp": now,
        "identity": {
            "subject": "smoke-agent",
            "agent_id": "smoke-agent",
            "provider": "local",
        },
        "auth": {"protocol": "mcp"},
        "threat": {"risk_score": 7, "risk_tier": "low"},
        "resource": {"path": "/smoke"},
    }


def main() -> None:
    _require_postgres_env()

    # Keep local appliance smoke runs deterministic and isolated.
    run_id = uuid.uuid4().hex[:12]
    tenant_id = f"smoke-tenant-{run_id}"
    subject = "smoke-operator@example.com"

    from modules.tenants import store as tenant_store
    from modules.product import metering, staged_rollout
    from modules.identity import decision_audit, policy_bundles, uis_store
    from modules.product.feature_gates import PlanTier
    from modules.storage.migrations import apply_migrations

    migration_report = apply_migrations()
    if not migration_report.get("up_to_date"):
        raise RuntimeError(f"storage migrations are not up to date: {migration_report}")

    tenant, raw_key = tenant_store.create_tenant(
        name=f"Smoke Tenant {run_id}",
        owner_email=subject,
    )
    if not tenant_store.lookup_by_key(raw_key):
        raise RuntimeError("tenant API-key lookup failed")

    usage = metering.record_usage(
        tenant_id=tenant.id,
        feature_key="policy.simulation.advanced",
        plan=PlanTier.PRO,
        amount=1,
        detail={"smoke": True, "run_id": run_id},
    )
    if usage["usage"]["status"] not in {"ok", "warning"}:
        raise RuntimeError(f"unexpected metering status: {usage['usage']['status']}")

    event_id = f"evt-{run_id}"
    event = _uis_event(event_id)
    uis_store.insert_event(tenant.id, event)
    if not uis_store.get_event(tenant.id, event_id):
        raise RuntimeError("UIS event round trip failed")

    bundle = policy_bundles.create_bundle(
        tenant_id=tenant.id,
        name=f"smoke-bundle-{run_id}",
        version="1.0.0",
        description="Postgres smoke bundle",
        config={"default_action": "allow", "created_by": subject},
    )
    if not policy_bundles.get_bundle(tenant_id=tenant.id, bundle_id=bundle["bundle_id"]):
        raise RuntimeError("policy bundle round trip failed")

    audit = decision_audit.record_decision(
        tenant_id=tenant.id,
        request_id=f"req-{run_id}",
        source_endpoint="/smoke",
        actor_subject=subject,
        evaluation_input={"uis_event": event},
        enforcement_result={"decision": {"action": "allow", "reasons": ["postgres-smoke"]}},
        policy_bundle=bundle,
    )
    if not audit.get("audit_id"):
        raise RuntimeError("decision audit round trip failed")

    grant = staged_rollout.grant_access(
        tenant_id=tenant.id,
        feature_key="ent.intent_correlation",
        granted_by=subject,
        reason="postgres smoke",
    )
    grants = staged_rollout.list_grants(tenant_id=tenant.id)
    if not grants:
        raise RuntimeError("staged rollout grant round trip failed")

    print(
        json.dumps(
            {
                "ok": True,
                "tenant_id": tenant.id,
                "usage_event_id": usage["event"]["event_id"],
                "uis_event_id": event_id,
                "policy_bundle_id": bundle["bundle_id"],
                "audit_id": audit["audit_id"],
                "rollout_grant_id": grant.grant_id,
                "schema_head": migration_report.get("head"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

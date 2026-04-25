"""
TokenDNA — Commercial tier entitlement system

Defines the three customer-facing tiers (community / pro / enterprise) and the
``ent.*`` feature gates that control access to the Phase 5 enterprise modules.

Why a separate module
---------------------
``modules.product.feature_gates`` enforces the OSS / paid plan boundaries that
existed before Phase 5. This module models the *commercial tier ladder* the
sales motion cares about (community → pro → enterprise) and emits structured
``403`` errors with the upgrade target and metadata so the UI can render an
actionable upsell rather than a generic "forbidden" page.

Public surface
--------------
- ``CommercialTier``                Enum of tiers in ascending order.
- ``FeatureGate``                   Frozen dataclass describing one gate.
- ``COMMERCIAL_FEATURES``           Catalog of every ``ent.*`` gate.
- ``tier_for_plan(plan)``           Map ``Plan`` → ``CommercialTier``.
- ``is_entitled(plan, feature)``    Pure boolean check.
- ``forbidden_payload(...)``        Build the structured 403 detail dict.
- ``require_feature(feature)``      FastAPI dependency factory (returns the
                                    resolved ``TenantContext`` so routes can
                                    swap ``Depends(get_tenant)`` 1-for-1).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from fastapi import Depends, HTTPException, status

from modules.tenants.middleware import get_tenant
from modules.tenants.models import Plan, TenantContext


# ── Tiers ─────────────────────────────────────────────────────────────────────

class CommercialTier(str, Enum):
    """Customer-facing commercial tiers, ordered by entitlement strength."""
    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


# Lower number = lower entitlement. Comparisons go through this map so the
# CommercialTier enum can stay a plain str-Enum (FastAPI/JSON friendly).
_TIER_RANK: dict[CommercialTier, int] = {
    CommercialTier.COMMUNITY: 10,
    CommercialTier.PRO: 20,
    CommercialTier.ENTERPRISE: 30,
}


def _rank(tier: CommercialTier) -> int:
    return _TIER_RANK[tier]


# Existing Plan values map onto commercial tiers. FREE and STARTER both fall
# into COMMUNITY — the commercial taxonomy is coarser than the billing plans.
_PLAN_TO_TIER: dict[Plan, CommercialTier] = {
    Plan.FREE: CommercialTier.COMMUNITY,
    Plan.STARTER: CommercialTier.COMMUNITY,
    Plan.PRO: CommercialTier.PRO,
    Plan.ENTERPRISE: CommercialTier.ENTERPRISE,
}


def tier_for_plan(plan: Plan | str) -> CommercialTier:
    """
    Resolve a billing ``Plan`` (or its raw string value) to a commercial tier.
    Unknown values fall back to COMMUNITY — the most restrictive tier — so
    misconfigured tenants never accidentally get paid features.
    """
    if isinstance(plan, Plan):
        return _PLAN_TO_TIER.get(plan, CommercialTier.COMMUNITY)
    try:
        return _PLAN_TO_TIER.get(Plan(str(plan).lower()), CommercialTier.COMMUNITY)
    except ValueError:
        return CommercialTier.COMMUNITY


# ── Feature gate catalog ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class FeatureGate:
    """One commercial entitlement gate."""
    key: str
    name: str
    min_tier: CommercialTier
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "min_tier": self.min_tier.value,
            "description": self.description,
        }


# Phase 5 commercial gates — every Phase 5 module is anchored here.
COMMERCIAL_FEATURES: dict[str, FeatureGate] = {
    gate.key: gate
    for gate in (
        FeatureGate(
            key="ent.mcp_gateway",
            name="MCP Security Gateway",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Enforce MCP server attestation, capability-aware routing, "
                "and intent-aware request inspection at the network edge."
            ),
        ),
        FeatureGate(
            key="ent.agent_discovery",
            name="Agent Discovery & Inventory",
            min_tier=CommercialTier.PRO,
            description=(
                "Continuously inventory agents, detect ghost/orphaned agents, "
                "and enforce lifecycle offboarding."
            ),
        ),
        FeatureGate(
            key="ent.enforcement_plane",
            name="Real-Time Enforcement Plane",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Real-time policy guard, agent freeze/unfreeze, and runtime "
                "enforcement of constitutional rules."
            ),
        ),
        FeatureGate(
            key="ent.behavioral_dna",
            name="Behavioral DNA Drift",
            min_tier=CommercialTier.PRO,
            description=(
                "Track per-agent behavioral DNA fingerprints and alert on "
                "permission/behavior drift relative to attested baselines."
            ),
        ),
        FeatureGate(
            key="ent.blast_radius",
            name="Blast Radius Simulator",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Simulate the downstream impact of an agent compromise across "
                "the trust graph."
            ),
        ),
        FeatureGate(
            key="ent.intent_correlation",
            name="Intent Correlation Engine",
            min_tier=CommercialTier.ENTERPRISE,
            description=(
                "Correlate UIS events against attack-playbook signatures to "
                "surface multi-step exploit intent."
            ),
        ),
    )
}


def get_feature(feature_key: str) -> FeatureGate:
    """
    Look up a gate. Raises ``KeyError`` for unknown keys — callers should
    catch and translate to the appropriate user-facing error.
    """
    try:
        return COMMERCIAL_FEATURES[feature_key]
    except KeyError as exc:
        raise KeyError(f"Unknown commercial feature gate: {feature_key!r}") from exc


def list_features(plan: Plan | str | None = None) -> list[dict[str, Any]]:
    """
    Return the full feature matrix. When ``plan`` is supplied, each row also
    includes an ``entitled`` boolean for that plan's tier.
    """
    rows: list[dict[str, Any]] = []
    tier = tier_for_plan(plan) if plan is not None else None
    for gate in COMMERCIAL_FEATURES.values():
        row = gate.to_dict()
        if tier is not None:
            row["tenant_tier"] = tier.value
            row["entitled"] = _rank(tier) >= _rank(gate.min_tier)
        rows.append(row)
    return rows


# ── Entitlement checks ────────────────────────────────────────────────────────

def is_entitled(plan: Plan | str, feature_key: str) -> bool:
    """
    Pure boolean check. Returns ``False`` for unknown features so a typo in a
    gate key cannot accidentally grant access.
    """
    gate = COMMERCIAL_FEATURES.get(feature_key)
    if gate is None:
        return False
    return _rank(tier_for_plan(plan)) >= _rank(gate.min_tier)


def forbidden_payload(
    *,
    tenant: TenantContext,
    feature_key: str,
    gate: FeatureGate,
) -> dict[str, Any]:
    """
    Build the structured ``detail`` body for a 403 response. The shape is
    stable — the dashboard renders an upsell modal off these fields.
    """
    return {
        "error": "feature_not_entitled",
        "feature": feature_key,
        "feature_name": gate.name,
        "tenant_id": tenant.tenant_id,
        "tenant_tier": tier_for_plan(tenant.plan).value,
        "required_tier": gate.min_tier.value,
        "message": (
            f"Feature '{gate.name}' requires the {gate.min_tier.value} tier; "
            f"tenant '{tenant.tenant_id}' is on the "
            f"{tier_for_plan(tenant.plan).value} tier."
        ),
        "upgrade_url": "/billing/upgrade",
    }


# ── FastAPI dependency factory ────────────────────────────────────────────────

def require_feature(feature_key: str) -> Callable[..., TenantContext]:
    """
    FastAPI dependency factory.

    Usage — drop-in replacement for ``Depends(get_tenant)``::

        @app.post("/api/simulate/blast_radius")
        async def api_blast_radius(
            body: dict,
            tenant: TenantContext = Depends(require_feature("ent.blast_radius")),
        ):
            ...

    Or as a side-effect dependency on routes that already inject tenant via
    a different dependency (e.g. ``require_role``)::

        @app.post(
            "/api/intent/playbooks",
            dependencies=[Depends(require_feature("ent.intent_correlation"))],
        )
        async def api_intent_add_playbook(
            body: dict,
            tenant: TenantContext = Depends(require_role(Role.ANALYST)),
        ):
            ...

    Behaviour:
      - ``get_tenant`` runs first; auth failures continue to return 401.
      - If the tenant's tier is below the gate's ``min_tier``, raises
        ``HTTPException(403)`` with the ``forbidden_payload`` detail.
      - On success returns the resolved ``TenantContext`` (so callers using
        the first form keep working unchanged).

    Unknown feature keys are caught at *dependency-construction* time so a
    typo in a route decorator fails on import rather than at request time.
    """
    gate = get_feature(feature_key)  # KeyError → fast fail at import.

    def _dependency(
        tenant: TenantContext = Depends(get_tenant),
    ) -> TenantContext:
        if _rank(tier_for_plan(tenant.plan)) < _rank(gate.min_tier):
            # Staged-rollout override: a tenant may be allowlisted onto a
            # feature without paying for the tier. Lookup is best-effort —
            # if staged_rollout is unavailable, fall through to the 403.
            try:
                from modules.product import staged_rollout  # noqa: PLC0415
                if staged_rollout.is_allowlisted(tenant.tenant_id, feature_key):
                    return tenant
            except Exception:  # noqa: BLE001
                pass
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=forbidden_payload(
                    tenant=tenant,
                    feature_key=feature_key,
                    gate=gate,
                ),
            )
        return tenant

    # Friendly repr in OpenAPI / debug logs.
    _dependency.__name__ = f"require_feature[{feature_key}]"
    return _dependency

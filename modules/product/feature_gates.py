"""
TokenDNA -- commercialization feature-gating helpers.

Defines explicit OSS vs paid feature boundaries and helpers for endpoint-level
plan checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from modules.tenants.models import Plan


def _tier_value(plan: Plan | str) -> int:
    value = str(plan.value if isinstance(plan, Plan) else plan).lower()
    order = {
        "free": 10,
        "starter": 20,
        "pro": 30,
        "enterprise": 40,
    }
    return order.get(value, 0)


@dataclass(frozen=True)
class FeatureGate:
    key: str
    min_plan: Plan
    description: str
    tier: str  # "oss" | "paid"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "min_plan": self.min_plan.value,
            "description": self.description,
            "tier": self.tier,
        }


FEATURE_GATES: dict[str, FeatureGate] = {
    # OSS baseline
    "uis.normalize": FeatureGate(
        key="uis.normalize",
        min_plan=Plan.FREE,
        description="UIS protocol normalization and schema access",
        tier="oss",
    ),
    "agent.attestation": FeatureGate(
        key="agent.attestation",
        min_plan=Plan.FREE,
        description="Agent attestation creation and verification",
        tier="oss",
    ),
    "policy.bundle.basic": FeatureGate(
        key="policy.bundle.basic",
        min_plan=Plan.FREE,
        description="Create/list/activate policy bundles",
        tier="oss",
    ),
    # Paid differentiation
    "policy.simulation.advanced": FeatureGate(
        key="policy.simulation.advanced",
        min_plan=Plan.PRO,
        description="Versioned dry-run simulations with expected-action overlays",
        tier="paid",
    ),
    "intel.cross_tenant_controls": FeatureGate(
        key="intel.cross_tenant_controls",
        min_plan=Plan.PRO,
        description="Suppression/allowlist governance and decay operations",
        tier="paid",
    ),
    "compliance.signed_snapshots": FeatureGate(
        key="compliance.signed_snapshots",
        min_plan=Plan.PRO,
        description="Signed OSCAL/eMASS snapshot generation and verification",
        tier="paid",
    ),
    "operator.enterprise_status": FeatureGate(
        key="operator.enterprise_status",
        min_plan=Plan.ENTERPRISE,
        description="Enterprise operator telemetry and reliability surface",
        tier="paid",
    ),
}


def is_feature_enabled(plan: Plan | str, feature_key: str) -> bool:
    gate = FEATURE_GATES.get(feature_key)
    if gate is None:
        return False
    return _tier_value(plan) >= _tier_value(gate.min_plan)


def list_feature_matrix() -> list[dict[str, Any]]:
    return [gate.to_dict() for gate in FEATURE_GATES.values()]


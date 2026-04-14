from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_feature_gate_module_exposes_plan_tier_and_evaluate():
    from modules.product.feature_gates import PlanTier, evaluate_feature_access

    assert PlanTier.FREE.value == "free"
    result = evaluate_feature_access(
        feature_name="uis.normalize",
        plan=PlanTier.FREE,
        identity_fields={"subject": "user-1"},
    )
    assert result["enabled"] is True
    assert result["reason"] == "ok"


def test_operator_status_payload_shape():
    from api import api_operator_status

    # Validate payload contract without invoking network services.
    # Build minimal fake tenant context expected by dependency output.
    class _Tenant:
        tenant_id = "tenant-1"

    result = __import__("asyncio").run(api_operator_status(tenant=_Tenant()))
    assert result["tenant_id"] == "tenant-1"
    assert "dependencies" in result
    assert "slo" in result
    assert "edge_decision_ms" in result["slo"]
    assert "rate_limit_per_minute" in result["slo"]
    assert "posture" in result


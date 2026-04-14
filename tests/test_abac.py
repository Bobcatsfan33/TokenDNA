from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity.abac import evaluate_attestation_policy


def _base_event(score: int = 80, tier: str = "allow") -> dict:
    return {"threat": {"risk_score": score, "risk_tier": tier}}


def test_abac_blocks_high_identity_risk():
    decision = evaluate_attestation_policy(
        uis_event=_base_event(score=20, tier="block"),
        attestation={"attestation_id": "a1", "why": {"scope": ["read"]}},
        drift=None,
        certificate_verified=True,
    )
    assert decision.action == "block"


def test_abac_step_up_without_attestation():
    decision = evaluate_attestation_policy(
        uis_event=_base_event(score=80, tier="allow"),
        attestation=None,
        drift=None,
        certificate_verified=True,
    )
    assert decision.action == "step_up"


def test_abac_blocks_scope_escalation():
    decision = evaluate_attestation_policy(
        uis_event=_base_event(score=80, tier="allow"),
        attestation={"attestation_id": "a1", "why": {"scope": ["orders:read"]}},
        drift=None,
        certificate_verified=True,
        required_scope=["orders:admin"],
    )
    assert decision.action == "block"


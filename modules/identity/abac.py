"""
TokenDNA -- Attestation-aware ABAC policy engine.

Evaluates deterministic allow/step-up/block outcomes from UIS event attributes
plus attestation and drift context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ABACDecision:
    action: str
    reasons: list[str]
    policy_trace: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reasons": self.reasons,
            "policy_trace": self.policy_trace,
        }


def evaluate_attestation_policy(
    *,
    uis_event: dict[str, Any],
    attestation: dict[str, Any] | None,
    drift: dict[str, Any] | None,
    certificate_verified: bool | None,
    required_scope: list[str] | None = None,
) -> ABACDecision:
    reasons: list[str] = []
    trace: dict[str, Any] = {
        "checks": {},
        "inputs": {
            "required_scope": required_scope or [],
            "certificate_verified": certificate_verified,
        },
    }

    threat = uis_event.get("threat", {}) or {}
    risk_score = int(threat.get("risk_score", 0))
    risk_tier = str(threat.get("risk_tier", "unknown"))
    trace["checks"]["risk"] = {"score": risk_score, "tier": risk_tier}

    # Hard blocks
    if risk_tier in {"revoke", "block"} or risk_score < 30:
        reasons.append("high_identity_risk")
        return ABACDecision(action="block", reasons=reasons, policy_trace=trace)

    if attestation is None:
        reasons.append("missing_attestation_baseline")
        trace["checks"]["attestation"] = {"present": False}
        return ABACDecision(action="step_up", reasons=reasons, policy_trace=trace)

    trace["checks"]["attestation"] = {
        "present": True,
        "attestation_id": attestation.get("attestation_id"),
    }

    if certificate_verified is False:
        reasons.append("certificate_verification_failed")
        trace["checks"]["certificate"] = {"verified": False}
        return ABACDecision(action="block", reasons=reasons, policy_trace=trace)

    trace["checks"]["certificate"] = {"verified": bool(certificate_verified)}

    if drift:
        drift_score = float(drift.get("score", 0.0))
        trace["checks"]["drift"] = {"score": drift_score, "severity": drift.get("severity")}
        if drift_score >= 0.6:
            reasons.append("critical_runtime_drift")
            return ABACDecision(action="block", reasons=reasons, policy_trace=trace)
        if drift_score >= 0.3:
            reasons.append("moderate_runtime_drift")
            return ABACDecision(action="step_up", reasons=reasons, policy_trace=trace)

    # Scope policy (least privilege)
    if required_scope:
        granted_scope = set(attestation.get("why", {}).get("scope", []) or [])
        if not set(required_scope).issubset(granted_scope):
            reasons.append("scope_not_authorized")
            trace["checks"]["scope"] = {
                "required": required_scope,
                "granted": sorted(granted_scope),
            }
            return ABACDecision(action="block", reasons=reasons, policy_trace=trace)
        trace["checks"]["scope"] = {"required": required_scope, "authorized": True}

    # Conservative step-up for medium risk
    if risk_tier == "step_up" or risk_score < 60:
        reasons.append("elevated_identity_risk")
        return ABACDecision(action="step_up", reasons=reasons, policy_trace=trace)

    reasons.append("policy_allow")
    return ABACDecision(action="allow", reasons=reasons, policy_trace=trace)


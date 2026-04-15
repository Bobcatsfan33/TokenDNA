"""
TokenDNA -- Runtime drift detection against attested agent baseline.

This module compares runtime-provided agent integrity signals against the
latest attested baseline and computes a normalized drift score.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _parse_chain(raw: str) -> list[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DriftAssessment:
    score: float
    severity: str
    reasons: list[str]

    @property
    def is_drift(self) -> bool:
        return self.score > 0.0

    @property
    def should_step_up(self) -> bool:
        return self.score >= 0.3

    @property
    def should_block(self) -> bool:
        return self.score >= 0.6

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "is_drift": self.is_drift,
            "should_step_up": self.should_step_up,
            "should_block": self.should_block,
        }


def assess_runtime_drift(
    attestation: dict[str, Any],
    *,
    request_headers: dict[str, str],
    observed_scope: list[str],
) -> DriftAssessment:
    """
    Compute drift against attested WHAT/HOW/WHY dimensions.

    Scoring intentionally requires explicit runtime evidence headers.
    Missing headers are treated as "unknown" (no penalty) rather than drift.
    """
    what = attestation.get("what", {}) or {}
    how = attestation.get("how", {}) or {}
    why = attestation.get("why", {}) or {}

    score = 0.0
    reasons: list[str] = []

    current_soul_hash = request_headers.get("x-agent-soul-hash", "")
    if current_soul_hash and what.get("soul_hash") and current_soul_hash != what.get("soul_hash"):
        score += 0.35
        reasons.append("soul_hash_mismatch")

    current_model_fp = request_headers.get("x-agent-model-fingerprint", "")
    if current_model_fp and what.get("model_fingerprint") and current_model_fp != what.get("model_fingerprint"):
        score += 0.25
        reasons.append("model_fingerprint_mismatch")

    current_mcp_hash = request_headers.get("x-agent-mcp-manifest-hash", "")
    if current_mcp_hash and what.get("mcp_manifest_hash") and current_mcp_hash != what.get("mcp_manifest_hash"):
        score += 0.2
        reasons.append("mcp_manifest_hash_mismatch")

    expected_dpop_bound = bool(how.get("dpop_bound"))
    dpop_present = bool(request_headers.get("dpop"))
    if expected_dpop_bound and not dpop_present:
        score += 0.1
        reasons.append("dpop_binding_missing")

    expected_mtls_bound = bool(how.get("mtls_bound"))
    mtls_present = bool(request_headers.get("x-mtls-subject"))
    if expected_mtls_bound and not mtls_present:
        score += 0.1
        reasons.append("mtls_binding_missing")

    expected_scope = set(why.get("scope", []) or [])
    if expected_scope and observed_scope:
        if not set(observed_scope).issubset(expected_scope):
            score += 0.2
            reasons.append("scope_escalation_detected")

    expected_chain = [v for v in (why.get("delegation_chain", []) or []) if v]
    observed_chain = _parse_chain(request_headers.get("x-agent-delegation-chain", ""))
    if expected_chain and observed_chain and observed_chain != expected_chain:
        score += 0.15
        reasons.append("delegation_chain_drift")

    score = round(min(score, 1.0), 4)
    if score >= 0.6:
        severity = "critical"
    elif score >= 0.4:
        severity = "high"
    elif score >= 0.2:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "none"

    return DriftAssessment(score=score, severity=severity, reasons=reasons)


def build_drift_event(
    *,
    tenant_id: str,
    agent_id: str,
    attestation_id: str | None,
    certificate_id: str | None,
    assessment: DriftAssessment,
    request_id: str,
) -> dict[str, Any]:
    # Keep IDs deterministic per request so repeated processing upserts cleanly.
    return {
        "drift_event_id": f"{tenant_id}:{agent_id}:{request_id}",
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "attestation_id": attestation_id,
        "certificate_id": certificate_id,
        "detected_at": _iso_now(),
        "severity": assessment.severity,
        "drift_score": assessment.score,
        "reasons": assessment.reasons,
        "request_id": request_id,
    }

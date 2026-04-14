"""
TokenDNA -- Shared edge/runtime enforcement decision engine.

Keeps `/secure` and explicit policy evaluation endpoints behaviorally aligned by
running certificate, drift, and ABAC checks through one function.
"""

from __future__ import annotations

import os
import time
from typing import Any

from modules.identity.abac import evaluate_attestation_policy
from modules.identity.attestation_certificates import verify_certificate
from modules.identity.attestation_drift import assess_runtime_drift
from modules.identity.certificate_status import certificate_status_payload


def _slo_target_ms() -> float:
    try:
        return max(0.001, float(os.getenv("EDGE_DECISION_SLO_MS", "5")))
    except Exception:
        return 5.0


def _slo_violation_action() -> str:
    action = str(os.getenv("EDGE_SLO_VIOLATION_ACTION", "allow")).lower()
    if action in {"allow", "step_up", "block"}:
        return action
    return "allow"


def evaluate_runtime_enforcement(
    *,
    uis_event: dict[str, Any],
    attestation: dict[str, Any] | None,
    certificate: dict[str, Any] | None,
    certificate_id: str,
    request_headers: dict[str, str],
    observed_scope: list[str],
    required_scope: list[str] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    certificate_verified: bool | None = None
    authn_failure = False
    cert_status: dict[str, Any] | None = None

    cert_verify_started = time.perf_counter()
    if certificate_id:
        if certificate is None:
            authn_failure = True
            cert_status = certificate_status_payload(certificate=None, verification=None)
        else:
            verification = verify_certificate(certificate)
            cert_status = certificate_status_payload(certificate=certificate, verification=verification)
            certificate_verified = bool(verification.get("valid", False))
            if not certificate_verified:
                authn_failure = True
    cert_verify_ms = round((time.perf_counter() - cert_verify_started) * 1000.0, 3)

    drift_started = time.perf_counter()
    drift = None
    if attestation is not None:
        drift_assessment = assess_runtime_drift(
            attestation=attestation,
            request_headers=request_headers,
            observed_scope=observed_scope,
        )
        drift = drift_assessment.to_dict()
    drift_ms = round((time.perf_counter() - drift_started) * 1000.0, 3)

    policy_started = time.perf_counter()
    decision = evaluate_attestation_policy(
        uis_event=uis_event,
        attestation=attestation,
        drift=drift,
        certificate_verified=certificate_verified,
        required_scope=required_scope or [],
    ).to_dict()
    policy_ms = round((time.perf_counter() - policy_started) * 1000.0, 3)

    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    slo_target_ms = _slo_target_ms()
    slo_met = elapsed_ms <= slo_target_ms
    slo_action = _slo_violation_action()

    if not slo_met:
        decision["reasons"] = list(decision.get("reasons", [])) + ["edge_slo_exceeded"]
        trace = decision.get("policy_trace", {})
        if isinstance(trace, dict):
            trace["slo"] = {
                "target_ms": slo_target_ms,
                "elapsed_ms": elapsed_ms,
                "met": False,
                "violation_action": slo_action,
            }
            decision["policy_trace"] = trace
        if slo_action in {"step_up", "block"} and decision.get("action") == "allow":
            decision["action"] = slo_action
        elif slo_action == "block" and decision.get("action") == "step_up":
            decision["action"] = "block"

    return {
        "decision": decision,
        "authn_failure": authn_failure,
        "certificate_status": cert_status,
        "drift": drift,
        "timing": {
            "cert_verify_ms": cert_verify_ms,
            "drift_ms": drift_ms,
            "policy_ms": policy_ms,
            "elapsed_ms": elapsed_ms,
            "slo_target_ms": slo_target_ms,
            "slo_met": slo_met,
        },
    }


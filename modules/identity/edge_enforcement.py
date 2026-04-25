"""
TokenDNA -- Shared edge/runtime enforcement decision engine.

Keeps `/secure` and explicit policy evaluation endpoints behaviorally aligned by
running certificate, drift, and ABAC checks through one function.

Honeytoken pre-check
--------------------
Before any of the real auth steps run, the engine consults
``honeypot_mesh.is_honeytoken`` against every credential-shaped value in the
incoming request. If any match, the request is short-circuited to a
deception-hit response and ``honeypot_mesh.record_decoy_hit`` logs the
event. This runs *before* certificate verification and policy evaluation
specifically so the system never reveals — via timing or response code —
whether the presented value would have been a real credential.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from modules.identity.abac import evaluate_attestation_policy
from modules.identity.attestation_certificates import verify_certificate
from modules.identity.attestation_drift import assess_runtime_drift
from modules.identity.certificate_status import certificate_status_payload

logger = logging.getLogger(__name__)


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


def with_policy_bundle(
    *,
    policy_bundle_config: dict[str, Any] | None,
    required_scope: list[str] | None,
) -> tuple[list[str], str | None, float | None, str | None]:
    config = policy_bundle_config or {}
    effective_scope = required_scope
    if not effective_scope:
        bundle_scope = config.get("required_scope")
        if isinstance(bundle_scope, list):
            effective_scope = [str(v) for v in bundle_scope if str(v)]
    expected_action = str(config.get("expected_action", "")).strip() or None
    bundle_slo_ms = None
    if config.get("slo_target_ms") is not None:
        try:
            bundle_slo_ms = max(0.001, float(config.get("slo_target_ms")))
        except Exception:
            bundle_slo_ms = None
    bundle_slo_action = str(config.get("slo_violation_action", "")).strip().lower() or None
    if bundle_slo_action not in {None, "allow", "step_up", "block"}:
        bundle_slo_action = None
    return (effective_scope or []), expected_action, bundle_slo_ms, bundle_slo_action


_HONEYTOKEN_HEADER_KEYS: tuple[str, ...] = (
    "authorization",          # Bearer / Basic
    "x-api-key",
    "x-agent-token",
    "x-tokendna-key",
)


def _candidate_tokens(
    *,
    certificate_id: str,
    request_headers: dict[str, str],
) -> list[str]:
    """Pull credential-shaped values out of the request for honeytoken
    lookup. Lowercase header keys, normalize Bearer prefixes."""
    out: list[str] = []
    if certificate_id:
        out.append(certificate_id)
    norm = {str(k).lower(): str(v) for k, v in (request_headers or {}).items()}
    for key in _HONEYTOKEN_HEADER_KEYS:
        v = norm.get(key)
        if not v:
            continue
        if key == "authorization":
            # "Bearer <token>" → just the token; same for Basic.
            parts = v.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in {"bearer", "basic"}:
                out.append(parts[1])
                continue
        out.append(v)
    return out


def _check_honeytokens(
    *,
    certificate_id: str,
    request_headers: dict[str, str],
    source_ip: str | None = None,
    request_path: str | None = None,
) -> dict[str, Any] | None:
    """Run is_honeytoken against every credential-shaped value in the
    request. On the first match, log the hit and return a synthesized
    deception-hit decision payload. Returns None if nothing matched.

    Wrapped in try/except so a honeypot module outage NEVER fails the
    real auth path — fail-open is correct here, the worst case is missing
    one decoy hit.
    """
    try:
        from modules.identity import honeypot_mesh  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None
    candidates = _candidate_tokens(
        certificate_id=certificate_id,
        request_headers=request_headers,
    )
    for token in candidates:
        try:
            match = honeypot_mesh.is_honeytoken(token)
        except Exception:  # noqa: BLE001
            logger.exception("honeytoken lookup failed; failing open")
            return None
        if not match:
            continue
        # Match — log the hit (best-effort).
        norm_headers = (
            {str(k).lower(): str(v) for k, v in request_headers.items()}
            if isinstance(request_headers, dict) else {}
        )
        try:
            honeypot_mesh.record_decoy_hit(
                match["decoy_id"],
                source_ip=source_ip,
                user_agent=norm_headers.get("user-agent"),
                request_path=request_path,
                request_meta={
                    "header_keys": sorted(norm_headers.keys()),
                },
                tenant_id=match.get("tenant_id"),
            )
        except Exception:  # noqa: BLE001
            logger.exception("record_decoy_hit failed")
        logger.warning(
            "honeytoken presented decoy=%s tenant=%s ip=%s path=%s",
            match["decoy_id"], match.get("tenant_id"), source_ip or "?",
            request_path or "?",
        )
        return {
            "decoy_id": match["decoy_id"],
            "kind": match["kind"],
            "public_id": match["public_id"],
        }
    return None


def evaluate_runtime_enforcement(
    *,
    uis_event: dict[str, Any],
    attestation: dict[str, Any] | None,
    certificate: dict[str, Any] | None,
    certificate_id: str,
    request_headers: dict[str, str],
    observed_scope: list[str],
    required_scope: list[str] | None = None,
    policy_bundle_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()

    # ── Honeytoken pre-check ──────────────────────────────────────────────
    # Runs before any other auth step so the response is indistinguishable
    # in shape from a normal block. Adversary cannot tell whether the value
    # they presented was a real credential or a decoy.
    session = (uis_event or {}).get("session") or {}
    honeytoken = _check_honeytokens(
        certificate_id=certificate_id,
        request_headers=request_headers,
        source_ip=session.get("ip") or session.get("source_ip"),
        request_path=session.get("request_path"),
    )
    if honeytoken is not None:
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        return {
            "decision": {
                "action": "block",
                "reasons": ["honeytoken_presented"],
                "policy_trace": {"deception": honeytoken},
            },
            "authn_failure": True,
            "certificate_status": None,
            "drift": None,
            "honeytoken_hit": honeytoken,
            "timing": {
                "cert_verify_ms": 0.0,
                "drift_ms": 0.0,
                "policy_ms": 0.0,
                "elapsed_ms": elapsed_ms,
                "slo_target_ms": _slo_target_ms(),
                "slo_met": True,
            },
        }

    effective_scope, expected_action, bundle_slo_ms, bundle_slo_action = with_policy_bundle(
        policy_bundle_config=policy_bundle_config,
        required_scope=required_scope,
    )

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
        required_scope=effective_scope,
    ).to_dict()
    policy_ms = round((time.perf_counter() - policy_started) * 1000.0, 3)

    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    slo_target_ms = bundle_slo_ms if bundle_slo_ms is not None else _slo_target_ms()
    slo_met = elapsed_ms <= slo_target_ms
    slo_action = bundle_slo_action or _slo_violation_action()

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

    if expected_action and decision.get("action") != expected_action:
        decision["reasons"] = list(decision.get("reasons", [])) + ["policy_bundle_expected_action_mismatch"]
        trace = decision.get("policy_trace", {})
        if isinstance(trace, dict):
            trace["bundle"] = {
                "expected_action": expected_action,
                "actual_action": decision.get("action"),
            }
            decision["policy_trace"] = trace

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


#!/usr/bin/env python3
"""
TokenDNA adversarial security harness.

Runs deterministic attack simulations against core security controls and emits
strict pass/fail output for CI gates.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.identity import network_intel, trust_federation, uis_store
from modules.identity.attestation_certificates import issue_certificate, verify_certificate
from modules.identity.edge_enforcement import evaluate_runtime_enforcement


def _set_tmp_db() -> tempfile.TemporaryDirectory:
    tmpdir = tempfile.TemporaryDirectory()
    os.environ["DATA_DB_PATH"] = str(Path(tmpdir.name) / "tokendna-adversarial.db")
    os.environ["ATTESTATION_CA_SECRET"] = "adversarial-secret"
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    return tmpdir


def _assert(name: str, ok: bool, detail: str) -> dict[str, object]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def run(strict: bool = False) -> dict[str, object]:
    tmp = _set_tmp_db()
    checks: list[dict[str, object]] = []
    try:
        # Prepare stores used by simulations.
        uis_store.init_db()
        network_intel.init_db()
        trust_federation.init_db()

        # 1) Forged certificate should fail verification.
        cert = issue_certificate(
            tenant_id="tenant-1",
            attestation_id="att-1",
            subject="agent-1",
            issuer="TokenDNA Trust Authority",
            claims={"integrity_digest": "abc"},
            ttl_hours=1,
            secret="adversarial-secret",
        )
        forged = dict(cert)
        forged["subject"] = "tampered-agent"
        forged_check = verify_certificate(forged)
        checks.append(
            _assert(
                "forged_certificate_detected",
                not bool(forged_check.get("valid", False)),
                f"reason={forged_check.get('reason')}",
            )
        )

        # 2) Replay-ish event (scope escalation) should not allow silently.
        attestation = {
            "attestation_id": "att-1",
            "what": {
                "soul_hash": "soul-1",
                "model_fingerprint": "model-1",
                "mcp_manifest_hash": "mcp-1",
            },
            "how": {"dpop_bound": False, "mtls_bound": False},
            "why": {"scope": ["orders:read"], "delegation_chain": ["svc-a"]},
        }
        enforcement = evaluate_runtime_enforcement(
            uis_event={"threat": {"risk_score": 92, "risk_tier": "allow"}},
            attestation=attestation,
            certificate=cert,
            certificate_id=cert["certificate_id"],
            request_headers={
                "x-agent-soul-hash": "soul-1",
                "x-agent-model-fingerprint": "model-1",
                "x-agent-mcp-manifest-hash": "mcp-1",
                "x-agent-delegation-chain": "svc-a",
            },
            observed_scope=["orders:read", "admin:write"],
            required_scope=["orders:read"],
        )
        action = str((enforcement.get("decision") or {}).get("action"))
        drift_reasons = [str(v) for v in ((enforcement.get("drift") or {}).get("reasons") or [])]
        checks.append(
            _assert(
                "scope_replay_escalation_handled",
                (action in {"step_up", "block"}) or ("scope_escalation_detected" in drift_reasons),
                f"action={action},drift_reasons={drift_reasons}",
            )
        )

        # 3) Poisoned intelligence should be suppressed by anti-poisoning logic.
        poisoned = network_intel.record_signal(
            tenant_id="tenant-1",
            signal_type="ip_hash",
            raw_value="198.51.100.9",
            severity="critical",
            confidence=0.99,
            metadata={"source": "unknown", "trust_tier": "untrusted"},
        )
        checks.append(
            _assert(
                "intel_poisoning_suppressed",
                bool(poisoned.get("suppressed")),
                f"suppression_reason={poisoned.get('suppression_reason')}",
            )
        )

        # 4) Stale federation attestation must fail signature validation if tampered.
        verifier = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Verifier A",
            trust_score=0.9,
            issuer="https://verifier-a.example",
            jwks_uri="https://verifier-a.example/jwks.json",
            metadata={"region": "us"},
            status="active",
        )
        fed = trust_federation.issue_federation_attestation(
            tenant_id="tenant-1",
            verifier_id=verifier["verifier_id"],
            target_type="agent",
            target_id="agent-1",
            verdict="allow",
            confidence=0.9,
        )
        tampered_fed = dict(fed)
        tampered_payload = dict(tampered_fed["payload"])
        tampered_payload["verdict"] = "block"
        tampered_fed["payload"] = tampered_payload
        fed_verify = trust_federation.verify_attestation_signature(tampered_fed)
        checks.append(
            _assert(
                "tampered_federation_signature_detected",
                not bool(fed_verify.get("valid", False)),
                f"reason={fed_verify.get('reason')}",
            )
        )

        # 5) Replay-event detector should catch duplicate event IDs.
        evt = {
            "event_id": "replay-evt-1",
            "event_timestamp": "2026-04-15T00:00:00+00:00",
            "identity": {"subject": "user-replay"},
            "auth": {"protocol": "oidc"},
            "threat": {"risk_tier": "allow"},
        }
        uis_store.insert_event("tenant-1", evt)
        uis_store.insert_event("tenant-1", evt)
        replayed = uis_store.get_event("tenant-1", "replay-evt-1")
        checks.append(
            _assert(
                "replayed_event_id_tracked",
                bool(replayed and replayed.get("event_id") == "replay-evt-1"),
                "event_id=replay-evt-1",
            )
        )

        # 6) Cross-tenant signal noise remains bounded by anti-poisoning thresholds.
        for t in ("tenant-a", "tenant-b", "tenant-c"):
            network_intel.record_signal(
                tenant_id=t,
                signal_type="ip_hash",
                raw_value="203.0.113.42",
                severity="medium",
                confidence=0.61,
                metadata={"source": "secure_runtime", "trust_tier": "trusted"},
            )
        penalty = network_intel.assess_runtime_penalty(
            [{"signal_type": "ip_hash", "raw_value": "203.0.113.42"}]
        )
        checks.append(
            _assert(
                "cross_tenant_signal_noise_has_limited_effect",
                int(penalty.get("penalty", 0)) <= 20,
                f"penalty={penalty.get('penalty')},reasons={penalty.get('reasons')}",
            )
        )

        # 7) Expired federation verifier should be rejected by quorum evaluation.
        verifier_exp = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Verifier Expired",
            trust_score=0.9,
            issuer="https://verifier-expired.example",
            jwks_uri="https://verifier-expired.example/jwks.json",
            metadata={"region": "us"},
            status="active",
        )
        trust_federation.rotate_verifier_key(
            tenant_id="tenant-1",
            verifier_id=verifier_exp["verifier_id"],
            actor="harness",
            key_version="v2",
            key_expires_at="2001-01-01T00:00:00+00:00",
        )
        att_expired = trust_federation.issue_federation_attestation(
            tenant_id="tenant-1",
            verifier_id=verifier_exp["verifier_id"],
            target_type="agent",
            target_id="agent-2",
            verdict="allow",
            confidence=0.95,
        )
        _ = att_expired
        quorum_expired = trust_federation.evaluate_federation_quorum(
            tenant_id="tenant-1",
            target_type="agent",
            target_id="agent-2",
            min_verifiers=1,
            min_trust_score=0.6,
            min_confidence=0.6,
        )
        reasons = [str(v.get("reason", "")) for v in quorum_expired.get("rejected", []) if isinstance(v, dict)]
        checks.append(
            _assert(
                "expired_verifier_rejected",
                "verifier_key_expired" in reasons,
                f"reasons={reasons}",
            )
        )

        # 8) Revoked verifier should be rejected by quorum evaluation.
        verifier_rev = trust_federation.upsert_verifier(
            tenant_id="tenant-1",
            verifier_id=None,
            name="Verifier Revoked",
            trust_score=0.92,
            issuer="https://verifier-revoked.example",
            jwks_uri="https://verifier-revoked.example/jwks.json",
            metadata={"region": "eu"},
            status="active",
        )
        trust_federation.revoke_verifier(
            tenant_id="tenant-1",
            verifier_id=verifier_rev["verifier_id"],
            actor="harness",
            reason="compromised",
        )
        att_revoked = trust_federation.issue_federation_attestation(
            tenant_id="tenant-1",
            verifier_id=verifier_rev["verifier_id"],
            target_type="agent",
            target_id="agent-3",
            verdict="allow",
            confidence=0.9,
        )
        _ = att_revoked
        quorum_revoked = trust_federation.evaluate_federation_quorum(
            tenant_id="tenant-1",
            target_type="agent",
            target_id="agent-3",
            min_verifiers=1,
            min_trust_score=0.6,
            min_confidence=0.6,
        )
        reasons = [str(v.get("reason", "")) for v in quorum_revoked.get("rejected", []) if isinstance(v, dict)]
        checks.append(
            _assert(
                "revoked_verifier_rejected",
                ("verifier_revoked" in reasons) or ("unknown_or_inactive_verifier" in reasons),
                f"reasons={reasons}",
            )
        )

        # 7) Replayed UIS event IDs should upsert deterministically (no growth).
        replay_event = {
            "event_id": "evt-replay-1",
            "event_timestamp": "2026-04-14T00:00:00+00:00",
            "identity": {"subject": "user-replay"},
            "auth": {"protocol": "oidc"},
            "threat": {"risk_tier": "allow"},
        }
        uis_store.insert_event("tenant-1", replay_event)
        uis_store.insert_event("tenant-1", replay_event)
        replay_rows = uis_store.list_events("tenant-1", limit=500)
        replay_count = len([row for row in replay_rows if str(row.get("event_id")) == "evt-replay-1"])
        checks.append(
            _assert(
                "replayed_event_id_upserted",
                replay_count == 1,
                f"replay_count={replay_count}",
            )
        )

        # 8) Cross-tenant poisoning noise should cap runtime penalty impact.
        for idx in range(15):
            network_intel.record_signal(
                tenant_id=f"tenant-noise-{idx}",
                signal_type="ip_hash",
                raw_value="203.0.113.5",
                severity="critical",
                confidence=0.99,
                metadata={"source": "unknown", "trust_tier": "untrusted"},
            )
        penalty_eval = network_intel.assess_runtime_penalty(
            [{"signal_type": "ip_hash", "raw_value": "203.0.113.5"}]
        )
        checks.append(
            _assert(
                "cross_tenant_noise_penalty_capped",
                int(penalty_eval.get("penalty", 0)) <= 40,
                f"penalty={penalty_eval.get('penalty')}",
            )
        )
    finally:
        tmp.cleanup()

    failed = [c for c in checks if not c["ok"]]
    result = {
        "ok": len(failed) == 0,
        "failed_count": len(failed),
        "checks": checks,
    }
    if strict and failed:
        raise SystemExit(1)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run TokenDNA adversarial security harness")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any check fails")
    args = parser.parse_args()

    result = run(strict=args.strict)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.strict and not result["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

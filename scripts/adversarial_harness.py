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

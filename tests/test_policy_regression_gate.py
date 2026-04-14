from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import decision_audit
from scripts import policy_regression_gate


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-policy-regression-gate-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["ATTESTATION_CA_SECRET"] = "policy-regression-secret"
    return tmpdir


def _record_sample(idx: int, *, action: str = "allow") -> None:
    decision_audit.record_decision(
        tenant_id="tenant-1",
        request_id=f"req-{idx}",
        source_endpoint="/secure",
        actor_subject="user-1",
        evaluation_input={
            "uis_event": {"threat": {"risk_score": 90, "risk_tier": "allow"}},
            "attestation": {
                "attestation_id": f"att-{idx}",
                "what": {
                    "soul_hash": "soul-1",
                    "model_fingerprint": "model-1",
                    "mcp_manifest_hash": "mcp-1",
                },
                "how": {"dpop_bound": False, "mtls_bound": False},
                "why": {"scope": ["orders:read"], "delegation_chain": ["svc-a"]},
            },
            "certificate": None,
            "certificate_id": "",
            "request_headers": {
                "x-agent-soul-hash": "soul-1",
                "x-agent-model-fingerprint": "model-1",
                "x-agent-mcp-manifest-hash": "mcp-1",
                "x-agent-delegation-chain": "svc-a",
            },
            "observed_scope": ["orders:read"],
            "required_scope": [],
        },
        enforcement_result={
            "decision": {
                "action": action,
                "reasons": ["policy_allow"] if action == "allow" else ["elevated_identity_risk"],
                "policy_trace": {"checks": {"risk": {"score": 90, "tier": "allow"}}},
            },
            "authn_failure": False,
            "certificate_status": None,
            "drift": {"score": 0.0, "severity": "none", "reasons": []},
            "timing": {"elapsed_ms": 1.0, "slo_target_ms": 5.0, "slo_met": True},
        },
    )


def test_policy_regression_gate_detects_action_delta():
    tmp = _setup_tmp_db()
    try:
        decision_audit.init_db()
        for i in range(12):
            _record_sample(i, action="allow")

        report = policy_regression_gate.run(
            tenant_id="tenant-1",
            candidate_config={"required_scope": ["orders:write"]},
            sample_size=12,
            max_action_delta_pct=20.0,
            min_samples=10,
        )
        assert report["ok"] is False
        assert report["changed_count"] > 0
        assert report["action_delta_pct"] > 20.0
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()


def test_policy_regression_gate_passes_when_delta_within_threshold():
    tmp = _setup_tmp_db()
    try:
        decision_audit.init_db()
        for i in range(12):
            _record_sample(i, action="allow")

        report = policy_regression_gate.run(
            tenant_id="tenant-1",
            candidate_config={},
            sample_size=12,
            max_action_delta_pct=1.0,
            min_samples=10,
        )
        assert report["ok"] is True
        assert report["changed_count"] == 0
        assert report["action_delta_pct"] == 0.0
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()

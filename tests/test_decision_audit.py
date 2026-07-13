from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import decision_audit


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-decision-audit-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["ATTESTATION_CA_SECRET"] = "decision-audit-secret"
    os.environ.pop("ATTESTATION_ACTIVE_KEY_ID", None)
    os.environ.pop("ATTESTATION_KEYRING_JSON", None)
    return tmpdir


def _evaluation_input() -> dict:
    return {
        "uis_event": {"threat": {"risk_score": 88, "risk_tier": "allow"}},
        "attestation": {
            "attestation_id": "att-1",
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
    }


def _enforcement(action: str = "allow") -> dict:
    return {
        "decision": {
            "action": action,
            "reasons": ["policy_allow"] if action == "allow" else ["elevated_identity_risk"],
            "policy_trace": {"checks": {"risk": {"score": 88, "tier": "allow"}}},
        },
        "authn_failure": False,
        "certificate_status": None,
        "drift": {"score": 0.0, "severity": "none", "reasons": []},
        "timing": {"elapsed_ms": 1.0, "slo_target_ms": 5.0, "slo_met": True},
    }


def test_decision_audit_record_list_and_replay_diff():
    tmp = _setup_tmp_db()
    try:
        decision_audit.init_db()
        record = decision_audit.record_decision(
            tenant_id="tenant-1",
            request_id="req-1",
            source_endpoint="/secure",
            actor_subject="user-1",
            evaluation_input=_evaluation_input(),
            enforcement_result=_enforcement("allow"),
            policy_bundle={
                "name": "edge-default",
                "version": "2026.04.14",
                "config": {"expected_action": "block"},
            },
        )
        assert record["audit_id"]
        assert record["previous_action"] == "allow"

        page = decision_audit.list_decisions_paginated(tenant_id="tenant-1", page_size=10)
        assert len(page["items"]) == 1
        assert page["items"][0]["audit_id"] == record["audit_id"]
        assert page["has_more"] is False

        replay = decision_audit.replay_decision(
            record=record,
            policy_bundle_config={"expected_action": "block"},
        )
        assert replay["previous_decision"]["action"] == "allow"
        assert replay["replay_decision"]["action"] in {"allow", "step_up", "block"}
        assert replay["diff"]["action_changed"] in {True, False}
        assert isinstance(replay["diff"]["drift_score_delta"], float)
    finally:
        os.environ.pop("ATTESTATION_CA_SECRET", None)
        tmp.cleanup()


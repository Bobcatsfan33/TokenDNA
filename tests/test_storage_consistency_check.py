from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.identity import attestation_store, decision_audit, uis_store
from scripts import storage_consistency_check


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-consistency-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ.pop("TOKENDNA_PG_DSN", None)
    os.environ.pop("TOKENDNA_DB_BACKEND", None)
    os.environ.pop("TOKENDNA_DB_DUAL_WRITE", None)
    return tmpdir


def test_storage_consistency_check_runs_without_postgres():
    tmp = _setup_tmp_db()
    try:
        uis_store.init_db()
        attestation_store.init_db()
        decision_audit.init_db()

        uis_store.insert_event(
            "tenant-1",
            {
                "event_id": "evt-1",
                "event_timestamp": "2026-04-15T00:00:00+00:00",
                "identity": {"subject": "user-1"},
                "auth": {"protocol": "oidc"},
                "threat": {"risk_tier": "allow"},
            },
        )
        attestation_store.insert_attestation(
            "tenant-1",
            {
                "attestation_id": "att-1",
                "created_at": "2026-04-15T00:00:01+00:00",
                "who": {"agent_id": "agent-1"},
                "what": {},
                "how": {},
                "why": {},
                "integrity_digest": "d1",
                "agent_dna_fingerprint": "fp-1",
            },
        )
        decision_audit.record_decision(
            tenant_id="tenant-1",
            request_id="req-1",
            source_endpoint="/secure",
            actor_subject="user-1",
            evaluation_input={
                "uis_event": {"threat": {"risk_score": 90, "risk_tier": "allow"}},
                "attestation": None,
                "certificate": None,
                "certificate_id": "",
                "request_headers": {},
                "observed_scope": [],
                "required_scope": [],
            },
            enforcement_result={
                "decision": {"action": "allow", "reasons": ["policy_allow"], "policy_trace": {}},
                "authn_failure": False,
                "certificate_status": None,
                "drift": {"score": 0.0, "severity": "none", "reasons": []},
                "timing": {"elapsed_ms": 1.0, "slo_target_ms": 5.0, "slo_met": True},
            },
        )

        report = storage_consistency_check.run("tenant-1")
        assert report["tenant_id"] == "tenant-1"
        assert report["sqlite"]["uis_events"] == 1
        assert report["sqlite"]["attestations"] == 1
        assert report["sqlite"]["decision_audits"] == 1
        # Without postgres configured, checker reports sentinel values and stays informational.
        assert report["postgres"]["uis_events"] == -1
    finally:
        tmp.cleanup()

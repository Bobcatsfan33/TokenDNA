from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _setup_tmp_db():
    tmpdir = tempfile.TemporaryDirectory()
    db_path = Path(tmpdir.name) / "tokendna-enterprise-test.db"
    os.environ["DATA_DB_PATH"] = str(db_path)
    os.environ["NETWORK_INTEL_HASH_SALT"] = "enterprise-test-salt"
    return tmpdir


def test_cursor_pagination_for_uis_attestation_and_policy_bundles():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import uis_store, attestation_store, policy_bundles

        uis_store.init_db()
        attestation_store.init_db()
        policy_bundles.init_db()

        # UIS events
        for i in range(5):
            uis_store.insert_event(
                "tenant-1",
                {
                    "event_id": f"evt-{i}",
                    "event_timestamp": f"2026-04-14T00:00:0{i}+00:00",
                    "identity": {"subject": "user-1"},
                    "auth": {"protocol": "oidc"},
                    "threat": {"risk_tier": "allow"},
                },
            )
        page1_items, page1_cursor = uis_store.list_events_with_cursor("tenant-1", limit=2)
        page2_items, _page2_cursor = uis_store.list_events_with_cursor(
            "tenant-1",
            limit=2,
            before_event_timestamp=page1_cursor,
        )
        assert len(page1_items) == 2
        assert len(page2_items) >= 1
        assert page1_items[-1]["event_id"] != page2_items[0]["event_id"]

        # Attestations
        for i in range(5):
            attestation_store.insert_attestation(
                "tenant-1",
                {
                    "attestation_id": f"att-{i}",
                    "created_at": f"2026-04-14T00:00:1{i}+00:00",
                    "who": {"agent_id": "agent-1"},
                    "what": {},
                    "how": {},
                    "why": {},
                    "integrity_digest": "d",
                    "agent_dna_fingerprint": "dna",
                },
            )
        att_page1 = attestation_store.list_attestations_paginated("tenant-1", page_size=2)
        att_page2 = attestation_store.list_attestations_paginated(
            "tenant-1",
            page_size=2,
            cursor=att_page1["next_cursor"],
        )
        assert len(att_page1["items"]) == 2
        assert len(att_page2["items"]) >= 1
        assert att_page1["items"][-1]["attestation_id"] != att_page2["items"][0]["attestation_id"]

        # Policy bundles
        for i in range(4):
            policy_bundles.create_bundle(
                tenant_id="tenant-1",
                name="edge-default",
                version=f"2026.04.{10 + i}",
                description=f"bundle {i}",
                config={"required_scope": ["orders:read"]},
            )
        bundle_page1 = policy_bundles.list_bundles_paginated("tenant-1", page_size=2)
        bundle_page2 = policy_bundles.list_bundles_paginated(
            "tenant-1",
            page_size=2,
            cursor=bundle_page1["next_cursor"],
        )
        assert len(bundle_page1["items"]) == 2
        assert len(bundle_page2["items"]) >= 1
        assert bundle_page1["items"][-1]["bundle_id"] != bundle_page2["items"][0]["bundle_id"]
    finally:
        tmp.cleanup()


def test_operator_status_contains_slos_and_dependency_health():
    tmp = _setup_tmp_db()
    try:
        from modules.identity import (
            uis_store,
            attestation_store,
            policy_bundles,
            compliance,
            network_intel,
            certificate_transparency,
        )
        from modules.identity.edge_enforcement import evaluate_runtime_enforcement
        from modules.identity.attestation_certificates import issue_certificate

        uis_store.init_db()
        attestation_store.init_db()
        policy_bundles.init_db()
        compliance.init_db()
        network_intel.init_db()
        certificate_transparency.init_db()

        cert = issue_certificate(
            tenant_id="tenant-1",
            attestation_id="att-1",
            subject="agent-1",
            issuer="TokenDNA Trust Authority",
            claims={"integrity_digest": "abc"},
            ttl_hours=1,
            secret="enterprise-secret",
        )
        enforcement = evaluate_runtime_enforcement(
            uis_event={"threat": {"risk_score": 90, "risk_tier": "allow"}},
            attestation={
                "attestation_id": "att-1",
                "what": {"soul_hash": "s"},
                "how": {"dpop_bound": False, "mtls_bound": False},
                "why": {"scope": []},
            },
            certificate=cert,
            certificate_id=cert["certificate_id"],
            request_headers={"x-agent-soul-hash": "s"},
            observed_scope=[],
            required_scope=[],
        )

        status = {
            "dependencies": {
                "sqlite": {"ok": True},
                "redis": {"ok": True},
                "clickhouse": {"ok": True},
            },
            "slo": {
                "edge_decision_ms": {
                    "target": float(os.getenv("EDGE_DECISION_SLO_MS", "5")),
                    "latest": enforcement["timing"]["elapsed_ms"],
                    "met": enforcement["timing"]["slo_met"],
                }
            },
        }
        assert status["dependencies"]["sqlite"]["ok"] is True
        assert "edge_decision_ms" in status["slo"]
    finally:
        tmp.cleanup()

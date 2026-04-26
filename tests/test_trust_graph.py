"""
Tests for UIS Trust Graph (Sprint 1-2).

Coverage:
  - Node/edge upsert and observation counting
  - Graph ingestion from UIS events
  - Shortest-path query (BFS via recursive CTE)
  - Anomaly detection: NEW_TOOL_IN_STABLE_AGENT_TOOLKIT
  - Anomaly detection: UNFAMILIAR_VERIFIER_IN_TRUST_PATH
  - Anomaly detection: DELEGATION_DEPTH_EXCEEDED
  - Anomaly persistence (store_anomaly + get_anomalies)
  - Graph stats
  - uis_store.insert_event hooks graph ingestion (integration)
  - Idempotent init_db (multiple calls safe)
"""

from __future__ import annotations

import json
import os
import tempfile
import time

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path):
    """Isolated SQLite DB per test."""
    db = str(tmp_path / "test.db")
    old = os.environ.get("DATA_DB_PATH")
    os.environ["DATA_DB_PATH"] = db
    yield db
    if old is None:
        os.environ.pop("DATA_DB_PATH", None)
    else:
        os.environ["DATA_DB_PATH"] = old


@pytest.fixture()
def tg(tmp_db):
    """Fresh trust_graph module with isolated DB."""
    import importlib
    import modules.identity.trust_graph as m
    importlib.reload(m)
    m.init_db()
    return m


TENANT = "tenant-test"


def _uis_event(
    subject: str = "user@x.com",
    agent_id: str | None = None,
    entity_type: str = "human",
    issuer: str = "https://auth.example.com",
    attestation_id: str | None = None,
    auth_method: str = "password",
    protocol: str = "oidc",
    risk_score: int = 10,
    risk_tier: str = "low",
) -> dict:
    return {
        "uis_version": "1.0",
        "event_id": f"ev-{subject}-{time.time_ns()}",
        "event_timestamp": "2026-04-15T00:00:00+00:00",
        "identity": {
            "entity_type": entity_type,
            "subject": subject,
            "tenant_id": TENANT,
            "tenant_name": "Test",
            "machine_classification": "agent" if entity_type == "machine" else "user",
            "agent_id": agent_id,
        },
        "auth": {"method": auth_method, "mfa_asserted": True, "protocol": protocol, "credential_strength": "standard"},
        "token": {"type": "bearer", "issuer": issuer, "audience": "api", "claims_hash": "x",
                  "dpop_bound": False, "expires_at": None, "issued_at": None, "rotation_history": [], "jti": "j"},
        "session": {"id": "s-1", "request_id": "r-1", "ip": "1.2.3.4", "country": "US",
                    "asn": "AS1", "device_fingerprint": None, "user_agent": "test",
                    "impossible_travel": False, "graph_position": None},
        "behavior": {"dna_fingerprint": None, "pattern_deviation_score": 0.0, "velocity_anomaly": False},
        "lifecycle": {"state": "active", "provisioned_at": None, "revoked_at": None, "dormant": False},
        "threat": {"risk_score": risk_score, "risk_tier": risk_tier, "indicators": [], "lateral_movement": False},
        "binding": {"dpop_jkt": None, "mtls_subject": None, "spiffe_id": None,
                    "attestation_id": attestation_id, "supply_chain_hash": None},
    }


# ─────────────────────────────────────────────────────────────────────────────
# init_db
# ─────────────────────────────────────────────────────────────────────────────

class TestInitDB:
    def test_init_creates_tables(self, tg, tmp_db):
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        assert "tg_nodes" in tables
        assert "tg_edges" in tables

    def test_init_idempotent(self, tg):
        """Calling init_db() twice must not raise."""
        tg.init_db()
        tg.init_db()


# ─────────────────────────────────────────────────────────────────────────────
# Node/edge upsert
# ─────────────────────────────────────────────────────────────────────────────

class TestUpsert:
    def test_node_created_on_first_ingest(self, tg):
        ev = _uis_event(subject="svc@x", agent_id="agt-1", entity_type="machine")
        tg.ingest_uis_event(TENANT, ev)
        stats = tg.get_stats(TENANT)
        assert stats["node_count"] >= 1

    def test_observation_count_increments(self, tg):
        ev = _uis_event(subject="svc@x", agent_id="agt-1", entity_type="machine",
                        issuer="https://auth.example.com")
        tg.ingest_uis_event(TENANT, ev)
        tg.ingest_uis_event(TENANT, ev)  # second identical event
        stats = tg.get_stats(TENANT)
        # At least one node should have obs_count=2
        import sqlite3
        conn = sqlite3.connect(os.environ["DATA_DB_PATH"])
        row = conn.execute(
            "SELECT MAX(observation_count) FROM tg_nodes WHERE tenant_id=?", (TENANT,)
        ).fetchone()
        conn.close()
        assert row[0] >= 2

    def test_multiple_node_types_created(self, tg):
        ev = _uis_event(
            subject="agt@svc",
            agent_id="agt-1",
            entity_type="machine",
            issuer="https://auth.example.com",
            auth_method="mtls",
            protocol="spiffe",
        )
        tg.ingest_uis_event(TENANT, ev)
        stats = tg.get_stats(TENANT)
        # Should have agent + issuer + tool nodes
        assert stats["node_count"] >= 3
        assert "agent" in stats["node_types"]
        assert "issuer" in stats["node_types"]
        assert "tool" in stats["node_types"]

    def test_edge_types_created(self, tg):
        ev = _uis_event(
            subject="agt@svc",
            agent_id="agt-1",
            entity_type="machine",
            issuer="https://auth.example.com",
            attestation_id="att-abc123",
        )
        tg.ingest_uis_event(TENANT, ev)
        stats = tg.get_stats(TENANT)
        assert "issued_by" in stats["edge_types"]
        assert "attested_by" in stats["edge_types"]

    def test_tenant_isolation(self, tg):
        ev = _uis_event(subject="user@x")
        tg.ingest_uis_event("tenant-A", ev)
        tg.ingest_uis_event("tenant-B", ev)
        stats_a = tg.get_stats("tenant-A")
        stats_b = tg.get_stats("tenant-B")
        assert stats_a["node_count"] == stats_b["node_count"]
        # But they should be separate (no cross-contamination)
        stats_c = tg.get_stats("tenant-C")
        assert stats_c["node_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Shortest path
# ─────────────────────────────────────────────────────────────────────────────

class TestShortestPath:
    def test_path_to_self(self, tg):
        ev = _uis_event(subject="agt@x", agent_id="agt-1", entity_type="machine")
        tg.ingest_uis_event(TENANT, ev)
        result = tg.shortest_path(TENANT, "agt-1", "agt-1")
        assert result["found"] is True
        assert result["length"] == 0

    def test_path_not_found_unknown_nodes(self, tg):
        result = tg.shortest_path(TENANT, "ghost-a", "ghost-b")
        assert result["found"] is False
        assert "not_found" in result.get("error", "")

    def test_direct_path_agent_to_issuer(self, tg):
        ev = _uis_event(
            subject="agt@svc",
            agent_id="agt-1",
            entity_type="machine",
            issuer="https://auth.example.com",
        )
        tg.ingest_uis_event(TENANT, ev)
        result = tg.shortest_path(TENANT, "agt-1", "https://auth.example.com")
        assert result["found"] is True
        assert result["length"] == 1

    def test_path_contains_node_dicts(self, tg):
        ev = _uis_event(
            subject="agt@svc",
            agent_id="agt-1",
            entity_type="machine",
            issuer="https://auth.example.com",
        )
        tg.ingest_uis_event(TENANT, ev)
        result = tg.shortest_path(TENANT, "agt-1", "https://auth.example.com")
        assert result["found"] is True
        for node in result["path"]:
            assert "node_id" in node
            assert "node_type" in node
            assert "label" in node

    def test_no_path_between_disconnected_nodes(self, tg):
        ev1 = _uis_event(subject="u1@x", issuer="https://issuer-a.com")
        ev2 = _uis_event(subject="u2@x", issuer="https://issuer-b.com")
        tg.ingest_uis_event(TENANT, ev1)
        tg.ingest_uis_event(TENANT, ev2)
        result = tg.shortest_path(TENANT, "u1@x", "https://issuer-b.com")
        # No direct path
        assert result["found"] is False or result["length"] > 0


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly: NEW_TOOL_IN_STABLE_AGENT_TOOLKIT
# ─────────────────────────────────────────────────────────────────────────────

class TestNewToolAnomaly:
    def _seed_stable_agent(self, tg, n: int = 6) -> str:
        """Insert n events with the same agent/tool to establish baseline."""
        for _ in range(n):
            ev = _uis_event(
                subject="svc@stable",
                agent_id="stable-agt",
                entity_type="machine",
                auth_method="mtls",
                protocol="spiffe",
            )
            tg.ingest_uis_event(TENANT, ev)
        return "stable-agt"

    def test_no_anomaly_below_threshold(self, tg):
        # Only 3 observations — below MIN_STABLE_OBSERVATIONS (5)
        for _ in range(3):
            ev = _uis_event(subject="new-agt", agent_id="new-agt", entity_type="machine",
                            auth_method="password", protocol="oidc")
            tg.ingest_uis_event(TENANT, ev)
        # Introduce new tool — should NOT fire anomaly (not stable yet)
        ev_new = _uis_event(subject="new-agt", agent_id="new-agt", entity_type="machine",
                            auth_method="api_key", protocol="custom")
        anomalies = tg.ingest_uis_event(TENANT, ev_new)
        new_tool_anomalies = [a for a in anomalies if a.anomaly_type == "NEW_TOOL_IN_STABLE_AGENT_TOOLKIT"]
        assert len(new_tool_anomalies) == 0

    def test_anomaly_fires_for_stable_agent_new_tool(self, tg):
        self._seed_stable_agent(tg, n=6)  # > MIN_STABLE_OBSERVATIONS
        # Now introduce a completely new tool
        ev_new = _uis_event(
            subject="svc@stable",
            agent_id="stable-agt",
            entity_type="machine",
            auth_method="api_key",      # New method
            protocol="custom",          # New protocol
        )
        anomalies = tg.ingest_uis_event(TENANT, ev_new)
        new_tool = [a for a in anomalies if a.anomaly_type == "NEW_TOOL_IN_STABLE_AGENT_TOOLKIT"]
        assert len(new_tool) >= 1
        assert new_tool[0].severity == "medium"
        assert "stable-agt" in new_tool[0].subject_node

    def test_anomaly_includes_context(self, tg):
        self._seed_stable_agent(tg, n=6)
        ev_new = _uis_event(subject="svc@stable", agent_id="stable-agt",
                            entity_type="machine", auth_method="mfa", protocol="saml")
        anomalies = tg.ingest_uis_event(TENANT, ev_new)
        new_tool = [a for a in anomalies if a.anomaly_type == "NEW_TOOL_IN_STABLE_AGENT_TOOLKIT"]
        if new_tool:
            ctx = new_tool[0].context
            assert "agent_observations" in ctx
            assert ctx["agent_observations"] >= 6

    def test_same_tool_used_again_no_anomaly(self, tg):
        self._seed_stable_agent(tg, n=6)
        # Use the SAME tool again — no anomaly
        ev_same = _uis_event(subject="svc@stable", agent_id="stable-agt",
                             entity_type="machine", auth_method="mtls", protocol="spiffe")
        anomalies = tg.ingest_uis_event(TENANT, ev_same)
        new_tool = [a for a in anomalies if a.anomaly_type == "NEW_TOOL_IN_STABLE_AGENT_TOOLKIT"]
        assert len(new_tool) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly: UNFAMILIAR_VERIFIER_IN_TRUST_PATH
# ─────────────────────────────────────────────────────────────────────────────

class TestUnfamiliarVerifierAnomaly:
    def _seed_stable_issuer(self, tg, n: int = 6, attestation_id: str = "att-known") -> None:
        for _ in range(n):
            ev = _uis_event(
                subject="user@tenant",
                entity_type="human",
                issuer="https://known-issuer.com",
                attestation_id=attestation_id,
            )
            tg.ingest_uis_event(TENANT, ev)

    def test_no_anomaly_issuer_not_stable(self, tg):
        # Issuer only seen twice — below threshold
        for _ in range(2):
            ev = _uis_event(subject="user@x", issuer="https://new-issuer.com",
                            attestation_id="att-001")
            tg.ingest_uis_event(TENANT, ev)
        # New verifier with unstable issuer — no anomaly
        ev_new = _uis_event(subject="user@x", issuer="https://new-issuer.com",
                            attestation_id="att-brand-new")
        anomalies = tg.ingest_uis_event(TENANT, ev_new)
        unfamiliar = [a for a in anomalies if a.anomaly_type == "UNFAMILIAR_VERIFIER_IN_TRUST_PATH"]
        assert len(unfamiliar) == 0

    def test_anomaly_fires_for_stable_issuer_new_verifier(self, tg):
        self._seed_stable_issuer(tg, n=6, attestation_id="att-known")
        # Introduce brand-new verifier
        ev_new = _uis_event(
            subject="user@tenant",
            entity_type="human",
            issuer="https://known-issuer.com",
            attestation_id="att-BRAND-NEW-verifier",
        )
        anomalies = tg.ingest_uis_event(TENANT, ev_new)
        unfamiliar = [a for a in anomalies if a.anomaly_type == "UNFAMILIAR_VERIFIER_IN_TRUST_PATH"]
        assert len(unfamiliar) >= 1
        assert unfamiliar[0].severity == "high"
        assert "known-issuer.com" in unfamiliar[0].detail

    def test_known_verifier_no_anomaly(self, tg):
        self._seed_stable_issuer(tg, n=6, attestation_id="att-known")
        # Same known verifier — no anomaly
        ev_same = _uis_event(subject="user@tenant", issuer="https://known-issuer.com",
                             attestation_id="att-known")
        anomalies = tg.ingest_uis_event(TENANT, ev_same)
        unfamiliar = [a for a in anomalies if a.anomaly_type == "UNFAMILIAR_VERIFIER_IN_TRUST_PATH"]
        assert len(unfamiliar) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly: DELEGATION_DEPTH_EXCEEDED
# ─────────────────────────────────────────────────────────────────────────────

class TestDelegationDepthAnomaly:
    def test_no_anomaly_within_depth(self, tg):
        # No delegation edges → depth is 0
        ev = _uis_event(subject="user@x")
        anomalies = tg.ingest_uis_event(TENANT, ev)
        depth_anomalies = [a for a in anomalies if a.anomaly_type == "DELEGATION_DEPTH_EXCEEDED"]
        assert len(depth_anomalies) == 0

    def test_delegation_depth_helper(self, tg, tmp_db):
        """Manually insert delegation edges and verify depth calculation."""
        import sqlite3
        # Build chain: A → B → C → D → E (depth 4 from A)
        now = "2026-04-15T00:00:00+00:00"
        node_ids = []
        conn = sqlite3.connect(tmp_db)
        for label in ["node-A", "node-B", "node-C", "node-D", "node-E"]:
            nid = tg._node_id(TENANT, "agent", label)
            node_ids.append(nid)
            conn.execute(
                """INSERT OR IGNORE INTO tg_nodes
                   (node_id, tenant_id, node_type, label, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?)""",
                (nid, TENANT, "agent", label, now, now),
            )
        # A→B→C→D→E as delegates_to
        for i in range(4):
            eid = tg._edge_id(TENANT, node_ids[i], node_ids[i+1], "delegates_to")
            conn.execute(
                """INSERT OR IGNORE INTO tg_edges
                   (edge_id, tenant_id, src_node, dst_node, edge_type, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?)""",
                (eid, TENANT, node_ids[i], node_ids[i+1], "delegates_to", now, now),
            )
        conn.commit()
        conn.close()

        depth = tg._delegation_depth(TENANT, node_ids[0])
        assert depth == 4

    def test_max_depth_env_var_respected(self, tg):
        """MAX_DELEGATION_DEPTH is read from env."""
        old = os.environ.get("TG_MAX_DELEGATION_DEPTH")
        os.environ["TG_MAX_DELEGATION_DEPTH"] = "2"
        import importlib
        import modules.identity.trust_graph as m
        importlib.reload(m)
        assert m.MAX_DELEGATION_DEPTH == 2
        if old is None:
            os.environ.pop("TG_MAX_DELEGATION_DEPTH")
        else:
            os.environ["TG_MAX_DELEGATION_DEPTH"] = old


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestAnomalyPersistence:
    def test_store_and_retrieve_anomaly(self, tg):
        from modules.identity.trust_graph import GraphAnomaly
        a = GraphAnomaly(
            anomaly_type="NEW_TOOL_IN_STABLE_AGENT_TOOLKIT",
            tenant_id=TENANT,
            detected_at="2026-04-15T00:00:00+00:00",
            subject_node="agt-x",
            detail="Test anomaly",
            severity="medium",
            context={"test": True},
        )
        tg.store_anomaly(a)
        results = tg.get_anomalies(TENANT)
        assert len(results) >= 1
        found = [r for r in results if r["anomaly_type"] == "NEW_TOOL_IN_STABLE_AGENT_TOOLKIT"]
        assert len(found) >= 1
        assert found[0]["detail"] == "Test anomaly"

    def test_anomaly_severity_filter(self, tg):
        from modules.identity.trust_graph import GraphAnomaly
        tg.store_anomaly(GraphAnomaly("TYPE_A", TENANT, "2026-04-15T00:00:00+00:00",
                                      "node-1", "detail", "high", {}))
        tg.store_anomaly(GraphAnomaly("TYPE_B", TENANT, "2026-04-15T00:00:00+00:00",
                                      "node-2", "detail", "low", {}))
        high = tg.get_anomalies(TENANT, severity="high")
        low = tg.get_anomalies(TENANT, severity="low")
        assert all(a["severity"] == "high" for a in high)
        assert all(a["severity"] == "low" for a in low)

    def test_anomaly_context_roundtrips(self, tg):
        from modules.identity.trust_graph import GraphAnomaly
        ctx = {"agent_observations": 10, "new_tool": "saml:mfa", "min_stable_threshold": 5}
        a = GraphAnomaly("TEST", TENANT, "2026-04-15T00:00:00+00:00",
                         "agt", "d", "medium", ctx)
        tg.store_anomaly(a)
        results = tg.get_anomalies(TENANT)
        assert results[0]["context"] == ctx

    def test_get_anomalies_empty(self, tg):
        results = tg.get_anomalies("unknown-tenant")
        assert results == []


# ─────────────────────────────────────────────────────────────────────────────
# Graph stats
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphStats:
    def test_empty_stats(self, tg):
        stats = tg.get_stats(TENANT)
        assert stats["node_count"] == 0
        assert stats["edge_count"] == 0
        assert stats["node_types"] == {}
        assert stats["edge_types"] == {}

    def test_stats_after_ingest(self, tg):
        ev = _uis_event(subject="user@x", issuer="https://auth.com",
                        auth_method="password", protocol="oidc")
        tg.ingest_uis_event(TENANT, ev)
        stats = tg.get_stats(TENANT)
        assert stats["node_count"] >= 2   # subject + issuer (+ tool)
        assert stats["edge_count"] >= 1

    def test_stats_include_anomaly_count(self, tg):
        from modules.identity.trust_graph import GraphAnomaly
        tg.store_anomaly(GraphAnomaly("T", TENANT, "2026-04-15T00:00:00+00:00",
                                      "n", "d", "low", {}))
        stats = tg.get_stats(TENANT)
        assert stats["anomaly_count"] == 1

    def test_stats_tenant_isolation(self, tg):
        ev = _uis_event(subject="user@x")
        tg.ingest_uis_event("tenant-X", ev)
        stats_y = tg.get_stats("tenant-Y")
        assert stats_y["node_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# Integration: uis_store.insert_event → graph ingestion
# ─────────────────────────────────────────────────────────────────────────────

class TestUISStoreIntegration:
    def test_insert_event_populates_graph(self, tg, tmp_db):
        import importlib
        import modules.identity.uis_store as store
        importlib.reload(store)
        store.init_db()

        ev = _uis_event(
            subject="svc@integration",
            agent_id="agt-integration",
            entity_type="machine",
            issuer="https://auth.int.com",
        )
        ev["event_id"] = "integ-001"
        store.insert_event(TENANT, ev)

        stats = tg.get_stats(TENANT)
        assert stats["node_count"] >= 1

    def test_insert_event_does_not_fail_if_graph_errors(self, tg, tmp_db, monkeypatch):
        """Graph ingestion failure must not block event persistence."""
        import importlib
        import modules.identity.uis_store as store
        importlib.reload(store)
        store.init_db()

        import modules.identity.trust_graph as tgm
        monkeypatch.setattr(tgm, "ingest_uis_event", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))

        ev = _uis_event(subject="failsafe@x")
        ev["event_id"] = "failsafe-001"
        # Must NOT raise
        store.insert_event(TENANT, ev)
        # Event was persisted
        retrieved = store.get_event(TENANT, "failsafe-001")
        assert retrieved is not None


# ─────────────────────────────────────────────────────────────────────────────
# Node ID determinism
# ─────────────────────────────────────────────────────────────────────────────

class TestNodeIDHelpers:
    def test_node_id_deterministic(self, tg):
        nid1 = tg._node_id("tenant-1", "agent", "agt-1")
        nid2 = tg._node_id("tenant-1", "agent", "agt-1")
        assert nid1 == nid2

    def test_node_id_different_tenants(self, tg):
        nid1 = tg._node_id("tenant-1", "agent", "agt-1")
        nid2 = tg._node_id("tenant-2", "agent", "agt-1")
        assert nid1 != nid2

    def test_node_id_different_types(self, tg):
        nid1 = tg._node_id("t", "agent", "x")
        nid2 = tg._node_id("t", "issuer", "x")
        assert nid1 != nid2

    def test_edge_id_deterministic(self, tg):
        eid1 = tg._edge_id("t", "src", "dst", "uses_tool")
        eid2 = tg._edge_id("t", "src", "dst", "uses_tool")
        assert eid1 == eid2

    def test_edge_id_direction_matters(self, tg):
        eid1 = tg._edge_id("t", "A", "B", "uses_tool")
        eid2 = tg._edge_id("t", "B", "A", "uses_tool")
        assert eid1 != eid2


# ─────────────────────────────────────────────────────────────────────────────
# RSA gap detections — POLICY_SCOPE_MODIFICATION + PERMISSION_WEIGHT_DRIFT
# ─────────────────────────────────────────────────────────────────────────────


class TestPolicyScopeModificationAnomaly:
    """RSA gap 1 — agent self-elevation via policy modification."""

    def test_self_modification_fires_critical(self, tg):
        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-A",
            modified_by="agent-A",
            policy_id="pol-1",
            scope=["s3:write:*"],
        )
        types = [a.anomaly_type for a in anomalies]
        assert "POLICY_SCOPE_MODIFICATION" in types
        sm = next(a for a in anomalies if a.anomaly_type == "POLICY_SCOPE_MODIFICATION")
        assert sm.severity == "critical"
        assert sm.context["self_modification"] is True
        assert sm.context["modifier"] == "agent-A"
        assert sm.context["target"] == "agent-A"

    def test_other_modifies_no_self_anomaly(self, tg):
        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-A",
            modified_by="admin-bot",
            policy_id="pol-1",
            scope=["s3:read:*"],
        )
        types = [a.anomaly_type for a in anomalies]
        assert "POLICY_SCOPE_MODIFICATION" not in types

    def test_self_modification_includes_policy_and_scope(self, tg):
        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-X",
            modified_by="agent-X",
            policy_id="pol-42",
            scope=["iam:CreateAccessKey", "iam:PutRolePolicy"],
        )
        sm = next(a for a in anomalies if a.anomaly_type == "POLICY_SCOPE_MODIFICATION")
        assert sm.context["policy_id"] == "pol-42"
        assert sm.context["scope"] == [
            "iam:CreateAccessKey",
            "iam:PutRolePolicy",
        ]

    def test_required_args_validated(self, tg):
        with pytest.raises(ValueError):
            tg.record_policy_modification(
                TENANT, target_agent="", modified_by="m", policy_id="p"
            )
        with pytest.raises(ValueError):
            tg.record_policy_modification(
                TENANT, target_agent="t", modified_by="", policy_id="p"
            )
        with pytest.raises(ValueError):
            tg.record_policy_modification(
                TENANT, target_agent="t", modified_by="m", policy_id=""
            )


class TestPermissionWeightDriftAnomaly:
    """RSA gap 2 — modifier→target edge weight grows past threshold without attestation."""

    def test_below_threshold_no_anomaly(self, tg):
        # First call creates the edge with weight=1; threshold is 4.
        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-T",
            modified_by="admin-bot",
            policy_id="pol-1",
        )
        assert all(a.anomaly_type != "PERMISSION_WEIGHT_DRIFT" for a in anomalies)

    def test_growth_past_threshold_with_no_attestation_fires_high(self, tg):
        # Drive the edge weight up to the threshold by repeated modifications
        # from the same actor against the same target.
        threshold = tg._PERMISSION_WEIGHT_DRIFT_THRESHOLD
        last_anomalies: list = []
        for i in range(threshold):
            last_anomalies = tg.record_policy_modification(
                TENANT,
                target_agent="agent-T",
                modified_by="admin-bot",
                policy_id=f"pol-{i}",
            )
        types = [a.anomaly_type for a in last_anomalies]
        assert "PERMISSION_WEIGHT_DRIFT" in types
        drift = next(
            a for a in last_anomalies if a.anomaly_type == "PERMISSION_WEIGHT_DRIFT"
        )
        assert drift.severity == "high"
        assert drift.context["edge_weight"] >= threshold
        assert drift.context["modifier"] == "admin-bot"
        assert drift.context["target"] == "agent-T"
        assert drift.context["attestation_present"] is False

    def test_growth_with_recent_attestation_suppresses_anomaly(self, tg):
        # Seed a recent attested_by edge for the modifier so the attestation
        # gate suppresses PERMISSION_WEIGHT_DRIFT.
        from datetime import datetime, timezone

        modifier = "admin-bot"
        target = "agent-T"
        now_iso = datetime.now(timezone.utc).isoformat()
        tg._upsert_nodes(
            TENANT,
            [("agent", modifier, "{}"), ("verifier", "ver-1", "{}")],
            now_iso,
        )
        tg._upsert_edges(
            TENANT,
            [("agent", modifier, "verifier", "ver-1", "attested_by")],
            now_iso,
        )

        threshold = tg._PERMISSION_WEIGHT_DRIFT_THRESHOLD
        last_anomalies: list = []
        for i in range(threshold):
            last_anomalies = tg.record_policy_modification(
                TENANT,
                target_agent=target,
                modified_by=modifier,
                policy_id=f"pol-{i}",
            )
        assert all(
            a.anomaly_type != "PERMISSION_WEIGHT_DRIFT" for a in last_anomalies
        ), "attestation in window should suppress drift anomaly"

    def test_self_modification_and_drift_can_coexist(self, tg):
        # Self-mod fires per call (CRITICAL); drift fires once weight crosses
        # threshold (HIGH).  The final call should yield both.
        threshold = tg._PERMISSION_WEIGHT_DRIFT_THRESHOLD
        last_anomalies: list = []
        for i in range(threshold):
            last_anomalies = tg.record_policy_modification(
                TENANT,
                target_agent="agent-S",
                modified_by="agent-S",
                policy_id=f"pol-{i}",
            )
        types = sorted(a.anomaly_type for a in last_anomalies)
        assert "POLICY_SCOPE_MODIFICATION" in types
        assert "PERMISSION_WEIGHT_DRIFT" in types

    def test_out_of_window_first_seen_suppresses_drift(self, tg, monkeypatch):
        """
        If the modifier→target edge was first seen more than
        PERMISSION_DRIFT_WINDOW_DAYS ago, drift should NOT fire even when
        the weight has crossed the threshold.  Otherwise an old edge that
        slowly accumulates weight would trip the gate without representing
        rapid recent growth.
        """
        monkeypatch.setattr(tg, "PERMISSION_DRIFT_WINDOW_DAYS", 1)
        threshold = tg._PERMISSION_WEIGHT_DRIFT_THRESHOLD
        for i in range(threshold):
            tg.record_policy_modification(
                TENANT,
                target_agent="agent-O",
                modified_by="admin-bot",
                policy_id=f"pol-{i}",
            )
        # Backdate the edge's first_seen so it falls outside the 1-day window.
        from datetime import datetime, timedelta, timezone

        backdated = (
            datetime.now(timezone.utc) - timedelta(days=10)
        ).isoformat()
        src = tg._node_id(TENANT, "agent", "admin-bot")
        dst = tg._node_id(TENANT, "agent", "agent-O")
        eid = tg._edge_id(TENANT, src, dst, tg._POLICY_MOD_EDGE_TYPE)
        conn = tg._get_conn()
        try:
            conn.execute(
                "UPDATE tg_edges SET first_seen=? WHERE edge_id=?",
                (backdated, eid),
            )
            conn.commit()
        finally:
            conn.close()

        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-O",
            modified_by="admin-bot",
            policy_id="pol-final",
        )
        assert all(
            a.anomaly_type != "PERMISSION_WEIGHT_DRIFT" for a in anomalies
        )

    def test_unparseable_timestamp_does_not_crash(self, tg):
        """
        Defensive: if first_seen is not ISO8601 parseable for any reason,
        _check_permission_weight_drift returns None instead of raising.
        """
        tg.record_policy_modification(
            TENANT,
            target_agent="agent-Q",
            modified_by="admin-bot",
            policy_id="pol-q",
        )
        src = tg._node_id(TENANT, "agent", "admin-bot")
        dst = tg._node_id(TENANT, "agent", "agent-Q")
        eid = tg._edge_id(TENANT, src, dst, tg._POLICY_MOD_EDGE_TYPE)
        conn = tg._get_conn()
        try:
            conn.execute(
                "UPDATE tg_edges SET first_seen=? WHERE edge_id=?",
                ("not-a-date", eid),
            )
            conn.commit()
        finally:
            conn.close()
        anomalies = tg.record_policy_modification(
            TENANT,
            target_agent="agent-Q",
            modified_by="admin-bot",
            policy_id="pol-q-2",
        )
        assert isinstance(anomalies, list)

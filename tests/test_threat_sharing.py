"""
Tests for modules/product/threat_sharing.py — cross-tenant threat-intel network.

Coverage:
  - Anonymization strips tenant_id / agent_id / user_id / IP from every
    nesting level and replaces with stable per-playbook placeholders.
  - Detection logic (category, mitre_technique, pivot, objective,
    min_confidence, risk_tier) is preserved verbatim.
  - Opt-in / opt-out / status counters round-trip and stay idempotent.
  - publish() rejects non-owned, missing, and built-in playbooks.
  - publish() is idempotent on repeat publication.
  - propagate_to_tenant() is idempotent.
  - sync() is a no-op for opted-out tenants.
  - sync() is idempotent across repeat calls.
  - End-to-end gate: a playbook published by Tenant A appears in Tenant B's
    intent_correlation.get_playbooks() with source="network" and zero
    Tenant A identifiers in the propagated copy.
  - Route-level: /opt-in, /publish, /sync, /network, /status all behave
    correctly through the FastAPI TestClient with dependency_overrides.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path, monkeypatch):
    """Isolated SQLite DB per test."""
    db = str(tmp_path / "ts.db")
    monkeypatch.setenv("DATA_DB_PATH", db)
    yield db


@pytest.fixture()
def ts(tmp_db):
    """Reload threat_sharing + intent_correlation against a fresh DB."""
    import importlib

    import modules.identity.intent_correlation as ic
    import modules.product.threat_sharing as t

    importlib.reload(ic)
    importlib.reload(t)
    t.init_db()
    return t


@pytest.fixture()
def ic(ts):
    import modules.identity.intent_correlation as ic_mod
    return ic_mod


TENANT_A = "tenant-acme"
TENANT_B = "tenant-globex"


def _seed_custom_playbook(ic_mod, tenant: str, name: str = "Acme Custom") -> str:
    return ic_mod.add_playbook(
        tenant_id=tenant,
        name=name,
        description="Tenant-specific exploit signature",
        severity="high",
        steps=[
            {"category": "auth_anomaly", "min_confidence": 0.5,
             "agent_id": "agt-prod-001", "source_ip": "10.1.2.3"},
            {"category": "privilege_escalation", "min_confidence": 0.6,
             "user_id": "alice@acme.com"},
        ],
        window_seconds=1800,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Anonymization
# ─────────────────────────────────────────────────────────────────────────────

class TestAnonymize:
    def test_strips_tenant_agent_user_ip_fields(self, ts):
        pb = {
            "name": "Test",
            "description": "from 10.0.0.5",
            "severity": "high",
            "steps": [
                {"category": "auth_anomaly", "agent_id": "agt-secret",
                 "user_id": "bob@x.com", "source_ip": "192.168.1.1",
                 "min_confidence": 0.5},
            ],
            "window_seconds": 900,
        }
        out = ts.anonymize_playbook(pb)
        flat = repr(out)
        for forbidden in ("agt-secret", "bob@x.com", "192.168.1.1", "10.0.0.5"):
            assert forbidden not in flat, f"{forbidden} leaked into {flat}"

    def test_preserves_detection_logic(self, ts):
        pb = {
            "name": "Logic",
            "description": "",
            "severity": "critical",
            "steps": [
                {"category": "credential_abuse",
                 "mitre_technique": "T1110.004",
                 "pivot": "context_switch",
                 "objective": "escalat",
                 "min_confidence": 0.62,
                 "risk_tier": "high",
                 "agent_id": "agt-1"},
            ],
            "window_seconds": 1800,
        }
        out = ts.anonymize_playbook(pb)
        step = out["steps"][0]
        assert step["category"] == "credential_abuse"
        assert step["mitre_technique"] == "T1110.004"
        assert step["pivot"] == "context_switch"
        assert step["objective"] == "escalat"
        assert step["min_confidence"] == 0.62
        assert step["risk_tier"] == "high"
        # agent_id was scrubbed.
        assert step["agent_id"].startswith("agent_")

    def test_drops_top_level_metadata(self, ts):
        pb = {
            "playbook_id": "custom:abc123",
            "tenant_id": "tenant-secret",
            "created_at": "2026-04-24T00:00:00Z",
            "updated_at": "2026-04-24T00:00:00Z",
            "builtin": 0,
            "enabled": 1,
            "name": "x",
            "description": "y",
            "severity": "high",
            "steps": [],
            "window_seconds": 1,
        }
        out = ts.anonymize_playbook(pb)
        for dropped in ("playbook_id", "tenant_id", "created_at",
                        "updated_at", "builtin", "enabled"):
            assert dropped not in out

    def test_stable_placeholders_per_playbook(self, ts):
        """The same agent_id appearing twice maps to the same label."""
        pb = {
            "name": "n", "description": "", "severity": "high",
            "steps": [
                {"category": "auth_anomaly", "agent_id": "agt-X", "min_confidence": 0.4},
                {"category": "auth_anomaly", "agent_id": "agt-X", "min_confidence": 0.4},
                {"category": "auth_anomaly", "agent_id": "agt-Y", "min_confidence": 0.4},
            ],
            "window_seconds": 60,
        }
        out = ts.anonymize_playbook(pb)
        a1 = out["steps"][0]["agent_id"]
        a2 = out["steps"][1]["agent_id"]
        a3 = out["steps"][2]["agent_id"]
        assert a1 == a2
        assert a3 != a1

    def test_input_not_mutated(self, ts):
        pb = {"name": "x", "description": "y", "severity": "high",
              "steps": [{"category": "auth_anomaly", "agent_id": "agt-1"}],
              "window_seconds": 60, "tenant_id": "tenant-secret"}
        before = repr(pb)
        ts.anonymize_playbook(pb)
        assert repr(pb) == before

    def test_inline_email_and_ip_in_description(self, ts):
        pb = {"name": "n",
              "description": "Caught alice@acme.com from 10.20.30.40",
              "severity": "high",
              "steps": [], "window_seconds": 60}
        out = ts.anonymize_playbook(pb)
        assert "alice@acme.com" not in out["description"]
        assert "10.20.30.40" not in out["description"]

    def test_rejects_non_dict(self, ts):
        with pytest.raises(TypeError):
            ts.anonymize_playbook(["not", "a", "dict"])


# ─────────────────────────────────────────────────────────────────────────────
# Opt-in registry
# ─────────────────────────────────────────────────────────────────────────────

class TestOptIn:
    def test_default_status_is_opted_out(self, ts):
        s = ts.get_status(TENANT_A)
        assert s["opted_in"] is False
        assert s["published_count"] == 0
        assert s["received_count"] == 0

    def test_opt_in_round_trip(self, ts):
        s = ts.opt_in(TENANT_A)
        assert s["opted_in"] is True
        assert s["opted_in_at"]
        assert ts.is_opted_in(TENANT_A)

    def test_opt_in_idempotent(self, ts):
        ts.opt_in(TENANT_A)
        ts.opt_in(TENANT_A)
        assert ts.is_opted_in(TENANT_A)

    def test_opt_out_clears_flag(self, ts):
        ts.opt_in(TENANT_A)
        s = ts.opt_out(TENANT_A)
        assert s["opted_in"] is False
        assert s["opted_out_at"]
        assert not ts.is_opted_in(TENANT_A)


# ─────────────────────────────────────────────────────────────────────────────
# Publish
# ─────────────────────────────────────────────────────────────────────────────

class TestPublish:
    def test_requires_opt_in(self, ts, ic):
        pid = _seed_custom_playbook(ic, TENANT_A)
        with pytest.raises(ValueError, match="not_opted_in"):
            ts.publish_playbook(TENANT_A, pid)

    def test_unknown_playbook(self, ts):
        ts.opt_in(TENANT_A)
        with pytest.raises(ValueError, match="not_found"):
            ts.publish_playbook(TENANT_A, "custom:does-not-exist")

    def test_cannot_publish_other_tenants_playbook(self, ts, ic):
        ts.opt_in(TENANT_B)
        pid = _seed_custom_playbook(ic, TENANT_A)
        with pytest.raises(ValueError, match="not_found"):
            ts.publish_playbook(TENANT_B, pid)

    def test_cannot_publish_builtin(self, ts, ic):
        ts.opt_in(TENANT_A)
        builtins = [p for p in ic.get_playbooks(tenant_id=None) if p["builtin"]]
        assert builtins, "expected built-in playbooks to be seeded"
        with pytest.raises(ValueError, match="not_found"):
            # Built-ins have tenant_id IS NULL — owner check fails first.
            ts.publish_playbook(TENANT_A, builtins[0]["playbook_id"])

    def test_publish_succeeds_and_increments_counter(self, ts, ic):
        ts.opt_in(TENANT_A)
        pid = _seed_custom_playbook(ic, TENANT_A)
        receipt = ts.publish_playbook(TENANT_A, pid)
        assert receipt["network_playbook_id"].startswith("net:")
        assert receipt["deduplicated"] is False
        status = ts.get_status(TENANT_A)
        assert status["published_count"] == 1

    def test_publish_is_idempotent(self, ts, ic):
        ts.opt_in(TENANT_A)
        pid = _seed_custom_playbook(ic, TENANT_A)
        first = ts.publish_playbook(TENANT_A, pid)
        second = ts.publish_playbook(TENANT_A, pid)
        assert second["network_playbook_id"] == first["network_playbook_id"]
        assert second["deduplicated"] is True
        # Counter only bumps on the first real publish.
        assert ts.get_status(TENANT_A)["published_count"] == 1

    def test_publish_marks_local_as_shared(self, ts, ic):
        ts.opt_in(TENANT_A)
        pid = _seed_custom_playbook(ic, TENANT_A)
        ts.publish_playbook(TENANT_A, pid)
        import sqlite3
        conn = sqlite3.connect(os.environ["DATA_DB_PATH"])
        row = conn.execute(
            "SELECT shared FROM intent_playbooks WHERE playbook_id=?", (pid,)
        ).fetchone()
        conn.close()
        assert row[0] == 1


# ─────────────────────────────────────────────────────────────────────────────
# Propagation
# ─────────────────────────────────────────────────────────────────────────────

class TestPropagate:
    def _publish_one(self, ts, ic) -> str:
        ts.opt_in(TENANT_A)
        pid = _seed_custom_playbook(ic, TENANT_A)
        return ts.publish_playbook(TENANT_A, pid)["network_playbook_id"]

    def test_propagate_creates_local_copy(self, ts, ic):
        nid = self._publish_one(ts, ic)
        out = ts.propagate_to_tenant(TENANT_B, nid)
        assert out is not None
        assert out["deduplicated"] is False
        # Local copy exists with source=network.
        local = [p for p in ic.get_playbooks(tenant_id=TENANT_B)
                 if p["playbook_id"] == out["local_playbook_id"]]
        assert local
        assert ts.get_status(TENANT_B)["received_count"] == 1

    def test_propagate_idempotent(self, ts, ic):
        nid = self._publish_one(ts, ic)
        first = ts.propagate_to_tenant(TENANT_B, nid)
        second = ts.propagate_to_tenant(TENANT_B, nid)
        assert second["deduplicated"] is True
        assert second["local_playbook_id"] == first["local_playbook_id"]
        # Counter does not double-bump.
        assert ts.get_status(TENANT_B)["received_count"] == 1

    def test_propagate_unknown_network_id_returns_none(self, ts):
        assert ts.propagate_to_tenant(TENANT_B, "net:bogus") is None


# ─────────────────────────────────────────────────────────────────────────────
# Sync
# ─────────────────────────────────────────────────────────────────────────────

class TestSync:
    def test_opted_out_tenant_receives_nothing(self, ts, ic):
        ts.opt_in(TENANT_A)
        pid = _seed_custom_playbook(ic, TENANT_A)
        ts.publish_playbook(TENANT_A, pid)
        # Tenant B has not opted in.
        added = ts.sync_network_playbooks(TENANT_B)
        assert added == 0
        # And no propagation row exists.
        b_pbs = [p for p in ic.get_playbooks(tenant_id=TENANT_B)
                 if p.get("source") == "network"]
        assert b_pbs == []

    def test_sync_pulls_pending_playbooks(self, ts, ic):
        ts.opt_in(TENANT_A)
        ts.opt_in(TENANT_B)
        pid = _seed_custom_playbook(ic, TENANT_A)
        ts.publish_playbook(TENANT_A, pid)
        added = ts.sync_network_playbooks(TENANT_B)
        assert added == 1

    def test_sync_idempotent(self, ts, ic):
        ts.opt_in(TENANT_A)
        ts.opt_in(TENANT_B)
        pid = _seed_custom_playbook(ic, TENANT_A)
        ts.publish_playbook(TENANT_A, pid)
        ts.sync_network_playbooks(TENANT_B)
        again = ts.sync_network_playbooks(TENANT_B)
        assert again == 0
        # Only one network-sourced playbook present.
        nets = [p for p in ic.get_playbooks(tenant_id=TENANT_B)
                if p.get("source") == "network"]
        assert len(nets) == 1


# ─────────────────────────────────────────────────────────────────────────────
# End-to-end gate: A publishes → B syncs → B sees it, anonymized.
# ─────────────────────────────────────────────────────────────────────────────

class TestEndToEndGate:
    def test_published_playbook_reaches_tenant_b_anonymized(self, ts, ic):
        # Tenant A authors and publishes a playbook stuffed with PII.
        ts.opt_in(TENANT_A)
        ts.opt_in(TENANT_B)
        pid_a = ic.add_playbook(
            tenant_id=TENANT_A,
            name="Acme Lateral Movement",
            description=(
                "Detected on agent-prod-99 from source_ip 10.0.0.5; "
                "owner alice@acme.com"
            ),
            severity="critical",
            steps=[
                {"category": "auth_anomaly", "agent_id": "agt-prod-99",
                 "source_ip": "10.0.0.5", "min_confidence": 0.55,
                 "mitre_technique": "T1078"},
                {"category": "privilege_escalation",
                 "user_id": "alice@acme.com", "min_confidence": 0.7,
                 "risk_tier": "high"},
            ],
            window_seconds=1200,
        )
        ts.publish_playbook(TENANT_A, pid_a)

        added = ts.sync_network_playbooks(TENANT_B)
        assert added == 1

        b_playbooks = ic.get_playbooks(tenant_id=TENANT_B)
        net_copies = [p for p in b_playbooks if p.get("source") == "network"]
        assert len(net_copies) == 1
        copy = net_copies[0]

        # 1. source flag is set.
        assert copy["source"] == "network"
        assert copy["network_playbook_id"]

        # 2. Tenant A identifiers are gone — at every nesting depth.
        leaks = (
            "agt-prod-99",
            "alice@acme.com",
            "10.0.0.5",
            TENANT_A,
            pid_a,
        )
        flat = repr(copy)
        for leak in leaks:
            assert leak not in flat, f"leaked: {leak!r}"

        # 3. Detection logic is preserved.
        steps = copy["steps"]
        assert steps[0]["category"] == "auth_anomaly"
        assert steps[0]["mitre_technique"] == "T1078"
        assert steps[0]["min_confidence"] == 0.55
        assert steps[1]["category"] == "privilege_escalation"
        assert steps[1]["min_confidence"] == 0.7
        assert steps[1]["risk_tier"] == "high"

        # 4. Tenant B's local row is owned by Tenant B (not by A).
        assert copy["tenant_id"] == TENANT_B


# ─────────────────────────────────────────────────────────────────────────────
# Network catalog browse
# ─────────────────────────────────────────────────────────────────────────────

class TestListNetwork:
    def test_empty(self, ts):
        assert ts.list_network_playbooks() == []

    def test_lists_published_playbooks(self, ts, ic):
        ts.opt_in(TENANT_A)
        for i in range(3):
            pid = _seed_custom_playbook(ic, TENANT_A, name=f"Pattern {i}")
            ts.publish_playbook(TENANT_A, pid)
        listed = ts.list_network_playbooks()
        assert len(listed) == 3
        # Catalog never includes source identifiers.
        flat = repr(listed)
        assert TENANT_A not in flat


# ─────────────────────────────────────────────────────────────────────────────
# Route-level integration (TestClient + dependency_overrides)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def app_with_tenant(tmp_db):
    """Fresh TestClient pinned to TENANT_A on the enterprise tier so the
    intent_correlation gate is open. Reloads modules against the isolated DB."""
    import importlib

    import modules.identity.intent_correlation as ic
    import modules.product.threat_sharing as t

    importlib.reload(ic)
    importlib.reload(t)
    t.init_db()

    import api as app_module
    from fastapi.testclient import TestClient
    from modules.tenants.middleware import get_tenant
    from modules.tenants.models import Plan, TenantContext

    tenant = TenantContext(
        tenant_id=TENANT_A,
        tenant_name="Acme",
        plan=Plan.ENTERPRISE,
        api_key_id="key",
        role="owner",
    )
    # Override every known binding of get_tenant so the override matches even
    # after a prior test reloaded modules.tenants.middleware (which leaves
    # commercial_tiers.get_tenant pointing at a now-orphaned function).
    import modules.product.commercial_tiers as _ct
    def _override():
        return tenant
    app_module.app.dependency_overrides[get_tenant] = _override
    app_module.app.dependency_overrides[_ct.get_tenant] = _override
    client = TestClient(app_module.app, raise_server_exceptions=False)
    yield client, ic, t
    app_module.app.dependency_overrides.clear()


class TestRoutes:
    def test_status_default(self, app_with_tenant):
        client, _, _ = app_with_tenant
        resp = client.get("/api/threat-sharing/status")
        assert resp.status_code == 200
        body = resp.json()
        assert body["opted_in"] is False
        assert body["published_count"] == 0

    def test_opt_in_then_status(self, app_with_tenant):
        client, _, _ = app_with_tenant
        assert client.post("/api/threat-sharing/opt-in").status_code == 200
        body = client.get("/api/threat-sharing/status").json()
        assert body["opted_in"] is True

    def test_publish_requires_opt_in(self, app_with_tenant):
        client, ic, _ = app_with_tenant
        pid = _seed_custom_playbook(ic, TENANT_A)
        resp = client.post(f"/api/threat-sharing/publish/{pid}")
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "not_opted_in"

    def test_publish_unknown_playbook(self, app_with_tenant):
        client, _, _ = app_with_tenant
        client.post("/api/threat-sharing/opt-in")
        resp = client.post("/api/threat-sharing/publish/custom:does-not-exist")
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "playbook_not_found"

    def test_full_publish_sync_browse_flow(self, app_with_tenant):
        client, ic, ts = app_with_tenant
        pid = _seed_custom_playbook(ic, TENANT_A)
        client.post("/api/threat-sharing/opt-in")
        pub = client.post(f"/api/threat-sharing/publish/{pid}").json()
        assert pub["network_playbook_id"].startswith("net:")
        net = client.get("/api/threat-sharing/network").json()
        assert net["count"] >= 1
        # Sync to TENANT_A is a no-op (same tenant published it — propagation
        # row gets written but it's the only one).
        sync = client.post("/api/threat-sharing/sync").json()
        assert sync["added"] >= 0
        assert sync["opted_in"] is True

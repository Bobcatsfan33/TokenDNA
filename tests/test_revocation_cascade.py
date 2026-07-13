"""Tests for cascade kill (Gap roadmap Epic 2.4)."""
from __future__ import annotations

import pytest

from modules.identity import blast_radius
from modules.identity import revocation_bus as rb


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "casc.db"))
    rb.reset_connectors()
    yield
    rb.reset_connectors()


class _Mock:
    def __init__(self, plane):
        self.plane = plane
        self.reversible = False
        self.ripped = []

    def is_connected(self, t):
        return True

    def revoke(self, t, a, ctx):
        self.ripped.append(a)
        return f"{self.plane} ripped {a}"

    def reverse(self, t, a, ctx):
        return "n/a"


def _fake_blast(reachable):
    def _sim(tenant_id, agent_label, max_hops=6):
        nodes = [
            blast_radius.ReachableNode(
                node_id=f"n{i}", node_type=nt, label=lbl, hop_distance=1,
                path_edge_types=["delegates_to"], impact_contribution=10)
            for i, (nt, lbl) in enumerate(reachable)
        ]
        return blast_radius.BlastRadiusResult(
            agent_label=agent_label, tenant_id=tenant_id, simulated_at="now",
            reachable_nodes=nodes, total_nodes_reached=len(nodes),
            impact_score=42, risk_tier="high")
    return _sim


def test_cascade_rips_root_and_reachable_agents(monkeypatch):
    m = _Mock("p1")
    rb.register_connector(m)
    monkeypatch.setattr(blast_radius, "simulate_blast_radius",
                        _fake_blast([("agent", "down-1"), ("agent", "down-2"),
                                     ("tool", "some-tool")]))  # tool excluded
    out = rb.cascade_rip("t", "root", actor="owner", reason="rogue cluster", planes=["p1"])
    assert out["reachable_count"] == 2
    assert out["root"]["agent_id"] == "root"
    downstream_agents = {d["agent_id"] for d in out["downstream"]}
    assert downstream_agents == {"down-1", "down-2"}
    # root + 2 downstream ripped; tool node NOT ripped (exactly the reachable set)
    assert set(m.ripped) == {"root", "down-1", "down-2"}


def test_cascade_excludes_root_from_downstream(monkeypatch):
    rb.register_connector(_Mock("p1"))
    monkeypatch.setattr(blast_radius, "simulate_blast_radius",
                        _fake_blast([("agent", "root"), ("agent", "down-1")]))
    out = rb.cascade_rip("t", "root", actor="owner", reason="x", planes=["p1"])
    assert out["reachable_count"] == 1  # root deduped out


def test_cascade_survives_blast_failure(monkeypatch):
    rb.register_connector(_Mock("p1"))
    def _boom(*a, **k):
        raise RuntimeError("graph down")
    monkeypatch.setattr(blast_radius, "simulate_blast_radius", _boom)
    out = rb.cascade_rip("t", "root", actor="owner", reason="x", planes=["p1"])
    assert out["reachable_count"] == 0
    assert out["root"]["overall"] == "complete"  # root still ripped


def test_cascade_requires_actor():
    with pytest.raises(ValueError):
        rb.cascade_rip("t", "root", actor="", reason="x")


# ── API: OWNER gating ─────────────────────────────────────────────────────────

@pytest.fixture()
def client_as(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "casc_api.db"))
    import api as app_module
    from fastapi.testclient import TestClient
    from modules.security import rbac
    from modules.tenants.models import Plan, TenantContext

    def _mk(role):
        tenant = TenantContext(tenant_id="t", tenant_name="T", plan=Plan.ENTERPRISE,
                               api_key_id="k", role=role)
        app_module.app.dependency_overrides[rbac._get_tenant_ctx] = lambda: tenant
        return TestClient(app_module.app, raise_server_exceptions=False)

    yield _mk
    app_module.app.dependency_overrides.clear()


def test_cascade_endpoint_owner_required(client_as):
    # ANALYST is below OWNER -> 403
    c = client_as("analyst")
    r = c.post("/api/kill/root/cascade", json={"reason": "x", "confirm": True})
    assert r.status_code == 403


def test_cascade_endpoint_requires_confirm(client_as):
    c = client_as("owner")
    r = c.post("/api/kill/root/cascade", json={"reason": "x"})
    assert r.status_code == 400


def test_cascade_endpoint_requires_reason(client_as):
    c = client_as("owner")
    r = c.post("/api/kill/root/cascade", json={"confirm": True})
    assert r.status_code == 400


def test_cascade_endpoint_owner_succeeds(client_as, monkeypatch):
    monkeypatch.setattr(blast_radius, "simulate_blast_radius", _fake_blast([]))
    c = client_as("owner")
    r = c.post("/api/kill/root/cascade", json={"reason": "rogue", "confirm": True})
    assert r.status_code == 200
    assert "root" in r.json()

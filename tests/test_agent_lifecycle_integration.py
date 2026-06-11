"""T-4: agent_lifecycle <-> trust_graph + audit integration.

Proves the cross-module integration item of the 7-point completeness bar:
every lifecycle transition is reflected as a trust-graph edge, terminal
decommission raises a graph anomaly, and each transition emits a SOC 2
AuditEvent.
"""
from __future__ import annotations

import importlib

import pytest

TENANT = "tenant-itg-001"


@pytest.fixture
def modules(tmp_path, monkeypatch):
    """Isolated DB shared by agent_lifecycle + trust_graph."""
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "itg.db"))
    import modules.identity.agent_lifecycle as al
    import modules.identity.trust_graph as tg
    importlib.reload(al)
    importlib.reload(tg)
    al.init_db()
    tg.init_db()
    return al, tg


@pytest.fixture
def captured_audit(monkeypatch):
    events = []
    import modules.security.audit_log as audit
    real = audit.log_event

    def _spy(event_type, *a, **k):
        canonical = getattr(event_type, "value", str(event_type))
        events.append((canonical, k.get("detail", {}), k.get("resource")))
        return None  # skip hash-chain write in tests

    monkeypatch.setattr(audit, "log_event", _spy)
    yield events
    monkeypatch.setattr(audit, "log_event", real)


def _register(al, agent_id="agent-itg"):
    return al.register_agent(
        tenant_id=TENANT, agent_id=agent_id, display_name="ITG Bot",
        platform="aws", owner="ops@acme.io", credential_ids=[], last_token_id="tok-1",
    )


# ── trust_graph reflection ────────────────────────────────────────────────────

def test_register_creates_agent_node_in_graph(modules):
    al, tg = modules
    _register(al)
    data = tg.get_graph_data(TENANT)
    labels = {n["label"] for n in data["nodes"]}
    assert "agent-itg" in labels
    types = {n["node_type"] for n in data["nodes"]}
    assert "agent" in types
    assert "lifecycle_state" in types


def test_transition_records_edge(modules):
    al, tg = modules
    _register(al)
    desc = tg.record_lifecycle_transition(TENANT, "agent-itg", "suspended", from_state="active")
    assert desc["to_state"] == "suspended"
    assert desc["from_state"] == "active"
    assert desc["edge_id"]
    data = tg.get_graph_data(TENANT)
    edge_types = {e["edge_type"] for e in data["edges"]}
    assert "transitioned_to" in edge_types


def test_suspend_then_reactivate_reflected(modules):
    al, tg = modules
    _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops", reason="audit")
    al.reactivate_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops")
    states = {n["label"] for n in tg.get_graph_data(TENANT)["nodes"] if n["node_type"] == "lifecycle_state"}
    assert "suspended" in states
    assert "active" in states


def test_decommission_raises_graph_anomaly(modules):
    al, tg = modules
    _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops", reason="pilot ended")
    anomalies = tg.get_anomalies(TENANT)
    kinds = {a["anomaly_type"] for a in anomalies}
    assert "AGENT_DECOMMISSIONED" in kinds
    decom = next(a for a in anomalies if a["anomaly_type"] == "AGENT_DECOMMISSIONED")
    assert decom["severity"] == "medium"
    assert "pilot ended" in decom["detail"]
    assert decom["context"]["from_state"] == "active"


def test_non_terminal_transition_no_anomaly(modules):
    al, tg = modules
    _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops")
    kinds = {a["anomaly_type"] for a in tg.get_anomalies(TENANT)}
    assert "AGENT_DECOMMISSIONED" not in kinds


# ── audit emission ────────────────────────────────────────────────────────────

def test_register_emits_audit(modules, captured_audit):
    al, _ = modules
    _register(al)
    assert any(e[0] == "agent.registered" for e in captured_audit)


def test_suspend_emits_audit(modules, captured_audit):
    al, _ = modules
    _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops", reason="audit")
    evt = next(e for e in captured_audit if e[0] == "agent.suspended")
    assert evt[1]["to_state"] == "suspended"
    assert evt[1]["from_state"] == "active"
    assert evt[2] == "agent/agent-itg"


def test_decommission_emits_audit(modules, captured_audit):
    al, _ = modules
    _register(al)
    al.decommission_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops", reason="ended")
    kinds = [e[0] for e in captured_audit]
    assert "agent.registered" in kinds
    assert "agent.decommissioned" in kinds


def test_full_lifecycle_audit_trail(modules, captured_audit):
    al, _ = modules
    _register(al)
    al.suspend_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops")
    al.reactivate_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops")
    al.decommission_agent(tenant_id=TENANT, agent_id="agent-itg", actor="ops")
    kinds = [e[0] for e in captured_audit]
    assert kinds == [
        "agent.registered",
        "agent.suspended",
        "agent.reactivated",
        "agent.decommissioned",
    ]


def test_graph_sync_failure_does_not_break_lifecycle(modules, monkeypatch):
    al, tg = modules
    # Force the trust_graph integration to raise; lifecycle must still succeed.
    monkeypatch.setattr(tg, "record_lifecycle_transition", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    agent = _register(al)
    assert agent["status"] == "active"  # registration still committed

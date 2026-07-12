"""Kill-path end-to-end — one revoke call rips every plane (P2.1).

The Definition of Done says: "Compromise→containment real: one call revokes
across IdP/session/MCP, trace shows it, e2e-tested." This file is that test.

It seeds a genuinely compromised agent — an ISSUED passport, a live session, an
MCP credential + tool grant + open session, and a trust-graph presence — then
makes ONE ``rip_credentials`` call and asserts every plane actually moved AND
the hash-chained audit log recorded it and still verifies.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def planes(tmp_path, monkeypatch):
    """Isolate every plane's store, then reload the modules that freeze their
    DB path at import time."""
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tokendna.db"))
    monkeypatch.setenv("TOKENDNA_MCP_GATEWAY_DB", str(tmp_path / "gw.db"))
    monkeypatch.setenv("TOKENDNA_ENFORCEMENT_DB", str(tmp_path / "enf.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AUDIT_BACKEND", "file")

    from modules.identity import (
        enforcement_plane,
        mcp_gateway,
        passport,
        session_registry,
        trust_graph,
    )
    from modules.security import audit_log

    for mod in (passport, session_registry, mcp_gateway, enforcement_plane, audit_log):
        importlib.reload(mod)

    # Connector modules bind to the reloaded plane modules at call time, but the
    # bus registry itself must be rebuilt so every default connector is present.
    from modules.identity import (  # noqa: F401 — self-register on import
        graph_revocation,
        idp_revocation,
        mcp_revocation,
        passport_revocation,
        session_revocation,
    )
    from modules.identity import revocation_bus as rb

    importlib.reload(rb)
    for mod in (idp_revocation, mcp_revocation, session_revocation,
                passport_revocation, graph_revocation):
        importlib.reload(mod)

    passport.init_passport_db()
    session_registry.init_db()
    mcp_gateway.init_db()
    trust_graph.init_db()

    return {
        "rb": rb,
        "passport": passport,
        "session_registry": session_registry,
        "mcp_gateway": mcp_gateway,
        "enforcement_plane": enforcement_plane,
        "trust_graph": trust_graph,
        "audit_log": audit_log,
        "audit_path": str(tmp_path / "audit.jsonl"),
    }


TENANT = "acme"
AGENT = "agent-rogue-01"


def _issue_passport(passport_mod, agent_id: str = AGENT):
    p = passport_mod.request_passport(
        tenant_id=TENANT,
        agent_id=agent_id,
        owner_org="Acme",
        display_name="Rogue Agent",
        agent_dna_fingerprint="dna-" + agent_id,
        permissions=["read:data"],
        resource_patterns=["db://acme/*"],
        requested_by="soc@acme.com",
    )
    passport_mod.approve_passport(p.passport_id)
    passport_mod.issue_passport(p.passport_id)
    return p


def _seed_compromised_agent(planes):
    """An agent holding identity in every plane."""
    p = _issue_passport(planes["passport"])
    planes["session_registry"].register_session(
        tenant_id=TENANT, agent_id=AGENT, session_id="sess-1",
    )
    planes["mcp_gateway"].grant_credential(
        tenant_id=TENANT, agent_id=AGENT, server_id="srv1", credential_ref="vault://k1",
    )
    planes["mcp_gateway"].grant_tool(
        tenant_id=TENANT, agent_id=AGENT, server_id="srv1", tool_name="search",
    )
    planes["mcp_gateway"].open_session(
        tenant_id=TENANT, agent_id=AGENT, server_id="srv1",
    )
    planes["trust_graph"].ingest_uis_event(TENANT, {
        "identity": {
            "subject": AGENT,
            "entity_type": "machine",
            "agent_id": AGENT,
        },
        "token": {"issuer": "https://idp.acme.com"},
        "auth": {"method": "oauth", "protocol": "https"},
    })
    return p


# ── The money test ────────────────────────────────────────────────────────────

def test_one_call_rips_every_plane(planes):
    """Seed a compromised agent → ONE revoke call → every plane moved."""
    p = _seed_compromised_agent(planes)
    rb = planes["rb"]

    receipt = rb.rip_credentials(
        TENANT, AGENT, actor="soc@acme.com", reason="confirmed compromise",
    )

    # No plane failed.
    assert receipt.overall == "complete", receipt.as_dict()

    by_plane = {pr.plane: pr for pr in receipt.planes}

    # 1. Passport — the credential of record is dead.
    assert by_plane["passport"].status == rb.KILLED
    stored = planes["passport"].get_passport(p.passport_id)
    assert stored.status == planes["passport"].PassportStatus.REVOKED
    assert "confirmed compromise" in (stored.revocation_reason or "")

    # 2. Live sessions — terminated.
    assert by_plane["live_sessions"].status == rb.KILLED
    assert planes["session_registry"].list_active_sessions(TENANT, AGENT) == []

    # 3. MCP — credentials pulled, grants disabled, sessions closed.
    assert by_plane["mcp"].status == rb.KILLED
    grants = planes["mcp_gateway"].list_agent_grants(tenant_id=TENANT, agent_id=AGENT)
    assert grants["credentials"] == []
    assert grants["tool_grants"] == []
    assert grants["open_sessions"] == []

    # 4. Trust graph — the agent node is marked revoked.
    assert by_plane["trust_graph"].status == rb.KILLED
    assert planes["trust_graph"].is_agent_revoked(TENANT, AGENT) is True

    # 5. TokenDNA decision switch — evaluate() now short-circuits to deny.
    assert by_plane["tokendna_decision"].status == rb.KILLED
    status = planes["enforcement_plane"].get_kill_switch_status(TENANT, AGENT)
    assert status["active"] is True


def test_rip_writes_a_verifiable_audit_chain(planes):
    """Every plane revocation lands in the hash-chained audit log, intact."""
    _seed_compromised_agent(planes)
    audit_log = planes["audit_log"]

    planes["rb"].rip_credentials(
        TENANT, AGENT, actor="soc@acme.com", reason="confirmed compromise",
    )

    integrity = audit_log.verify_log_integrity(planes["audit_path"])
    assert integrity["ok"] is True, integrity
    assert integrity["entries"] > 0

    body = open(planes["audit_path"], encoding="utf-8").read()
    # NOTE: log_event serialises the event type as str(enum), which yields the
    # Python repr ("AuditEventType.KILL_RIP_INITIATED") rather than the AU-2
    # value it defines ("kill.rip.initiated"). That is pre-existing, system-wide
    # behaviour — see the DECISION NEEDED in SIMPLIFICATION_STATUS.md. These
    # assertions pin what the chain actually contains today.
    assert "KILL_RIP_INITIATED" in body
    assert "KILL_PLANE_REVOKED" in body
    # The planes that matter are each named in the chain.
    for plane in ("passport", "trust_graph", "mcp", "live_sessions"):
        assert f'"plane": "{plane}"' in body


# ── Passport plane ────────────────────────────────────────────────────────────

def test_passport_plane_revokes_all_issued_passports(planes):
    p1 = _issue_passport(planes["passport"])
    p2 = _issue_passport(planes["passport"])

    receipt = planes["rb"].rip_credentials(
        TENANT, AGENT, actor="soc", reason="rip", planes=["passport"],
    )

    assert receipt.planes[0].status == planes["rb"].KILLED
    assert "2 passport" in receipt.planes[0].detail
    for pid in (p1.passport_id, p2.passport_id):
        assert planes["passport"].get_passport(pid).status == \
            planes["passport"].PassportStatus.REVOKED


def test_passport_plane_is_idempotent(planes):
    """Re-ripping is safe — a second rip must not raise or fail the plane."""
    _issue_passport(planes["passport"])
    rb = planes["rb"]

    first = rb.rip_credentials(TENANT, AGENT, actor="soc", reason="rip",
                               planes=["passport"])
    second = rb.rip_credentials(TENANT, AGENT, actor="soc", reason="rip",
                                planes=["passport"])

    assert first.planes[0].status == rb.KILLED
    assert second.planes[0].status == rb.KILLED
    assert "already revoked" in second.planes[0].detail


def test_passport_plane_with_no_passports(planes):
    receipt = planes["rb"].rip_credentials(
        TENANT, "ghost-agent", actor="soc", reason="rip", planes=["passport"],
    )
    assert receipt.planes[0].status == planes["rb"].KILLED
    assert "no active passports" in receipt.planes[0].detail


def test_passport_plane_leaves_pending_passports_alone(planes):
    """A PENDING passport confers no trust — there is nothing to revoke."""
    pm = planes["passport"]
    pending = pm.request_passport(
        tenant_id=TENANT, agent_id=AGENT, owner_org="Acme",
        display_name="Rogue Agent", agent_dna_fingerprint="dna",
        permissions=["read:data"], resource_patterns=["db://acme/*"],
        requested_by="soc@acme.com",
    )

    receipt = planes["rb"].rip_credentials(
        TENANT, AGENT, actor="soc", reason="rip", planes=["passport"],
    )

    assert receipt.planes[0].status == planes["rb"].KILLED
    assert "no active passports" in receipt.planes[0].detail
    # Still PENDING — untouched, not spuriously "revoked".
    assert pm.get_passport(pending.passport_id).status == pm.PassportStatus.PENDING


def test_passport_plane_is_irreversible(planes):
    _issue_passport(planes["passport"])
    rb = planes["rb"]
    rb.rip_credentials(TENANT, AGENT, actor="soc", reason="rip", planes=["passport"])

    rev = rb.reverse_rip(TENANT, AGENT, actor="soc", reason="oops",
                         planes=["passport"])

    assert rev.planes[0].status == rb.NOT_CONNECTED
    assert "irreversible" in rev.planes[0].detail.lower() or \
        "re-issue" in rev.planes[0].detail.lower()


# ── Trust-graph plane ─────────────────────────────────────────────────────────

def test_trust_graph_plane_marks_node_and_raises_anomaly(planes):
    _seed_compromised_agent(planes)
    tg = planes["trust_graph"]

    receipt = planes["rb"].rip_credentials(
        TENANT, AGENT, actor="soc", reason="confirmed compromise",
        planes=["trust_graph"],
    )

    assert receipt.planes[0].status == planes["rb"].KILLED
    assert tg.is_agent_revoked(TENANT, AGENT) is True

    anomalies = tg.get_anomalies(TENANT)
    kinds = {a["anomaly_type"] if isinstance(a, dict) else a.anomaly_type
             for a in anomalies}
    assert "AGENT_CREDENTIALS_REVOKED" in kinds


def test_trust_graph_plane_when_agent_absent_from_graph(planes):
    """An agent TokenDNA never observed is not an error — just nothing to mark."""
    receipt = planes["rb"].rip_credentials(
        TENANT, "never-seen", actor="soc", reason="rip", planes=["trust_graph"],
    )
    assert receipt.planes[0].status == planes["rb"].KILLED
    assert "not present" in receipt.planes[0].detail.lower()
    assert planes["trust_graph"].is_agent_revoked(TENANT, "never-seen") is False


def test_trust_graph_plane_is_reversible(planes):
    _seed_compromised_agent(planes)
    tg = planes["trust_graph"]
    rb = planes["rb"]

    rb.rip_credentials(TENANT, AGENT, actor="soc", reason="rip", planes=["trust_graph"])
    assert tg.is_agent_revoked(TENANT, AGENT) is True

    rb.reverse_rip(TENANT, AGENT, actor="soc", reason="false positive",
                   planes=["trust_graph"])
    assert tg.is_agent_revoked(TENANT, AGENT) is False


def test_preview_lists_the_new_planes(planes):
    receipt = planes["rb"].preview(TENANT, AGENT)
    planes_seen = {p.plane for p in receipt.planes}
    assert {"passport", "trust_graph"} <= planes_seen

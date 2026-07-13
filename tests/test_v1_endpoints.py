"""The three flagship /v1 endpoints + the evaluate() core (P2.4).

Three questions, three endpoints, one code path. These tests hold the core to the
contract the product is sold on: a revoked passport cannot verify, a kill-switched
agent cannot authorize, a compromised agent's containment returns a *verifiable*
trace, and one revoke call changes the agent's state — provably, because the
endpoint re-diagnoses afterwards.
"""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tokendna.db"))
    monkeypatch.setenv("TOKENDNA_MCP_GATEWAY_DB", str(tmp_path / "gw.db"))
    monkeypatch.setenv("TOKENDNA_ENFORCEMENT_DB", str(tmp_path / "enf.db"))
    monkeypatch.setenv("TOKENDNA_BEHAVIORAL_DB", str(tmp_path / "bd.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AUDIT_BACKEND", "file")
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("TOKENDNA_ENV", "test")
    monkeypatch.setenv("DEV_TENANT_ID", TENANT)

    from modules.identity import (
        behavioral_dna,
        enforcement_plane,
        mcp_gateway,
        passport,
        session_registry,
        trust_graph,
        uis_store,
    )
    from modules.security import audit_log

    for mod in (passport, session_registry, mcp_gateway, enforcement_plane,
                behavioral_dna, uis_store, audit_log):
        importlib.reload(mod)

    from modules.identity import (  # noqa: F401 — self-register on import
        graph_revocation,
        idp_revocation,
        mcp_revocation,
        passport_revocation,
        session_revocation,
    )
    from modules.identity import evaluate as ev
    from modules.identity import revocation_bus as rb
    from modules.identity import trace_report

    importlib.reload(rb)
    for mod in (idp_revocation, mcp_revocation, session_revocation,
                passport_revocation, graph_revocation):
        importlib.reload(mod)
    importlib.reload(trace_report)
    importlib.reload(ev)

    passport.init_passport_db()
    uis_store.init_db()
    trust_graph.init_db()

    import api
    from fastapi.testclient import TestClient

    return {"client": TestClient(api.app), "ev": ev, "rb": rb,
            "passport": passport, "enforcement_plane": enforcement_plane}


TENANT = "acme"
AGENT = "agent-01"


def _issue_passport(pm, agent_id=AGENT):
    p = pm.request_passport(
        tenant_id=TENANT, agent_id=agent_id, owner_org="Acme",
        display_name="Agent", agent_dna_fingerprint="dna-" + agent_id,
        permissions=["read:data"], resource_patterns=["db://acme/*"],
        requested_by="soc@acme.com",
    )
    pm.approve_passport(p.passport_id)
    return pm.issue_passport(p.passport_id)


def _as_dict(p):
    """The wire shape verify_passport expects."""
    import dataclasses
    d = dataclasses.asdict(p)
    d["status"] = p.status.value
    return d


# ── VERIFY ────────────────────────────────────────────────────────────────────

def test_verify_allows_a_valid_passport(app_env):
    p = _issue_passport(app_env["passport"])

    r = app_env["client"].post("/v1/verify",
                               json={"agent_id": AGENT, "passport": _as_dict(p)})

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "ALLOW"
    assert body["question"] == "verify"
    assert any(e["check"] == "passport" for e in body["evidence"])


def test_verify_rejects_a_revoked_passport_with_401(app_env):
    """The kill path revoked it (P2.1); verify must now refuse it. This is the
    loop that was open before P2.1: every plane ripped, passport still ISSUED."""
    p = _issue_passport(app_env["passport"])
    app_env["rb"].rip_credentials(TENANT, AGENT, actor="soc", reason="compromise",
                                  planes=["passport"])

    stored = app_env["passport"].get_passport(p.passport_id)
    r = app_env["client"].post("/v1/verify",
                               json={"agent_id": AGENT, "passport": _as_dict(stored)})

    # 401, not 403: nothing was refused on policy grounds — the identity failed.
    assert r.status_code == 401
    body = r.json()
    assert body["verdict"] in ("BLOCK", "REVOKE")
    assert body["confidence"] == 1.0, "an explicit revocation is decisive, not inferred"
    assert any("revoked" in reason.lower() for reason in body["reasons"])


def test_verify_without_a_passport_is_not_a_confident_allow(app_env):
    """Honesty property: we must not answer ALLOW-with-certainty on no evidence."""
    r = app_env["client"].post("/v1/verify", json={"agent_id": "unknown-agent"})

    body = r.json()
    assert body["verdict"] != "ALLOW" or body["confidence"] < 0.9


def test_verify_requires_agent_id(app_env):
    assert app_env["client"].post("/v1/verify", json={}).status_code == 400


# ── AUTHORIZE ─────────────────────────────────────────────────────────────────

def test_authorize_allows_an_unrestricted_action(app_env):
    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/customers",
    })
    assert r.status_code == 200
    assert r.json()["verdict"] == "ALLOW"


def test_authorize_blocks_a_kill_switched_agent_with_403(app_env):
    """One rip (P2.1) → the decision plane short-circuits every later authorize."""
    app_env["rb"].rip_credentials(TENANT, AGENT, actor="soc", reason="compromise")

    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/customers",
    })

    assert r.status_code == 403
    body = r.json()
    assert body["verdict"] in ("BLOCK", "REVOKE")
    assert body["confidence"] == 1.0
    assert any("kill_switch" in reason for reason in body["reasons"])


def test_authorize_evaluates_token_scopes_but_honours_log_only_rollout(app_env, monkeypatch):
    """D-2 wire-in. `modules.auth.scopes` ships in log-only rollout, so a missing
    scope must be *reported*, not enforced, until the operator turns enforcement
    on. Wiring it must not silently start denying traffic that used to flow."""
    monkeypatch.delenv("TOKENDNA_SCOPES_ENFORCE", raising=False)

    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "write", "resource": "db://acme/x",
        "claims": {"scp": ["read"]},   # holds read, is asking for write
    })

    assert r.status_code == 200, "log-only rollout must not deny"
    body = r.json()
    assert body["verdict"] == "ALLOW"
    scope_ev = next(e for e in body["evidence"] if e["check"] == "scopes")
    assert scope_ev["covered"] is False
    assert scope_ev["enforcing"] is False
    assert any("log-only" in reason for reason in body["reasons"])


def test_authorize_denies_a_missing_scope_once_enforcement_is_on(app_env, monkeypatch):
    monkeypatch.setenv("TOKENDNA_SCOPES_ENFORCE", "true")

    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "write", "resource": "db://acme/x",
        "claims": {"scp": ["read"]},
    })

    assert r.status_code == 403
    body = r.json()
    assert body["verdict"] == "BLOCK"
    assert body["confidence"] == 1.0
    assert any("'write' scope" in reason for reason in body["reasons"])


def test_authorize_allows_when_the_token_holds_the_scope(app_env, monkeypatch):
    monkeypatch.setenv("TOKENDNA_SCOPES_ENFORCE", "true")

    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/x",
        "claims": {"scp": ["read", "list"]},
    })

    assert r.status_code == 200
    assert r.json()["verdict"] == "ALLOW"


def test_authorize_requires_action_and_resource(app_env):
    r = app_env["client"].post("/v1/authorize", json={"agent_id": AGENT})
    assert r.status_code == 400
    assert "action" in r.json()["detail"]


# ── CONTAIN ───────────────────────────────────────────────────────────────────

def test_contain_returns_a_verifiable_trace_and_blast_radius(app_env):
    app_env["rb"].rip_credentials(TENANT, AGENT, actor="soc", reason="compromise")

    r = app_env["client"].get(f"/v1/contain/{AGENT}")

    # CONTAIN is a diagnosis, not a refusal — the operator must get the evidence.
    assert r.status_code == 200
    body = r.json()
    assert body["question"] == "contain"

    blast = body["blast_radius"]
    assert "trace" in blast
    assert blast["trace_report_hash"]
    assert blast["trace_verification"]["ok"] is True, "the trace must verify"
    # The containment actions themselves are in the trace.
    assert any(row["source"] == "audit" for row in blast["trace"])


def test_contain_on_a_clean_agent_allows(app_env):
    r = app_env["client"].get("/v1/contain/quiet-agent")
    assert r.status_code == 200
    assert r.json()["verdict"] == "ALLOW"


# ── The full arc: verify → authorize → contain → revoke → re-diagnose ─────────

def test_revoke_endpoint_rips_every_plane_and_re_diagnoses(app_env):
    p = _issue_passport(app_env["passport"])
    client = app_env["client"]

    # Before: the agent verifies and is authorized.
    assert client.post("/v1/verify", json={"agent_id": AGENT,
                                           "passport": _as_dict(p)}).status_code == 200
    assert client.post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/x",
    }).status_code == 200

    # One call contains it.
    r = client.post(f"/v1/contain/{AGENT}/revoke",
                    json={"reason": "confirmed compromise"})
    assert r.status_code == 200
    body = r.json()

    assert body["receipt"]["overall"] == "complete"
    assert body["receipt"]["killed"] >= 6
    # The endpoint re-diagnoses rather than asserting success.
    assert body["post_containment_verdict"]["question"] == "contain"

    # After: the same agent no longer verifies, and no longer authorizes.
    stored = app_env["passport"].get_passport(p.passport_id)
    assert client.post("/v1/verify", json={"agent_id": AGENT,
                                           "passport": _as_dict(stored)}).status_code == 401
    assert client.post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/x",
    }).status_code == 403


def test_revoke_requires_a_reason(app_env):
    r = app_env["client"].post(f"/v1/contain/{AGENT}/revoke", json={})
    assert r.status_code == 400


# ── Signals that change the verdict ───────────────────────────────────────────

def test_verify_rejects_a_bad_dpop_proof(app_env):
    """D-2 wire-in: proof-of-possession is evidence in the verify verdict."""
    p = _issue_passport(app_env["passport"])

    r = app_env["client"].post("/v1/verify", json={
        "agent_id": AGENT, "passport": _as_dict(p),
        "dpop_proof": "not-a-jwt", "dpop_uri": "https://api.acme/x",
    })

    assert r.status_code == 401
    body = r.json()
    dpop_ev = next(e for e in body["evidence"] if e["check"] == "dpop")
    assert dpop_ev["valid"] is False
    assert body["confidence"] == 1.0, "a rejected proof is decisive"


def test_verify_steps_up_when_proof_of_control_is_overdue(app_env, monkeypatch):
    """A valid passport with a stale proof-of-control is not a BLOCK — the identity
    is real; our evidence that it is still *controlled* is not."""
    from modules.identity import proof_of_control

    p = _issue_passport(app_env["passport"])

    class _Overdue:
        overdue = True

    monkeypatch.setattr(proof_of_control, "get_proof_status",
                        lambda *a, **k: _Overdue())

    r = app_env["client"].post("/v1/verify",
                               json={"agent_id": AGENT, "passport": _as_dict(p)})

    assert r.status_code == 202  # STEP_UP
    body = r.json()
    assert body["verdict"] == "STEP_UP"
    assert any("proof-of-control" in reason for reason in body["reasons"])
    assert "step-up" in body["recommended_action"]


def test_authorize_steps_up_on_open_permission_drift(app_env, monkeypatch):
    from modules.identity import permission_drift

    class _Alert:
        severity = "high"
        reason = "agent acquired 3 new permissions in 24h"

    monkeypatch.setattr(permission_drift, "list_alerts", lambda *a, **k: [_Alert()])

    r = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/x",
    })

    assert r.status_code == 202
    body = r.json()
    assert body["verdict"] == "STEP_UP"
    assert any(e["check"] == "permission_drift" for e in body["evidence"])


def test_contain_recommends_revoke_on_a_critical_anomaly(app_env):
    """A critical anomaly is not a BLOCK — blocking one request does not help an
    agent that is already compromised. The verdict must be REVOKE."""
    from modules.identity import trust_graph

    trust_graph.ingest_uis_event(TENANT, {
        "identity": {"subject": AGENT, "entity_type": "machine", "agent_id": AGENT},
        "token": {"issuer": "https://idp.acme.com"},
        "auth": {"method": "oauth", "protocol": "https"},
    })
    # mark_agent_revoked raises a CRITICAL AGENT_CREDENTIALS_REVOKED anomaly (P2.1).
    trust_graph.mark_agent_revoked(TENANT, AGENT, actor="soc", reason="compromise")

    r = app_env["client"].get(f"/v1/contain/{AGENT}")

    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "REVOKE"
    assert body["confidence"] == 1.0
    assert "revoke credentials" in body["recommended_action"]


def test_contain_surfaces_behavioural_drift_and_mcp_violations(app_env, monkeypatch):
    from modules.identity import behavioral_dna, mcp_inspector

    monkeypatch.setattr(behavioral_dna, "list_drift_alerts",
                        lambda *a, **k: [{"reason": "tool-use pattern diverged"}])
    monkeypatch.setattr(mcp_inspector, "list_violations",
                        lambda *a, **k: [{"agent_id": AGENT,
                                          "violation_type": "read_then_exfil_chain"}])

    r = app_env["client"].get(f"/v1/contain/{AGENT}")

    body = r.json()
    checks = {e["check"] for e in body["evidence"]}
    assert "behavioral_drift" in checks
    assert "mcp_violation" in checks
    assert body["verdict"] in ("STEP_UP", "BLOCK", "REVOKE")


def test_a_pillar_that_raises_does_not_sink_the_verdict(app_env, monkeypatch):
    """A store that is not provisioned yet must degrade, not 500 — but it must not
    be silently scored as 'clean' either."""
    from modules.identity import behavioral_dna

    def _boom(*a, **k):
        raise RuntimeError("behavioural store not provisioned")

    monkeypatch.setattr(behavioral_dna, "list_drift_alerts", _boom)

    r = app_env["client"].get(f"/v1/contain/{AGENT}")
    assert r.status_code == 200
    assert not any(e["check"] == "behavioral_drift" for e in r.json()["evidence"])


# ── The evaluate() core itself ────────────────────────────────────────────────

def test_evaluate_rejects_an_unknown_question(app_env):
    ev = app_env["ev"]
    with pytest.raises(ValueError, match="unknown question"):
        ev.evaluate("teleport", ev.Subject(tenant_id=TENANT, agent_id=AGENT))


def test_evaluate_is_the_only_code_path(app_env):
    """Each endpoint is thin orchestration: the verdict it returns is exactly the
    one evaluate() produces, not a re-derivation."""
    ev = app_env["ev"]
    app_env["rb"].rip_credentials(TENANT, AGENT, actor="soc", reason="compromise")

    direct = ev.evaluate("authorize", ev.Subject(
        tenant_id=TENANT, agent_id=AGENT, action="read", resource="db://acme/x",
    ))
    via_api = app_env["client"].post("/v1/authorize", json={
        "agent_id": AGENT, "action": "read", "resource": "db://acme/x",
    }).json()

    assert via_api["verdict"] == direct.verdict
    assert via_api["confidence"] == round(direct.confidence, 2)

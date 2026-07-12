"""Tamper-evident TraceReport (P2.2).

The report's claim is not "TokenDNA says this happened" but "here is the chain,
re-derive it yourself". These tests hold it to that: they build a report from real
seeded state, then try to forge it — edit a row, reorder rows, drop a row, insert
one, and rewrite the audit log it cites — and assert every attempt is caught.
"""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DB_PATH", str(tmp_path / "tokendna.db"))
    monkeypatch.setenv("TOKENDNA_MCP_GATEWAY_DB", str(tmp_path / "gw.db"))
    monkeypatch.setenv("TOKENDNA_ENFORCEMENT_DB", str(tmp_path / "enf.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AUDIT_BACKEND", "file")

    from modules.identity import (
        delegation_receipt,
        enforcement_plane,
        mcp_gateway,
        passport,
        session_registry,
        trust_graph,
        uis_store,
    )
    from modules.security import audit_log

    for mod in (passport, session_registry, mcp_gateway, enforcement_plane,
                delegation_receipt, uis_store, audit_log):
        importlib.reload(mod)

    from modules.identity import (  # noqa: F401 — self-register on import
        graph_revocation,
        idp_revocation,
        mcp_revocation,
        passport_revocation,
        session_revocation,
    )
    from modules.identity import revocation_bus as rb
    from modules.identity import trace_report as tr

    importlib.reload(rb)
    for mod in (idp_revocation, mcp_revocation, session_revocation,
                passport_revocation, graph_revocation):
        importlib.reload(mod)
    importlib.reload(tr)

    uis_store.init_db()
    trust_graph.init_db()
    delegation_receipt.init_db()

    return {
        "tr": tr, "rb": rb, "uis_store": uis_store, "trust_graph": trust_graph,
        "delegation_receipt": delegation_receipt, "audit_log": audit_log,
        "audit_path": str(tmp_path / "audit.jsonl"),
    }


TENANT = "acme"
AGENT = "agent-rogue-01"


def _minutes_ago(minutes: int) -> str:
    """Timestamps must be relative to now, never hard-coded: the report's window
    is a rolling 24 hours, so a fixed date turns these into tests that pass today
    and fail tomorrow."""
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()


def _uis_event(env, *, event_id: str, outcome: str = "success", mitre=None,
               minutes_ago: int = 60):
    ev = {
        "uis_version": "1.0",
        "event_id": event_id,
        "event_timestamp": _minutes_ago(minutes_ago),
        "identity": {
            "entity_type": "machine",
            "subject": f"{AGENT}@svc.local",
            "tenant_id": TENANT,
            "agent_id": AGENT,
        },
        "auth": {"method": "oauth", "protocol": "https"},
        "token": {"issuer": "https://auth.acme.example.com", "audience": "payments-api"},
        "binding": {"attestation_id": "att-abc123", "spiffe_id": None},
        "outcome": outcome,
        "metadata": {"mitre_technique": mitre},
    }
    env["uis_store"].insert_event(TENANT, ev)
    env["trust_graph"].ingest_uis_event(TENANT, ev)
    return ev


def _seed(env):
    """A compromised agent with a real history across every source."""
    _uis_event(env, event_id="ev-001", minutes_ago=120)
    _uis_event(env, event_id="ev-002", outcome="failure", mitre="T1078",
               minutes_ago=90)
    # A containment action → lands in the hash-chained audit log.
    env["rb"].rip_credentials(TENANT, AGENT, actor="soc@acme.com",
                              reason="confirmed compromise")


# ── Composition ───────────────────────────────────────────────────────────────

def test_report_is_time_ordered_and_composes_every_source(env):
    _seed(env)
    report = env["tr"].build_trace_report(
        TENANT, AGENT, audit_log_path=env["audit_path"],
    )

    assert report.agent_id == AGENT
    assert report.rows, "report should not be empty"

    sources = {r.source for r in report.rows}
    assert "uis" in sources, "the agent's own actions must appear"
    assert "audit" in sources, "the containment actions must appear"

    # Time-ordered, oldest first.
    stamps = [env["tr"]._parse_ts(r.timestamp) for r in report.rows]
    assert stamps == sorted(stamps), "rows must be time-ordered"

    # Every row cites a source of record.
    for row in report.rows:
        assert row.evidence_pointer and ":" in row.evidence_pointer
        assert row.narrative


def test_uis_rows_carry_credential_action_resource(env):
    _uis_event(env, event_id="ev-100", mitre="T1550")
    report = env["tr"].build_trace_report(TENANT, AGENT,
                                          audit_log_path=env["audit_path"])

    uis = [r for r in report.rows if r.source == "uis"]
    assert uis
    row = uis[0]
    assert row.action == "https:oauth"
    assert row.resource == "payments-api"
    assert row.credential == "att-abc123"
    assert row.evidence_pointer == "uis:ev-100"
    assert "T1550" in row.narrative


def test_report_includes_blast_radius(env):
    _seed(env)
    report = env["tr"].build_trace_report(TENANT, AGENT,
                                          audit_log_path=env["audit_path"])
    assert report.blast_radius is not None
    assert "affected_agents" in report.blast_radius
    assert "affected_resources" in report.blast_radius
    assert "risk_tier" in report.blast_radius


def test_delegation_lineage_appears(env):
    dr = env["delegation_receipt"]
    receipt = dr.issue_receipt(
        tenant_id=TENANT,
        delegator_id="human:alice@acme.com",  # root receipt: delegator must be human
        delegatee_id=AGENT,
        scope=["read:payments"],
        expires_in_seconds=3600,
    )
    report = env["tr"].build_trace_report(TENANT, AGENT,
                                          audit_log_path=env["audit_path"])

    deleg = [r for r in report.rows if r.source == "delegation"]
    assert deleg, "the agent's delegated authority must be traceable"
    assert "alice@acme.com" in deleg[0].narrative
    assert "read:payments" in deleg[0].narrative
    assert deleg[0].evidence_pointer == f"receipt:{receipt.receipt_id}"
    assert deleg[0].credential == receipt.receipt_id


def test_agent_with_no_history_yields_an_empty_but_valid_report(env):
    report = env["tr"].build_trace_report(TENANT, "never-seen",
                                          audit_log_path=env["audit_path"])
    assert report.rows == []
    assert report.report_hash == env["tr"].GENESIS_HASH
    assert env["tr"].verify_trace_report(
        report, audit_log_path=env["audit_path"])["ok"] is True


# ── Tamper-evidence: the whole point ──────────────────────────────────────────

def test_untampered_report_verifies(env):
    _seed(env)
    report = env["tr"].build_trace_report(TENANT, AGENT,
                                          audit_log_path=env["audit_path"])

    result = env["tr"].verify_trace_report(report, audit_log_path=env["audit_path"])
    assert result["ok"] is True, result
    assert result["rows"] == len(report.rows)
    assert result["citations_checked"] >= 1, "audit citations must actually be checked"


def test_editing_a_row_is_detected(env):
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])

    forged = report.as_dict()
    # Rewrite history: make a failed action look successful.
    victim = next(i for i, r in enumerate(forged["rows"]) if r["source"] == "uis")
    forged["rows"][victim]["resource"] = "innocent-api"

    result = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert result["ok"] is False
    assert result["first_violation"] == victim + 1
    assert "Hash mismatch" in result["message"]


def test_reordering_rows_is_detected(env):
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])
    if len(report.rows) < 2:
        pytest.skip("need at least two rows to reorder")

    forged = report.as_dict()
    forged["rows"][0], forged["rows"][1] = forged["rows"][1], forged["rows"][0]

    result = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert result["ok"] is False


def test_dropping_a_row_is_detected(env):
    """Deleting the incriminating row must break the chain."""
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])
    if len(report.rows) < 2:
        pytest.skip("need at least two rows to drop one")

    forged = report.as_dict()
    del forged["rows"][0]

    result = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert result["ok"] is False
    assert result["first_violation"] == 1


def test_appending_a_forged_row_is_detected(env):
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])

    forged = report.as_dict()
    forged["rows"].append({
        "timestamp": "2026-07-11T23:59:00+00:00", "agent": AGENT,
        "credential": "-", "action": "totally_fine", "resource": "-",
        "evidence_pointer": "uis:fake", "source": "uis",
        "narrative": "nothing to see here", "severity": "info",
        "prev_hash": forged["rows"][-1]["row_hash"] if forged["rows"] else tr.GENESIS_HASH,
        "row_hash": "0" * 64,
    })

    result = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert result["ok"] is False


def test_report_hash_must_match_the_chain(env):
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])

    forged = report.as_dict()
    forged["report_hash"] = "f" * 64

    result = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert result["ok"] is False
    assert "report_hash" in result["message"]


def test_a_report_that_agrees_with_itself_but_not_the_audit_log_is_caught(env):
    """The second, independent layer: citations are re-checked against the log.

    A forger who rebuilds the whole row chain correctly still cannot make the
    report agree with the tamper-evident audit log it cites.
    """
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])

    audit_rows = [r for r in report.rows if r.source == "audit"]
    assert audit_rows, "seed must produce audit rows"

    # Forge an audit row's content AND re-chain the report so it is internally
    # perfect — the lie is now only detectable against the audit log itself.
    forged_rows = []
    for r in report.rows:
        d = r.as_dict()
        if d["source"] == "audit":
            d["narrative"] = "routine maintenance, nothing was revoked"
        forged_rows.append(tr.TraceRow(**{**d, "prev_hash": "", "row_hash": ""}))
    rechained = tr._chain(forged_rows)

    forged = report.as_dict()
    forged["rows"] = [r.as_dict() for r in rechained]
    forged["report_hash"] = rechained[-1].row_hash

    # Internally consistent...
    assert tr.verify_trace_report(
        forged, audit_log_path=env["audit_path"], check_audit_citations=False,
    )["ok"] is True

    # ...but the citation check still catches it, because the row's evidence
    # pointer carries the audit entry_hash, and the audit log still has the truth.
    strict = tr.verify_trace_report(forged, audit_log_path=env["audit_path"])
    assert strict["ok"] is False
    assert "audit entry" in strict["message"]


def test_trace_endpoint_serves_a_self_verifying_report(env, monkeypatch):
    """GET /api/kill/{agent}/trace returns the report AND its verification."""
    monkeypatch.setenv("DEV_MODE", "true")
    monkeypatch.setenv("DEV_TENANT_ID", TENANT)
    _seed(env)

    import api
    from fastapi.testclient import TestClient

    r = TestClient(api.app).get(f"/api/kill/{AGENT}/trace")
    assert r.status_code == 200
    body = r.json()

    assert body["agent_id"] == AGENT
    assert body["row_count"] == len(body["rows"])
    assert body["verification"]["ok"] is True
    assert body["report_hash"]


def test_rewriting_the_audit_log_is_detected(env):
    """If someone edits the underlying audit log, the report stops matching it."""
    _seed(env)
    tr = env["tr"]
    report = tr.build_trace_report(TENANT, AGENT, audit_log_path=env["audit_path"])
    assert tr.verify_trace_report(report, audit_log_path=env["audit_path"])["ok"] is True

    # Tamper with the log the report cites.
    lines = open(env["audit_path"], encoding="utf-8").read().splitlines()
    doctored = [ln.replace('"entry_hash": "', '"entry_hash": "0') for ln in lines]
    with open(env["audit_path"], "w", encoding="utf-8") as f:
        f.write("\n".join(doctored) + "\n")

    result = tr.verify_trace_report(report, audit_log_path=env["audit_path"])
    assert result["ok"] is False
    assert "audit entry" in result["message"]

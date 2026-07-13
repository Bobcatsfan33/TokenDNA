"""Tests for the CrewAI callback adapter."""

from __future__ import annotations

import pytest

from tokendna_sdk.integrations.crewai import TokenDNACrewCallback
from tokendna_sdk.local import TokenDNALocalClient


def test_callback_requires_agent_id():
    with pytest.raises(ValueError):
        TokenDNACrewCallback(agent_id="")


def test_callback_call_records_tool_from_dict_step(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    cb = TokenDNACrewCallback(agent_id="crew-a", scope=["x"], client=client)
    cb({"tool": "search", "tool_input": {"q": "hi"}})
    events = client.read_events()
    bodies = [e["_body"].get("body", {}) for e in events]
    assert any(b.get("tool_name") == "search" for b in bodies)


def test_callback_ignores_string_thoughts(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    cb = TokenDNACrewCallback(agent_id="crew-a", client=client)
    cb("just a thought — not a tool call")
    # No tool events should have been emitted.
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert not any("tool_name" in b for b in bodies)


def test_callback_on_tool_start_then_end_emits_event(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    cb = TokenDNACrewCallback(agent_id="crew-a", client=client,
                                capture_args=True)
    cb.on_tool_start("search", tool_input={"q": "hi"})
    cb.on_tool_end("search", output="result", tool_input={"q": "hi"})
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    matching = [b for b in bodies if b.get("tool_name") == "search"]
    assert matching
    # duration_ms should have been populated by on_tool_end timing
    assert matching[0].get("duration_ms") is not None


def test_callback_on_finish_issues_attestation(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    cb = TokenDNACrewCallback(agent_id="crew-a", client=client)
    cb({"tool": "search"})
    cb.on_finish(result="done")
    events = client.read_events()
    assert any(e["_body"].get("type") == "attestation" for e in events)


def test_callback_unpacks_object_style_step(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    cb = TokenDNACrewCallback(agent_id="crew-a", client=client)

    class _Step:
        tool = "fetch"
        tool_input = {"url": "x"}
        result = "ok"

    cb(_Step())
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("tool_name") == "fetch" for b in bodies)

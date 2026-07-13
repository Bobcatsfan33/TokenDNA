"""Tests for the MCP proxy + secure_mcp_server decorator."""

from __future__ import annotations

import pytest

from tokendna_sdk.exceptions import TokenDNAVerificationError
from tokendna_sdk.integrations.mcp import TokenDNAMCPProxy, secure_mcp_server
from tokendna_sdk.local import TokenDNALocalClient


def test_proxy_requires_agent_id():
    with pytest.raises(ValueError):
        TokenDNAMCPProxy(agent_id="")


def test_handle_tool_call_records_event(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(agent_id="cd", scope=["fs:read"], client=client)
    result = proxy.handle_tool_call(
        {"name": "read_file", "arguments": {"path": "/etc/passwd"}},
        upstream=lambda req: f"content of {req['arguments']['path']}",
    )
    assert "content of" in result
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("tool_name") == "read_file" for b in bodies)


def test_handle_tool_call_without_upstream_returns_none(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(agent_id="cd", client=client)
    assert proxy.handle_tool_call({"name": "x", "arguments": {}}) is None


def test_deny_chain_flags_exfil_pattern(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(
        agent_id="cd", client=client, enforce=True,
        deny_chains=[["read_file", "send_email"]],
    )
    proxy.handle_tool_call({"name": "read_file", "arguments": {}},
                             upstream=lambda r: None)
    with pytest.raises(TokenDNAVerificationError):
        proxy.handle_tool_call({"name": "send_email", "arguments": {}},
                                 upstream=lambda r: None)


def test_deny_chain_advisory_mode_does_not_raise(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(
        agent_id="cd", client=client, enforce=False,
        deny_chains=[["read_file", "send_email"]],
    )
    proxy.handle_tool_call({"name": "read_file", "arguments": {}},
                             upstream=lambda r: None)
    # Should not raise even though the chain matches.
    proxy.handle_tool_call({"name": "send_email", "arguments": {}},
                             upstream=lambda r: "sent")
    # The flagged event should have the chain_match metadata. Two
    # events get emitted per call (pre-call + post-call duration);
    # at least one of them must carry the chain match.
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    send_events = [b for b in bodies if b.get("tool_name") == "send_email"]
    assert send_events
    assert any("chain_match" in (b.get("metadata") or {}) for b in send_events)


def test_deny_chain_respects_max_gap(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(
        agent_id="cd", client=client, enforce=True,
        deny_chains=[["read_file", "send_email"]],
        max_chain_gap=1,
    )
    # 2 unrelated calls between read_file and send_email — exceeds gap=1
    proxy.handle_tool_call({"name": "read_file"}, upstream=lambda r: None)
    proxy.handle_tool_call({"name": "process"}, upstream=lambda r: None)
    proxy.handle_tool_call({"name": "summarize"}, upstream=lambda r: None)
    # Now send_email should NOT trigger the deny chain.
    proxy.handle_tool_call({"name": "send_email"}, upstream=lambda r: None)


def test_finish_issues_attestation_and_resets_history(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(agent_id="cd-fin", client=client)
    proxy.handle_tool_call({"name": "read_file"}, upstream=lambda r: None)
    proxy.finish(metadata={"session": "demo"})
    events = client.read_events()
    assert any(e["_body"].get("type") == "attestation" for e in events)
    # New session — history reset.
    assert proxy._tool_calls == []


def test_secure_mcp_server_decorator_wraps_handler(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    @secure_mcp_server(agent_id="cd-decorated", client=client,
                        scope=["fs:read"])
    def handler(request):
        return f"handled {request['name']}"

    result = handler({"name": "read_file", "arguments": {}})
    assert result == "handled read_file"
    # The decorated function exposes its proxy.
    assert hasattr(handler, "tokendna_proxy")
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("tool_name") == "read_file" for b in bodies)


def test_secure_mcp_server_propagates_deny(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)

    @secure_mcp_server(
        agent_id="cd-deny", client=client, enforce=True,
        deny_chains=[["read_file", "send_email"]],
    )
    def handler(request):
        return "result"

    handler({"name": "read_file"})
    with pytest.raises(TokenDNAVerificationError):
        handler({"name": "send_email"})


def test_capture_args_off_by_default(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    proxy = TokenDNAMCPProxy(agent_id="cd-args", client=client)
    proxy.handle_tool_call(
        {"name": "leak", "arguments": {"secret": "pa$$w0rd"}},
        upstream=lambda r: None,
    )
    from tokendna_sdk.models import hash_args
    empty = hash_args(None)
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    leak_events = [b for b in bodies if b.get("tool_name") == "leak"]
    assert leak_events and leak_events[0]["tool_args_hash"] == empty

"""Tests for the LangChain middleware adapter.

LangChain is not installed in the SDK test env — we verify the
middleware works against its duck-typed base and exercises the hooks
correctly. Integration with a real LangChain agent is covered by the
examples directory.
"""

from __future__ import annotations

import pytest

from tokendna_sdk.exceptions import TokenDNAVerificationError
from tokendna_sdk.integrations.langchain import TokenDNAMiddleware
from tokendna_sdk.local import TokenDNALocalClient
from tokendna_sdk.models import PolicyVerdict


class _ToolCallStub:
    """Mirrors LangChain's ToolCall object shape."""
    def __init__(self, name, args=None, target=""):
        self.name = name
        self.args = args or {}
        self.target = target


class _ResponseStub:
    def __init__(self, model="gpt-4o", input_tokens=10, output_tokens=20):
        self.model = model
        self.usage_metadata = {"input_tokens": input_tokens,
                                "output_tokens": output_tokens}


def test_middleware_requires_agent_id():
    with pytest.raises(ValueError):
        TokenDNAMiddleware(agent_id="")


def test_middleware_wraps_tool_call_against_local_client(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAMiddleware(agent_id="agent-1", scope=["x"], client=client)

    handler_called = {"n": 0}

    def handler(request):
        handler_called["n"] += 1
        return {"result": "ok"}

    request = _ToolCallStub("search", args={"q": "hello"})
    result = mw.wrap_tool_call(request, handler)
    assert result == {"result": "ok"}
    assert handler_called["n"] == 1
    # Event landed in JSONL.
    events = client.read_events()
    bodies = [e["_body"].get("body") for e in events if isinstance(e["_body"].get("body"), dict)]
    assert any("tool_name" in b for b in bodies)


def test_middleware_wraps_model_call(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAMiddleware(agent_id="agent-1", client=client)

    response_stub = _ResponseStub(input_tokens=42, output_tokens=84)

    def handler(request):
        return response_stub

    mw.wrap_model_call({"model": "gpt-4o"}, handler)
    events = client.read_events()
    bodies = [e["_body"].get("body") for e in events]
    matching = [b for b in bodies if isinstance(b, dict) and b.get("prompt_tokens") == 42]
    assert matching, f"no ModelCallEvent recorded: {bodies}"
    assert matching[0]["completion_tokens"] == 84


def test_middleware_enforce_raises_on_deny():
    class _DenyClient:
        mode = "fake"
        emitter = None

        def post(self, *a, **kw): return {}
        def verify(self, *a, **kw):
            return PolicyVerdict(decision="deny", reason="scope:missing")
        def attest(self, *a, **kw): return None

    mw = TokenDNAMiddleware(agent_id="agent-1", scope=[],
                              client=_DenyClient(), enforce=True)

    def handler(_):
        raise AssertionError("handler should not have been called")

    with pytest.raises(TokenDNAVerificationError):
        mw.wrap_tool_call(_ToolCallStub("send_email"), handler)


def test_middleware_after_agent_issues_attestation(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAMiddleware(agent_id="agent-1", client=client)
    mw.wrap_tool_call(_ToolCallStub("search"), lambda r: "ok")
    mw.after_agent(state={"a": 1, "b": 2})
    events = client.read_events()
    # attestation events have ``type=attestation`` at the top of _body
    assert any(e["_body"].get("type") == "attestation" for e in events)


def test_middleware_after_agent_records_baseline_session(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAMiddleware(agent_id="agent-bl", client=client)
    for _ in range(2):
        mw.wrap_tool_call(_ToolCallStub("search"), lambda r: "ok")
    mw.after_agent(state={})
    baseline_path = tmp_tokendna_root / "baselines.json"
    assert baseline_path.exists()
    import json
    data = json.loads(baseline_path.read_text())
    assert "agent-bl" in data
    assert data["agent-bl"]["sessions_observed"] == 1


def test_middleware_extracts_token_counts_from_response_metadata(tmp_tokendna_root):
    client = TokenDNALocalClient(root=tmp_tokendna_root)
    mw = TokenDNAMiddleware(agent_id="agent-1", client=client)
    # Response with usage instead of usage_metadata.
    response = type("R", (), {"model": "claude-3", "usage": {
        "prompt_tokens": 33, "completion_tokens": 11,
    }})()
    mw.wrap_model_call({}, lambda r: response)
    bodies = [e["_body"].get("body", {}) for e in client.read_events()]
    assert any(b.get("prompt_tokens") == 33 for b in bodies)

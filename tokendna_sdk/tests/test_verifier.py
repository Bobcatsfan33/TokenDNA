"""Tests for the shared _core.Verifier helper."""

from __future__ import annotations

import pytest

from tokendna_sdk._core.verifier import Verifier
from tokendna_sdk.exceptions import TokenDNAVerificationError
from tokendna_sdk.local import TokenDNALocalClient
from tokendna_sdk.models import PolicyVerdict


class _FakeClient:
    """Minimal duck-typed client that records every call."""
    mode = "fake"
    emitter = None

    def __init__(self, verdict: PolicyVerdict | None = None,
                 raises: BaseException | None = None) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.verifies: list[dict] = []
        self.attests: list[tuple[str, list, dict | None]] = []
        self._verdict = verdict
        self._raises = raises

    def post(self, path, body):
        self.posts.append((path, body))
        return {"sent": True, "buffered": False}

    def verify(self, agent_id, action, *, target="", scope=None, score=0.0):
        if self._raises is not None:
            raise self._raises
        self.verifies.append({
            "agent_id": agent_id, "action": action, "target": target,
            "scope": list(scope or []), "score": score,
        })
        return self._verdict or PolicyVerdict(decision="allow")

    def attest(self, agent_id, hops, *, metadata=None):
        self.attests.append((agent_id, list(hops), metadata))
        from tokendna_sdk.models import Attestation
        return Attestation(receipt_id="rcpt-test", agent_id=agent_id, hops=hops,
                            metadata=metadata or {})


def test_record_tool_call_emits_event_and_pushes_hop():
    c = _FakeClient()
    v = Verifier(c, agent_id="a1", scope=["x"], framework="t")
    verdict = v.record_tool_call("search", args={"q": "hi"}, target="t1")
    assert verdict and verdict.allowed
    assert c.posts and c.posts[0][0] == "/api/uis/normalize"
    body = c.posts[0][1]
    assert body["agent_id"] == "a1"
    assert body["tool_name"] == "search"
    # arg values are hashed, not stored
    assert "q" not in body["tool_args_hash"]
    assert len(v.hops) == 1
    assert v.hops[0]["actor"] == "a1"
    assert c.verifies[0]["scope"] == ["x"]


def test_record_tool_call_enforce_raises_on_deny():
    c = _FakeClient(verdict=PolicyVerdict(decision="deny", reason="scope:missing"))
    v = Verifier(c, agent_id="a1", enforce=True)
    with pytest.raises(TokenDNAVerificationError):
        v.record_tool_call("send_email")


def test_record_tool_call_non_enforce_returns_verdict_without_raising():
    c = _FakeClient(verdict=PolicyVerdict(decision="deny", reason="scope:missing"))
    v = Verifier(c, agent_id="a1", enforce=False)
    verdict = v.record_tool_call("send_email")
    assert verdict.decision == "deny"
    assert not verdict.allowed


def test_record_tool_call_verify_exception_does_not_break_wedge():
    c = _FakeClient(raises=RuntimeError("verify broke"))
    v = Verifier(c, agent_id="a1", enforce=False)
    # Must not raise — the wedge contract is intact.
    verdict = v.record_tool_call("x")
    assert verdict is None
    assert c.posts  # event still emitted


def test_record_model_call_emits_event():
    c = _FakeClient()
    v = Verifier(c, agent_id="a1")
    v.record_model_call("gpt-4o", prompt_tokens=100, completion_tokens=20)
    assert c.posts
    body = c.posts[0][1]
    assert body["model"] == "gpt-4o"
    assert body["prompt_tokens"] == 100


def test_finish_attests_when_hops_present():
    c = _FakeClient()
    v = Verifier(c, agent_id="a1")
    v.record_tool_call("search")
    att = v.finish(metadata={"x": "y"})
    assert att is not None
    assert c.attests and c.attests[0][0] == "a1"
    assert c.attests[0][2] == {"x": "y"}


def test_finish_skips_when_no_hops():
    c = _FakeClient()
    v = Verifier(c, agent_id="a1")
    assert v.finish() is None
    assert not c.attests


def test_finish_swallows_attest_exception():
    class _BoomClient(_FakeClient):
        def attest(self, *a, **kw):
            raise RuntimeError("server down")

    c = _BoomClient()
    v = Verifier(c, agent_id="a1")
    v.record_tool_call("x")
    # Must not raise.
    result = v.finish()
    assert result is None


def test_verifier_session_id_is_stable_across_calls():
    c = _FakeClient()
    v = Verifier(c, agent_id="a1")
    v.record_tool_call("x")
    v.record_tool_call("y")
    s1 = c.posts[0][1]["session_id"]
    s2 = c.posts[1][1]["session_id"]
    assert s1 == s2


def test_verifier_works_with_local_client(tmp_tokendna_root):
    local = TokenDNALocalClient(root=tmp_tokendna_root)
    v = Verifier(local, agent_id="a1", framework="local-test")
    v.record_tool_call("search", target="example.com")
    events = local.read_events()
    assert any("tool_name" in e["_body"].get("body", {}) for e in events) or events

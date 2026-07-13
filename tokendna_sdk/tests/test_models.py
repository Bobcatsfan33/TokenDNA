"""Tests for tokendna_sdk.models."""

from __future__ import annotations

import re

from tokendna_sdk.models import (
    AgentIdentity,
    Attestation,
    BehavioralBaseline,
    ModelCallEvent,
    PolicyVerdict,
    ToolCallEvent,
    hash_args,
    new_session_id,
    utc_now,
)


ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")


def test_utc_now_is_byte_stable_iso8601():
    ts = utc_now()
    assert ISO_PATTERN.match(ts), f"unexpected timestamp shape: {ts!r}"


def test_hash_args_empty_and_stable():
    # Empty / None hash to the same canonical empty-dict hash.
    h_empty = hash_args(None)
    assert h_empty == hash_args({})
    # Stable across key order.
    a = hash_args({"a": 1, "b": "two"})
    b = hash_args({"b": "two", "a": 1})
    assert a == b
    # Different content => different hash.
    assert hash_args({"a": 1}) != hash_args({"a": 2})


def test_hash_args_handles_non_json_values():
    class Weird:
        def __repr__(self) -> str:
            return "Weird()"

    # Should not raise — falls back via default=repr.
    h = hash_args({"x": Weird()})
    assert isinstance(h, str) and len(h) == 64


def test_new_session_id_prefix_and_uniqueness():
    a = new_session_id()
    b = new_session_id()
    assert a.startswith("sess-") and b.startswith("sess-")
    assert a != b


def test_agent_identity_to_dict_roundtrip():
    a = AgentIdentity(agent_id="r1", framework="langchain", version="1.0.0",
                      metadata={"k": "v"})
    d = a.to_dict()
    assert d["agent_id"] == "r1"
    assert d["framework"] == "langchain"
    assert d["metadata"] == {"k": "v"}


def test_tool_call_event_defaults_populated():
    e = ToolCallEvent(agent_id="r1", tool_name="search",
                      tool_args_hash=hash_args({"q": "x"}))
    assert ISO_PATTERN.match(e.timestamp)
    assert e.session_id.startswith("sess-")
    assert e.duration_ms is None


def test_model_call_event_to_dict_carries_metadata():
    e = ModelCallEvent(agent_id="r1", model="gpt-4", prompt_tokens=100,
                       completion_tokens=20, metadata={"trace": "abc"})
    d = e.to_dict()
    assert d["prompt_tokens"] == 100
    assert d["metadata"]["trace"] == "abc"


def test_policy_verdict_allowed_property():
    allow = PolicyVerdict(decision="allow")
    deny = PolicyVerdict(decision="deny", reason="scope:missing")
    warn = PolicyVerdict(decision="warn")
    assert allow.allowed
    assert not deny.allowed
    assert not warn.allowed
    assert deny.to_dict()["reason"] == "scope:missing"


def test_attestation_defaults_have_receipt_and_timestamp():
    att = Attestation(receipt_id="r-1", agent_id="agent",
                       hops=[{"actor": "a", "action": "x"}])
    assert ISO_PATTERN.match(att.issued_at)
    d = att.to_dict()
    assert d["receipt_id"] == "r-1"
    assert d["hops"][0]["actor"] == "a"


def test_behavioral_baseline_is_warm():
    cold = BehavioralBaseline(agent_id="a", sessions_observed=3)
    warm = BehavioralBaseline(agent_id="a", sessions_observed=5)
    assert not cold.is_warm()
    assert warm.is_warm()

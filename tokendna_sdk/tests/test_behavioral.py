"""Tests for the behavioral baseline + scoring."""

from __future__ import annotations

from tokendna_sdk._core.behavioral import (
    BaselineStore,
    WARMUP_SESSIONS,
    detect_chain,
    score_session,
)
from tokendna_sdk.models import BehavioralBaseline


def test_cold_baseline_returns_zero_score():
    b = BehavioralBaseline(agent_id="a", sessions_observed=2)
    assert score_session(b, ["search", "fetch", "summarize"]) == 0.0


def test_warm_baseline_with_normal_session_returns_zero():
    b = BehavioralBaseline(
        agent_id="a",
        sessions_observed=10,
        tool_call_mean=5.0,
        tool_call_stddev=1.0,
        common_tools=["search", "fetch", "summarize"],
        common_sequences=[
            ["search", "fetch"],
            ["fetch", "summarize"],
            ["summarize", "search"],
        ],
    )
    # Length 5 (= mean), within vocabulary, every transition is in the
    # sequence vocab → 0.0.
    assert score_session(b, ["search", "fetch", "summarize", "search", "fetch"]) == 0.0


def test_frequency_anomaly_raises_score():
    b = BehavioralBaseline(
        agent_id="a",
        sessions_observed=10,
        tool_call_mean=3.0,
        tool_call_stddev=1.0,
        common_tools=["search"],
        common_sequences=[["search", "search"]],
    )
    score = score_session(b, ["search"] * 8)  # z ≈ 5 → ramped to 1.0
    assert score > 0.9


def test_vocabulary_anomaly_raises_score():
    b = BehavioralBaseline(
        agent_id="a", sessions_observed=10,
        tool_call_mean=3.0, tool_call_stddev=0.5,
        common_tools=["search", "fetch"],
        common_sequences=[["search", "fetch"]],
    )
    # 'send_email' is unknown → vocab signal kicks in
    score = score_session(b, ["search", "fetch", "send_email"])
    assert score > 0.3


def test_sequence_anomaly_raises_score():
    b = BehavioralBaseline(
        agent_id="a", sessions_observed=10,
        tool_call_mean=3.0, tool_call_stddev=0.5,
        common_tools=["search", "fetch", "summarize"],
        common_sequences=[["search", "fetch"]],
    )
    # "fetch → summarize" wasn't in the sequence vocabulary
    score = score_session(b, ["search", "fetch", "summarize"])
    assert score > 0.0


def test_baseline_store_persists_across_instances(tmp_path):
    p = tmp_path / "b.json"
    s1 = BaselineStore(str(p))
    s1.record_session("agent-1", ["search", "fetch"])
    s1.record_session("agent-1", ["search", "fetch", "summarize"])

    s2 = BaselineStore(str(p))
    b = s2.get("agent-1")
    assert b.sessions_observed == 2
    assert "fetch" in b.common_tools
    assert ["search", "fetch"] in b.common_sequences


def test_baseline_store_warmup_threshold(tmp_path):
    s = BaselineStore(str(tmp_path / "b.json"))
    for _ in range(WARMUP_SESSIONS - 1):
        s.record_session("a", ["search"])
    assert not s.get("a").is_warm()
    s.record_session("a", ["search"])
    assert s.get("a").is_warm()


def test_baseline_store_rolling_window(tmp_path):
    s = BaselineStore(str(tmp_path / "b.json"), window=5)
    for i in range(20):
        s.record_session("a", ["x"] * (i + 1))
    b = s.get("a")
    # We capped at 5 sessions; mean reflects only the last 5 (lengths 16-20).
    assert b.sessions_observed == 5
    assert 16 <= b.tool_call_mean <= 20


def test_baseline_store_unknown_agent_returns_empty():
    s = BaselineStore("/tmp/nonexistent-tdna-baselines.json")
    b = s.get("ghost")
    assert b.sessions_observed == 0
    assert not b.is_warm()


def test_detect_chain_basic_match():
    calls = ["read_file", "process", "send_email"]
    assert detect_chain(calls, ["read_file", "send_email"]) is True


def test_detect_chain_respects_max_gap():
    calls = ["read_file"] + ["other"] * 5 + ["send_email"]
    # 5 unrelated calls between read_file and send_email — exceeds default max_gap=3
    assert detect_chain(calls, ["read_file", "send_email"]) is False
    # Loosening the gap matches.
    assert detect_chain(calls, ["read_file", "send_email"], max_gap=10) is True


def test_detect_chain_empty_pattern_is_trivially_true():
    assert detect_chain(["x"], []) is True


def test_detect_chain_pattern_longer_than_calls_is_false():
    assert detect_chain(["a"], ["a", "b"]) is False

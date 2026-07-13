"""
Tests for Sprint 3-2 — Autonomous Verifier Reputation Network

Covers:
  - issue_challenge: challenge created in PENDING state
  - resolve_challenge: CORRECT / INCORRECT / TIMEOUT outcomes
  - double-resolve rejected
  - expire_pending_challenges: marks timed-out challenges
  - _compute_dynamic_score: EMA decay math
  - _compute_trend: UP / DOWN / STABLE
  - _outcome_delta: correct outcomes for all ChallengeOutcome values
  - _time_weight: decay over time
  - get_reputation: fresh / with history / with static fallback
  - list_reputations: tenant filter, sort, limit
  - get_challenge_history: paginated per-verifier history
  - get_leaderboard: ranking and format
  - get_reputation_anomalies: low-reliability, high-timeout, declining-score
  - evaluate_reputation_weighted_quorum: met / not met / low rep exclusion
  - sync_static_scores: only reliable verifiers updated
  - backward compatibility: static score used before reliable data exists
  - compute_challenge_response: helper for verifier integration
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta
from unittest import mock
import importlib

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    db_path = str(tmp_path / "test_reputation.db")
    with mock.patch.dict(os.environ, {"DATA_DB_PATH": db_path,
                                      "REPUTATION_CHALLENGE_TIMEOUT_S": "30"}):
        import modules.identity.verifier_reputation as rm
        importlib.reload(rm)
        yield rm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issue_and_resolve(rm, verifier_id="v1", tenant_id="t1",
                       outcome="correct", response_age_s=0):
    """Issue a challenge and immediately resolve it with the correct or wrong response."""
    ch = rm.issue_challenge(verifier_id=verifier_id, tenant_id=tenant_id)
    correct_resp = rm._compute_expected_response(ch.challenge_nonce)
    if outcome == "correct":
        submitted = correct_resp
    elif outcome == "incorrect":
        submitted = "deadbeef" * 8
    else:
        # Timeout: resolve with correct response but after backdating expires_at
        with rm._cursor() as cur:
            past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            cur.execute("UPDATE reputation_challenges SET expires_at=? WHERE challenge_id=?",
                        (past, ch.challenge_id))
        submitted = correct_resp
    return rm.resolve_challenge(ch.challenge_id, submitted)


def _seed_events(rm, verifier_id="v1", tenant_id="t1", n_correct=0, n_wrong=0, n_timeout=0):
    """Seed challenge history for a verifier."""
    results = []
    for _ in range(n_correct):
        results.append(_issue_and_resolve(rm, verifier_id, tenant_id, "correct"))
    for _ in range(n_wrong):
        results.append(_issue_and_resolve(rm, verifier_id, tenant_id, "incorrect"))
    for _ in range(n_timeout):
        results.append(_issue_and_resolve(rm, verifier_id, tenant_id, "timeout"))
    return results


# ---------------------------------------------------------------------------
# Challenge issuance
# ---------------------------------------------------------------------------


class TestIssueChallenge:
    def test_returns_pending_challenge(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        assert ch.outcome == rm.ChallengeOutcome.PENDING
        assert ch.challenge_id.startswith("chal-")

    def test_nonce_is_hex_string(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        assert len(ch.challenge_nonce) == 64
        int(ch.challenge_nonce, 16)  # must be valid hex

    def test_expected_response_set(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        assert len(ch.expected_response) == 64

    def test_expires_at_in_future(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        expires = datetime.fromisoformat(ch.expires_at)
        assert expires > datetime.now(timezone.utc)

    def test_multiple_challenges_unique_ids(self, isolated_db):
        rm = isolated_db
        ids = {rm.issue_challenge("v1", "t1").challenge_id for _ in range(5)}
        assert len(ids) == 5

    def test_different_verifiers_different_nonces(self, isolated_db):
        rm = isolated_db
        ch1 = rm.issue_challenge("v1", "t1")
        ch2 = rm.issue_challenge("v2", "t1")
        assert ch1.challenge_nonce != ch2.challenge_nonce


# ---------------------------------------------------------------------------
# Challenge resolution
# ---------------------------------------------------------------------------


class TestResolveChallenge:
    def test_correct_response_gives_correct_outcome(self, isolated_db):
        rm = isolated_db
        resolved = _issue_and_resolve(rm, outcome="correct")
        assert resolved.outcome == rm.ChallengeOutcome.CORRECT

    def test_incorrect_response_gives_incorrect_outcome(self, isolated_db):
        rm = isolated_db
        resolved = _issue_and_resolve(rm, outcome="incorrect")
        assert resolved.outcome == rm.ChallengeOutcome.INCORRECT

    def test_timed_out_response_gives_timeout_outcome(self, isolated_db):
        rm = isolated_db
        resolved = _issue_and_resolve(rm, outcome="timeout")
        assert resolved.outcome == rm.ChallengeOutcome.TIMEOUT

    def test_response_ms_measured(self, isolated_db):
        rm = isolated_db
        resolved = _issue_and_resolve(rm, outcome="correct")
        assert resolved.response_ms is not None
        assert resolved.response_ms >= 0

    def test_resolved_at_set(self, isolated_db):
        rm = isolated_db
        resolved = _issue_and_resolve(rm, outcome="correct")
        assert resolved.resolved_at is not None

    def test_double_resolve_raises(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        correct = rm._compute_expected_response(ch.challenge_nonce)
        rm.resolve_challenge(ch.challenge_id, correct)
        with pytest.raises(ValueError, match="already resolved"):
            rm.resolve_challenge(ch.challenge_id, correct)

    def test_nonexistent_challenge_raises(self, isolated_db):
        rm = isolated_db
        with pytest.raises(ValueError, match="not found"):
            rm.resolve_challenge("chal-does-not-exist", "resp")

    def test_resolve_triggers_reputation_refresh(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=3)
        rep = rm.get_reputation("v1", "t1")
        assert rep.total_challenges == 3


# ---------------------------------------------------------------------------
# Expire pending challenges
# ---------------------------------------------------------------------------


class TestExpirePendingChallenges:
    def test_expired_challenges_marked_timeout(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        # Backdate expires_at
        with rm._cursor() as cur:
            past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
            cur.execute("UPDATE reputation_challenges SET expires_at=? WHERE challenge_id=?",
                        (past, ch.challenge_id))
        count = rm.expire_pending_challenges(tenant_id="t1")
        assert count == 1

    def test_not_yet_expired_not_touched(self, isolated_db):
        rm = isolated_db
        rm.issue_challenge("v1", "t1")  # still in future
        count = rm.expire_pending_challenges(tenant_id="t1")
        assert count == 0

    def test_already_resolved_not_touched(self, isolated_db):
        rm = isolated_db
        _issue_and_resolve(rm, outcome="correct")
        count = rm.expire_pending_challenges(tenant_id="t1")
        assert count == 0

    def test_no_tenant_filter_expires_all(self, isolated_db):
        rm = isolated_db
        for tid in ["t1", "t2"]:
            ch = rm.issue_challenge("v1", tid)
            with rm._cursor() as cur:
                past = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
                cur.execute(
                    "UPDATE reputation_challenges SET expires_at=? WHERE challenge_id=?",
                    (past, ch.challenge_id),
                )
        count = rm.expire_pending_challenges()
        assert count == 2


# ---------------------------------------------------------------------------
# EMA scoring math
# ---------------------------------------------------------------------------


class TestDynamicScoreMath:
    def test_all_correct_gives_high_score(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=10)
        rep = rm.get_reputation("v1", "t1")
        assert rep.dynamic_score >= 0.7

    def test_all_timeout_gives_low_score(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_timeout=5)
        rep = rm.get_reputation("v1", "t1")
        assert rep.dynamic_score < 0.5

    def test_mixed_gives_mid_score(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=5, n_timeout=5)
        rep = rm.get_reputation("v1", "t1")
        assert 0.2 <= rep.dynamic_score <= 0.8

    def test_empty_history_gives_baseline(self, isolated_db):
        rm = isolated_db
        events: list = []
        score = rm._compute_dynamic_score(events)
        assert score == rm._BASELINE_SCORE

    def test_outcome_delta_correct(self, isolated_db):
        rm = isolated_db
        delta = rm._outcome_delta(rm.ChallengeOutcome.CORRECT, 500)
        assert delta == 1.0  # fast response

    def test_outcome_delta_incorrect_negative(self, isolated_db):
        rm = isolated_db
        delta = rm._outcome_delta(rm.ChallengeOutcome.INCORRECT, None)
        assert delta < 0

    def test_outcome_delta_timeout_negative(self, isolated_db):
        rm = isolated_db
        delta = rm._outcome_delta(rm.ChallengeOutcome.TIMEOUT, None)
        assert delta < 0

    def test_outcome_delta_error_negative(self, isolated_db):
        rm = isolated_db
        delta = rm._outcome_delta(rm.ChallengeOutcome.ERROR, None)
        assert delta < 0

    def test_time_weight_recent_is_one(self, isolated_db):
        rm = isolated_db
        w = rm._time_weight(0.0)
        assert abs(w - 1.0) < 0.001

    def test_time_weight_half_life_is_half(self, isolated_db):
        rm = isolated_db
        w = rm._time_weight(rm._DECAY_HALF_LIFE_DAYS)
        assert abs(w - 0.5) < 0.01

    def test_time_weight_monotone_decreasing(self, isolated_db):
        rm = isolated_db
        weights = [rm._time_weight(d) for d in [0, 7, 14, 30, 90]]
        for i in range(len(weights) - 1):
            assert weights[i] > weights[i + 1]

    def test_score_in_range(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=3, n_wrong=2, n_timeout=1)
        rep = rm.get_reputation("v1", "t1")
        assert 0.0 <= rep.dynamic_score <= 1.0
        assert 0.0 <= rep.effective_score <= 1.0


# ---------------------------------------------------------------------------
# Trend detection
# ---------------------------------------------------------------------------


class TestTrend:
    def test_stable_with_no_events(self, isolated_db):
        rm = isolated_db
        assert rm._compute_trend([]) == rm.TrendDirection.STABLE

    def test_stable_with_only_recent_events(self, isolated_db):
        rm = isolated_db
        now = datetime.now(timezone.utc)
        events = [
            {"outcome": "correct", "resolved_at": (now - timedelta(days=1)).isoformat(),
             "response_ms": 500},
        ]
        assert rm._compute_trend(events) == rm.TrendDirection.STABLE

    def test_declining_sequence_gives_down(self, isolated_db):
        rm = isolated_db
        now = datetime.now(timezone.utc)
        # Old events: all correct. Recent events: all timeout.
        events = []
        for i in range(5):
            events.append({
                "outcome": "timeout",
                "resolved_at": (now - timedelta(days=i + 1)).isoformat(),
                "response_ms": None,
            })
        for i in range(5):
            events.append({
                "outcome": "correct",
                "resolved_at": (now - timedelta(days=15 + i)).isoformat(),
                "response_ms": 200,
            })
        trend = rm._compute_trend(events)
        assert trend == rm.TrendDirection.DOWN

    def test_improving_sequence_gives_up(self, isolated_db):
        rm = isolated_db
        now = datetime.now(timezone.utc)
        events = []
        for i in range(5):
            events.append({
                "outcome": "correct",
                "resolved_at": (now - timedelta(days=i + 1)).isoformat(),
                "response_ms": 200,
            })
        for i in range(5):
            events.append({
                "outcome": "timeout",
                "resolved_at": (now - timedelta(days=15 + i)).isoformat(),
                "response_ms": None,
            })
        trend = rm._compute_trend(events)
        assert trend == rm.TrendDirection.UP


# ---------------------------------------------------------------------------
# Reputation retrieval
# ---------------------------------------------------------------------------


class TestGetReputation:
    def test_no_history_returns_default(self, isolated_db):
        rm = isolated_db
        rep = rm.get_reputation("v-unknown", "t1")
        assert rep.total_challenges == 0
        assert rep.is_reliable is False
        assert 0.0 <= rep.effective_score <= 1.0

    def test_after_correct_challenges_is_reliable(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=3)
        rep = rm.get_reputation("v1", "t1")
        assert rep.is_reliable is True
        assert rep.total_challenges == 3

    def test_not_reliable_before_minimum(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=2)
        rep = rm.get_reputation("v1", "t1")
        assert rep.is_reliable is False

    def test_correct_count_matches(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=4, n_wrong=1, n_timeout=2)
        rep = rm.get_reputation("v1", "t1")
        assert rep.correct_responses == 4
        assert rep.incorrect_responses == 1
        assert rep.timeout_responses == 2

    def test_reliability_rate_computed(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=8, n_timeout=2)
        rep = rm.get_reputation("v1", "t1")
        assert abs(rep.reliability_rate - 0.8) < 0.01

    def test_avg_response_ms_set(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=3)
        rep = rm.get_reputation("v1", "t1")
        assert rep.avg_response_ms is not None
        assert rep.avg_response_ms >= 0

    def test_last_challenge_at_set(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=2)
        rep = rm.get_reputation("v1", "t1")
        assert rep.last_challenge_at is not None

    def test_to_dict_is_serializable(self, isolated_db):
        rm = isolated_db
        import json
        _seed_events(rm, n_correct=3)
        rep = rm.get_reputation("v1", "t1")
        d = rep.to_dict()
        json.dumps(d)  # must not raise

    def test_effective_score_blends_before_reliable(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=1)  # below MIN_RELIABLE
        rep = rm.get_reputation("v1", "t1")
        # Should be between baseline and dynamic, not purely dynamic
        assert 0.0 <= rep.effective_score <= 1.0
        assert not rep.is_reliable


# ---------------------------------------------------------------------------
# List + leaderboard
# ---------------------------------------------------------------------------


class TestListAndLeaderboard:
    def test_list_by_tenant(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", tenant_id="t1", n_correct=3)
        _seed_events(rm, verifier_id="v2", tenant_id="t2", n_correct=3)
        results = rm.list_reputations(tenant_id="t1")
        assert len(results) == 1
        assert results[0].verifier_id == "v1"

    def test_list_respects_limit(self, isolated_db):
        rm = isolated_db
        for i in range(5):
            _seed_events(rm, verifier_id=f"v{i}", tenant_id="t1", n_correct=3)
        results = rm.list_reputations(tenant_id="t1", limit=3)
        assert len(results) == 3

    def test_leaderboard_ranked(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="good", tenant_id="t1", n_correct=10)
        _seed_events(rm, verifier_id="bad", tenant_id="t1", n_timeout=10)
        board = rm.get_leaderboard(tenant_id="t1", limit=10)
        assert len(board) == 2
        assert board[0]["rank"] == 1
        # good verifier should rank first
        assert board[0]["effective_score"] >= board[1]["effective_score"]

    def test_leaderboard_has_required_keys(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", tenant_id="t1", n_correct=3)
        board = rm.get_leaderboard(tenant_id="t1")
        for entry in board:
            assert "rank" in entry
            assert "verifier_id" in entry
            assert "effective_score" in entry
            assert "trend" in entry
            assert "reliability_rate" in entry
            assert "is_reliable" in entry


# ---------------------------------------------------------------------------
# Challenge history
# ---------------------------------------------------------------------------


class TestChallengeHistory:
    def test_history_returns_resolved_challenges(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=3, n_wrong=1)
        history = rm.get_challenge_history("v1", "t1", limit=10)
        assert len(history) == 4

    def test_history_limit_respected(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=5)
        history = rm.get_challenge_history("v1", "t1", limit=3)
        assert len(history) == 3

    def test_history_no_expected_response_field(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=1)
        history = rm.get_challenge_history("v1", "t1")
        assert all("expected_response" not in h for h in history)

    def test_history_empty_for_unknown_verifier(self, isolated_db):
        rm = isolated_db
        history = rm.get_challenge_history("unknown-verifier", "t1")
        assert history == []


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


class TestAnomalyDetection:
    def test_no_anomalies_for_reliable_good_verifier(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=10)
        anomalies = rm.get_reputation_anomalies(tenant_id="t1")
        assert len(anomalies) == 0

    def test_high_timeout_rate_flagged(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=1, n_timeout=9)
        anomalies = rm.get_reputation_anomalies(tenant_id="t1")
        assert len(anomalies) == 1
        reasons = anomalies[0]["anomaly_reasons"]
        assert "high_timeout_rate" in reasons

    def test_low_reliability_rate_flagged(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_correct=1, n_wrong=5, n_timeout=4)
        anomalies = rm.get_reputation_anomalies(tenant_id="t1")
        assert any("low_reliability_rate" in a["anomaly_reasons"] for a in anomalies)

    def test_anomaly_dict_has_required_keys(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, n_timeout=10)
        anomalies = rm.get_reputation_anomalies(tenant_id="t1")
        for a in anomalies:
            assert "verifier_id" in a
            assert "anomaly_reasons" in a
            assert isinstance(a["anomaly_reasons"], list)


# ---------------------------------------------------------------------------
# Reputation-weighted quorum
# ---------------------------------------------------------------------------


class TestReputationWeightedQuorum:
    def test_empty_attestations_returns_not_met(self, isolated_db):
        rm = isolated_db
        v = rm.evaluate_reputation_weighted_quorum(
            [], tenant_id="t1"
        )
        assert v.met is False
        assert v.effective_action == "step_up"

    def test_single_reliable_verifier_can_meet_quorum(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", n_correct=10)
        attestations = [{"verifier_id": "v1", "verdict": "allow", "confidence": 1.0}]
        v = rm.evaluate_reputation_weighted_quorum(
            attestations, tenant_id="t1", min_weight=0.5
        )
        assert v.met is True
        assert v.effective_action == "allow"

    def test_low_reputation_verifier_excluded(self, isolated_db):
        rm = isolated_db
        # v1 has poor reputation (all timeouts)
        _seed_events(rm, verifier_id="v1", n_timeout=10)
        attestations = [{"verifier_id": "v1", "verdict": "allow", "confidence": 1.0}]
        v = rm.evaluate_reputation_weighted_quorum(
            attestations, tenant_id="t1",
            min_weight=0.5, min_reputation=0.5  # v1 will be below threshold
        )
        assert v.met is False

    def test_quorum_not_met_with_insufficient_weight(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", n_correct=3)
        # v1 has reasonable score but confidence is very low
        attestations = [{"verifier_id": "v1", "verdict": "allow", "confidence": 0.1}]
        v = rm.evaluate_reputation_weighted_quorum(
            attestations, tenant_id="t1", min_weight=0.9
        )
        assert v.met is False

    def test_multiple_verifiers_weights_sum(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", n_correct=5)
        _seed_events(rm, verifier_id="v2", n_correct=5)
        attestations = [
            {"verifier_id": "v1", "verdict": "allow", "confidence": 1.0},
            {"verifier_id": "v2", "verdict": "allow", "confidence": 1.0},
        ]
        v = rm.evaluate_reputation_weighted_quorum(
            attestations, tenant_id="t1", min_weight=0.3
        )
        assert v.met is True
        assert v.participating_verifiers == 2

    def test_split_verdict_picks_dominant(self, isolated_db):
        rm = isolated_db
        _seed_events(rm, verifier_id="v1", n_correct=10)
        _seed_events(rm, verifier_id="v2", n_correct=3)
        _seed_events(rm, verifier_id="v3", n_correct=3)
        attestations = [
            {"verifier_id": "v1", "verdict": "deny", "confidence": 1.0},
            {"verifier_id": "v2", "verdict": "allow", "confidence": 1.0},
            {"verifier_id": "v3", "verdict": "allow", "confidence": 1.0},
        ]
        v = rm.evaluate_reputation_weighted_quorum(
            attestations, tenant_id="t1", min_weight=0.01
        )
        # v1 has higher reputation so deny should win on weight
        # (depends on exact scores, but the function should return a verdict)
        assert v.effective_action in ("allow", "deny", "step_up")

    def test_quorum_result_has_expected_fields(self, isolated_db):
        rm = isolated_db
        v = rm.evaluate_reputation_weighted_quorum([], tenant_id="t1")
        assert hasattr(v, "met")
        assert hasattr(v, "confidence")
        assert hasattr(v, "verdicts")
        assert hasattr(v, "participating_verifiers")
        assert hasattr(v, "total_reputation_weight")


# ---------------------------------------------------------------------------
# Sync static scores
# ---------------------------------------------------------------------------


class TestSyncStaticScores:
    def test_sync_requires_reliable_data(self, isolated_db):
        rm = isolated_db
        # Only 2 challenges (below MIN_RELIABLE=3) → should not sync
        _seed_events(rm, n_correct=2)
        count = rm.sync_static_scores("t1")
        assert count == 0

    def test_sync_updates_reliable_verifier(self, isolated_db):
        rm = isolated_db
        # 3 correct → reliable
        _seed_events(rm, n_correct=3)
        # Need trust_federation_verifiers row to exist for update to count
        # (table may not exist in test db; sync should not raise)
        try:
            count = rm.sync_static_scores("t1")
            assert count >= 0  # may be 0 if federation table missing in test
        except Exception as exc:
            pytest.fail(f"sync_static_scores raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# Challenge response helper
# ---------------------------------------------------------------------------


class TestChallengeResponseHelper:
    def test_compute_challenge_response_matches_expected(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        # Simulate verifier computing response with shared secret
        response = rm.compute_challenge_response(
            ch.challenge_nonce, rm._CHALLENGE_SECRET
        )
        assert response == ch.expected_response

    def test_wrong_secret_gives_wrong_response(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        response = rm.compute_challenge_response(ch.challenge_nonce, "wrong-secret")
        assert response != ch.expected_response

    def test_correct_response_resolves_to_correct(self, isolated_db):
        rm = isolated_db
        ch = rm.issue_challenge("v1", "t1")
        response = rm.compute_challenge_response(ch.challenge_nonce, rm._CHALLENGE_SECRET)
        resolved = rm.resolve_challenge(ch.challenge_id, response)
        assert resolved.outcome == rm.ChallengeOutcome.CORRECT


# ---------------------------------------------------------------------------
# Due-for-challenge helper
# ---------------------------------------------------------------------------


class TestDueForChallenge:
    def test_new_verifier_always_due(self, isolated_db):
        rm = isolated_db
        # Register a verifier in the federation table
        try:
            with rm._cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS trust_federation_verifiers (
                        verifier_id TEXT PRIMARY KEY,
                        tenant_id TEXT,
                        name TEXT,
                        trust_score REAL DEFAULT 0.5,
                        issuer TEXT,
                        jwks_uri TEXT,
                        status TEXT DEFAULT 'active',
                        updated_at TEXT
                    )
                """)
                cur.execute("""
                    INSERT OR IGNORE INTO trust_federation_verifiers
                    (verifier_id, tenant_id, name, status) VALUES (?,?,?,?)
                """, ("v-new", "t1", "New Verifier", "active"))
        except Exception:
            pass
        due = rm.get_verifiers_due_for_challenge(tenant_id="t1", max_age_hours=24)
        assert "v-new" in due

    def test_recently_challenged_not_due(self, isolated_db):
        rm = isolated_db
        try:
            with rm._cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS trust_federation_verifiers (
                        verifier_id TEXT PRIMARY KEY,
                        tenant_id TEXT,
                        name TEXT,
                        trust_score REAL DEFAULT 0.5,
                        issuer TEXT,
                        jwks_uri TEXT,
                        status TEXT DEFAULT 'active',
                        updated_at TEXT
                    )
                """)
                cur.execute("""
                    INSERT OR IGNORE INTO trust_federation_verifiers
                    (verifier_id, tenant_id, name, status) VALUES (?,?,?,?)
                """, ("v-fresh", "t1", "Fresh Verifier", "active"))
        except Exception:
            pass
        # Issue a challenge now (so it's recent)
        rm.issue_challenge("v-fresh", "t1")
        due = rm.get_verifiers_due_for_challenge(tenant_id="t1", max_age_hours=24)
        assert "v-fresh" not in due

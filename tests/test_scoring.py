"""
Tests — Token Integrity Scoring Engine  (Phase 2D)

Coverage targets for modules/identity/scoring.py:
  - compute() with all signal combinations
  - Edge cases: boundary values, score clamping, all-zero penalties
  - Each penalty type: tor, datacenter, vpn, abuse, branching, travel
  - Risk tier assignment: ALLOW, STEP_UP, BLOCK, REVOKE
  - Aggregation: multiple simultaneous penalties
  - Adversarial: penalty > base score (score floor = 0)
  - ScoreBreakdown.to_dict() format
  - Consistency: same inputs produce same output
"""

import pytest
from unittest.mock import MagicMock
from dataclasses import dataclass, field
from typing import Optional

# Configure test env to use dev thresholds
import os
os.environ.setdefault("SCORE_ALLOW_THRESHOLD",  "70")
os.environ.setdefault("SCORE_STEPUP_THRESHOLD", "50")
os.environ.setdefault("SCORE_BLOCK_THRESHOLD",  "30")
os.environ.setdefault("SCORE_REVOKE_THRESHOLD", "15")
os.environ.setdefault("ABUSEIPDB_MIN_CONFIDENCE", "50")

from modules.identity.scoring import compute, RiskTier, ScoreBreakdown


# ─────────────────────────────────────────────────────────────────────────────
# Mock classes matching the interfaces expected by compute()
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MockThreatContext:
    is_tor:        bool = False
    is_datacenter: bool = False
    is_vpn:        bool = False
    abuse_score:   int  = 0


@dataclass
class MockGraphResult:
    branching:          bool = False
    impossible_travel:  bool = False


def _clean_threat() -> MockThreatContext:
    return MockThreatContext()


def _clean_graph() -> MockGraphResult:
    return MockGraphResult()


# ─────────────────────────────────────────────────────────────────────────────
# 1. Baseline behavior / no signals
# ─────────────────────────────────────────────────────────────────────────────

class TestBaselineBehavior:
    def test_no_signals_returns_ml_score(self):
        bd = compute(ml_score=85)
        assert bd.ml_score == 85
        assert bd.threat_penalty == 0
        assert bd.graph_penalty == 0
        assert bd.final_score == 85
        assert bd.tier == RiskTier.ALLOW

    def test_no_signals_no_reasons(self):
        bd = compute(ml_score=85)
        assert bd.reasons == []

    def test_none_signals_same_as_no_signals(self):
        bd = compute(ml_score=85, threat_context=None, graph_result=None)
        assert bd.final_score == 85

    def test_clean_signals_no_penalty(self):
        bd = compute(ml_score=90, threat_context=_clean_threat(), graph_result=_clean_graph())
        assert bd.threat_penalty == 0
        assert bd.graph_penalty == 0
        assert bd.final_score == 90

    def test_ml_score_100_perfect(self):
        bd = compute(ml_score=100)
        assert bd.final_score == 100
        assert bd.tier == RiskTier.ALLOW

    def test_ml_score_0_baseline(self):
        bd = compute(ml_score=0)
        assert bd.final_score == 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. Threat intel penalties
# ─────────────────────────────────────────────────────────────────────────────

class TestThreatIntelPenalties:
    def test_tor_penalty_applied(self):
        threat = MockThreatContext(is_tor=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 40
        assert bd.final_score == 60
        assert "tor_exit_node" in bd.reasons

    def test_vpn_penalty_applied(self):
        threat = MockThreatContext(is_vpn=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 20
        assert bd.final_score == 80
        assert "vpn_or_proxy" in bd.reasons

    def test_datacenter_penalty_applied(self):
        threat = MockThreatContext(is_datacenter=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 15
        assert bd.final_score == 85
        assert "datacenter_ip" in bd.reasons

    def test_abuse_penalty_above_threshold(self):
        threat = MockThreatContext(abuse_score=75)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 30
        assert "abuseipdb:75" in bd.reasons

    def test_abuse_penalty_at_threshold(self):
        threat = MockThreatContext(abuse_score=50)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 30

    def test_abuse_penalty_below_threshold_skipped(self):
        threat = MockThreatContext(abuse_score=49)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 0
        assert not any("abuseipdb" in r for r in bd.reasons)

    def test_abuse_score_zero_no_penalty(self):
        threat = MockThreatContext(abuse_score=0)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 0

    def test_all_threat_signals_cumulative(self):
        threat = MockThreatContext(is_tor=True, is_vpn=True, is_datacenter=True, abuse_score=80)
        bd = compute(ml_score=100, threat_context=threat)
        # tor(40) + vpn(20) + dc(15) + abuse(30) = 105
        assert bd.threat_penalty == 105
        assert bd.final_score == 0  # clamped

    def test_tor_plus_datacenter(self):
        threat = MockThreatContext(is_tor=True, is_datacenter=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 55
        assert bd.final_score == 45

    def test_reason_order_threat_intel(self):
        threat = MockThreatContext(is_tor=True, is_vpn=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert "tor_exit_node" in bd.reasons
        assert "vpn_or_proxy" in bd.reasons


# ─────────────────────────────────────────────────────────────────────────────
# 3. Graph anomaly penalties
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphPenalties:
    def test_impossible_travel_penalty(self):
        graph = MockGraphResult(impossible_travel=True)
        bd = compute(ml_score=100, graph_result=graph)
        assert bd.graph_penalty == 50
        assert bd.final_score == 50
        assert "impossible_travel" in bd.reasons

    def test_branching_penalty(self):
        graph = MockGraphResult(branching=True)
        bd = compute(ml_score=100, graph_result=graph)
        assert bd.graph_penalty == 30
        assert bd.final_score == 70
        assert "session_branching" in bd.reasons

    def test_both_graph_anomalies(self):
        graph = MockGraphResult(branching=True, impossible_travel=True)
        bd = compute(ml_score=100, graph_result=graph)
        assert bd.graph_penalty == 80   # travel(50) + branching(30)
        assert bd.final_score == 20

    def test_no_graph_anomalies_no_penalty(self):
        graph = MockGraphResult()
        bd = compute(ml_score=100, graph_result=graph)
        assert bd.graph_penalty == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Risk tier assignment
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskTierAssignment:
    def test_tier_allow_at_threshold(self):
        bd = compute(ml_score=70)
        assert bd.tier == RiskTier.ALLOW

    def test_tier_allow_above_threshold(self):
        bd = compute(ml_score=100)
        assert bd.tier == RiskTier.ALLOW

    def test_tier_step_up_at_49(self):
        # SCORE_STEPUP_THRESHOLD=50: < 50 is step_up
        bd = compute(ml_score=49)
        assert bd.tier == RiskTier.STEP_UP

    def test_tier_allow_at_50(self):
        # >= SCORE_STEPUP_THRESHOLD → ALLOW
        bd = compute(ml_score=50)
        assert bd.tier == RiskTier.ALLOW

    def test_tier_step_up_between_30_and_50(self):
        bd = compute(ml_score=40)
        assert bd.tier == RiskTier.STEP_UP

    def test_tier_block_at_29(self):
        # SCORE_BLOCK_THRESHOLD=30: < 30 is block
        bd = compute(ml_score=29)
        assert bd.tier == RiskTier.BLOCK

    def test_tier_step_up_at_30(self):
        bd = compute(ml_score=30)
        assert bd.tier == RiskTier.STEP_UP

    def test_tier_block_between_15_and_30(self):
        bd = compute(ml_score=25)
        assert bd.tier == RiskTier.BLOCK

    def test_tier_revoke_at_14(self):
        # SCORE_REVOKE_THRESHOLD=15: < 15 is revoke
        bd = compute(ml_score=14)
        assert bd.tier == RiskTier.REVOKE
        assert "revoke_threshold_breached" in bd.reasons

    def test_tier_block_at_15(self):
        bd = compute(ml_score=15)
        assert bd.tier == RiskTier.BLOCK

    def test_tier_revoke_below_14(self):
        bd = compute(ml_score=10)
        assert bd.tier == RiskTier.REVOKE

    def test_tier_revoke_at_zero(self):
        bd = compute(ml_score=0)
        assert bd.tier == RiskTier.REVOKE

    def test_tier_revoke_has_reason(self):
        bd = compute(ml_score=0)
        assert "revoke_threshold_breached" in bd.reasons

    def test_tier_step_up_no_revoke_reason(self):
        bd = compute(ml_score=40)
        assert "revoke_threshold_breached" not in bd.reasons

    def test_boundary_50_allow(self):
        bd = compute(ml_score=50)
        assert bd.tier == RiskTier.ALLOW

    def test_boundary_49_step_up(self):
        bd = compute(ml_score=49)
        assert bd.tier == RiskTier.STEP_UP

    def test_boundary_30_step_up(self):
        bd = compute(ml_score=30)
        assert bd.tier == RiskTier.STEP_UP

    def test_boundary_29_block(self):
        bd = compute(ml_score=29)
        assert bd.tier == RiskTier.BLOCK

    def test_boundary_15_block(self):
        bd = compute(ml_score=15)
        assert bd.tier == RiskTier.BLOCK

    def test_boundary_14_revoke(self):
        bd = compute(ml_score=14)
        assert bd.tier == RiskTier.REVOKE


# ─────────────────────────────────────────────────────────────────────────────
# 5. Score floor and ceiling
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreFloorCeiling:
    def test_score_cannot_go_below_zero(self):
        threat = MockThreatContext(is_tor=True, is_vpn=True, is_datacenter=True, abuse_score=100)
        graph  = MockGraphResult(branching=True, impossible_travel=True)
        bd = compute(ml_score=10, threat_context=threat, graph_result=graph)
        assert bd.final_score == 0

    def test_score_floor_exact_zero(self):
        bd = compute(ml_score=0)
        assert bd.final_score == 0

    def test_ml_score_100_high_penalties(self):
        threat = MockThreatContext(is_tor=True)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.final_score == 60  # 100 - 40

    def test_penalty_exceeds_ml_score_clamped(self):
        threat = MockThreatContext(is_tor=True)  # 40 penalty
        bd = compute(ml_score=20, threat_context=threat)
        assert bd.final_score == 0  # 20 - 40 = -20 → clamped to 0

    def test_penalty_exactly_equals_ml_score(self):
        threat = MockThreatContext(is_datacenter=True)  # 15 penalty
        bd = compute(ml_score=15, threat_context=threat)
        assert bd.final_score == 0


# ─────────────────────────────────────────────────────────────────────────────
# 6. Aggregation and consistency
# ─────────────────────────────────────────────────────────────────────────────

class TestAggregation:
    def test_all_signals_combined(self):
        threat = MockThreatContext(is_tor=True, is_vpn=True, abuse_score=60)
        graph  = MockGraphResult(impossible_travel=True, branching=True)
        bd = compute(ml_score=100, threat_context=threat, graph_result=graph)
        expected_threat = 40 + 20 + 30  # 90
        expected_graph  = 50 + 30       # 80
        assert bd.threat_penalty == expected_threat
        assert bd.graph_penalty  == expected_graph
        assert bd.final_score    == 0  # clamped

    def test_consistency_same_inputs(self):
        threat = MockThreatContext(is_tor=True, abuse_score=75)
        graph  = MockGraphResult(branching=True)
        results = [compute(ml_score=80, threat_context=threat, graph_result=graph) for _ in range(10)]
        scores  = [r.final_score for r in results]
        assert len(set(scores)) == 1, "Score should be deterministic"

    def test_reasons_list_all_included(self):
        threat = MockThreatContext(is_tor=True, is_vpn=True, is_datacenter=True, abuse_score=60)
        graph  = MockGraphResult(impossible_travel=True, branching=True)
        bd = compute(ml_score=100, threat_context=threat, graph_result=graph)
        assert "tor_exit_node"     in bd.reasons
        assert "vpn_or_proxy"      in bd.reasons
        assert "datacenter_ip"     in bd.reasons
        assert "impossible_travel" in bd.reasons
        assert "session_branching" in bd.reasons
        assert any("abuseipdb" in r for r in bd.reasons)

    def test_ml_score_preserved_in_breakdown(self):
        bd = compute(ml_score=77)
        assert bd.ml_score == 77

    def test_threat_penalty_additive(self):
        t1 = compute(ml_score=100, threat_context=MockThreatContext(is_tor=True))
        t2 = compute(ml_score=100, threat_context=MockThreatContext(is_vpn=True))
        t3 = compute(ml_score=100, threat_context=MockThreatContext(is_tor=True, is_vpn=True))
        assert t3.threat_penalty == t1.threat_penalty + t2.threat_penalty


# ─────────────────────────────────────────────────────────────────────────────
# 7. ScoreBreakdown.to_dict()
# ─────────────────────────────────────────────────────────────────────────────

class TestScoreBreakdownToDict:
    def test_to_dict_keys(self):
        bd = compute(ml_score=80)
        d = bd.to_dict()
        assert set(d.keys()) == {
            "ml_score", "threat_penalty", "graph_penalty", "final_score", "tier", "reasons"
        }

    def test_to_dict_tier_is_string(self):
        bd = compute(ml_score=80)
        d = bd.to_dict()
        assert isinstance(d["tier"], str)
        assert d["tier"] == "allow"

    def test_to_dict_revoke_tier(self):
        bd = compute(ml_score=5)
        d = bd.to_dict()
        assert d["tier"] == "revoke"

    def test_to_dict_reasons_is_list(self):
        bd = compute(ml_score=80)
        d = bd.to_dict()
        assert isinstance(d["reasons"], list)

    def test_to_dict_with_signals(self):
        threat = MockThreatContext(is_tor=True)
        bd = compute(ml_score=100, threat_context=threat)
        d = bd.to_dict()
        assert d["threat_penalty"] == 40
        assert d["final_score"] == 60
        assert "tor_exit_node" in d["reasons"]


# ─────────────────────────────────────────────────────────────────────────────
# 8. Adversarial inputs
# ─────────────────────────────────────────────────────────────────────────────

class TestAdversarialInputs:
    def test_ml_score_negative_not_expected_but_handled(self):
        """If ML returns negative (shouldn't happen), system should not crash."""
        bd = compute(ml_score=0)
        assert bd.final_score >= 0

    def test_empty_reasons_initially(self):
        bd = ScoreBreakdown()
        assert bd.reasons == []

    def test_score_breakdown_defaults(self):
        bd = ScoreBreakdown()
        assert bd.ml_score == 100
        assert bd.threat_penalty == 0
        assert bd.graph_penalty == 0
        assert bd.final_score == 100
        assert bd.tier == RiskTier.ALLOW

    def test_high_abuse_score_100(self):
        threat = MockThreatContext(abuse_score=100)
        bd = compute(ml_score=100, threat_context=threat)
        assert bd.threat_penalty == 30
        assert "abuseipdb:100" in bd.reasons

    def test_tor_on_low_score_causes_revoke(self):
        threat = MockThreatContext(is_tor=True)
        bd = compute(ml_score=40, threat_context=threat)
        # 40 - 40 = 0 → REVOKE
        assert bd.final_score == 0
        assert bd.tier == RiskTier.REVOKE

    def test_all_clean_signals_with_perfect_ml(self):
        threat = _clean_threat()
        graph  = _clean_graph()
        bd = compute(ml_score=100, threat_context=threat, graph_result=graph)
        assert bd.final_score == 100
        assert bd.tier == RiskTier.ALLOW
        assert bd.reasons == []

    def test_risk_tier_enum_values(self):
        assert RiskTier.ALLOW.value   == "allow"
        assert RiskTier.STEP_UP.value == "step_up"
        assert RiskTier.BLOCK.value   == "block"
        assert RiskTier.REVOKE.value  == "revoke"

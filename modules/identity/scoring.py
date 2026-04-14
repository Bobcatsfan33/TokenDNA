"""
TokenDNA — Unified scoring engine.

Consolidates all risk signals into a single integer score (0–100) and a
RiskTier enum that drives the response strategy in api.py.

Score composition:
    Base score from AdaptiveModel (ml_model.py)     → 0–100
    Threat intel penalties (tor, datacenter, abuse)  → deductions
    Session graph penalties (branching, travel)      → deductions
    Final score clamped to [0, 100]

Risk tiers (driven by config thresholds):
    ALLOW      ≥ SCORE_ALLOW_THRESHOLD (default 70)   → pass through
    STEP_UP    ≥ SCORE_STEPUP_THRESHOLD (default 50)  → require MFA
    BLOCK      ≥ SCORE_BLOCK_THRESHOLD  (default 30)  → block request
    REVOKE     <  SCORE_REVOKE_THRESHOLD (default 15)  → block + revoke token
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from config import (
    SCORE_ALLOW_THRESHOLD,
    SCORE_BLOCK_THRESHOLD,
    SCORE_REVOKE_THRESHOLD,
    SCORE_STEPUP_THRESHOLD,
    ABUSEIPDB_MIN_CONFIDENCE,
)


class RiskTier(str, Enum):
    ALLOW   = "allow"
    STEP_UP = "step_up"
    BLOCK   = "block"
    REVOKE  = "revoke"


@dataclass
class ScoreBreakdown:
    """Detailed scoring result for logging and alerting."""
    ml_score:        int = 100      # from AdaptiveModel
    threat_penalty:  int = 0        # from ThreatContext
    graph_penalty:   int = 0        # from GraphAnomalyResult
    final_score:     int = 100
    tier:            RiskTier = RiskTier.ALLOW
    reasons:         list[str] = field(default_factory=list)
    network_penalty: int = 0

    def to_dict(self) -> dict:
        return {
            "ml_score":       self.ml_score,
            "threat_penalty": self.threat_penalty,
            "graph_penalty":  self.graph_penalty,
            "final_score":    self.final_score,
            "tier":           self.tier.value,
            "reasons":        self.reasons,
            "network_penalty": self.network_penalty,
        }


# ── Threat intel penalty table ────────────────────────────────────────────────
_TOR_PENALTY         = 40   # Tor exit: very high signal
_DATACENTER_PENALTY  = 15   # DC IP: medium (could be a legitimate cloud user)
_VPN_PENALTY         = 20   # VPN: medium-high
_ABUSE_PENALTY       = 30   # AbuseIPDB hit above confidence threshold

# ── Graph penalty table ───────────────────────────────────────────────────────
_BRANCHING_PENALTY   = 30   # Session branching: high signal
_TRAVEL_PENALTY      = 50   # Impossible travel: very high signal


def compute(
    ml_score: int,
    threat_context=None,   # ThreatContext | None
    graph_result=None,     # GraphAnomalyResult | None
    network_penalty: int = 0,
    network_reasons: list[str] | None = None,
) -> ScoreBreakdown:
    """
    Compute the final risk score and tier from all available signals.

    Args:
        ml_score:       Output of ml_model.score()
        threat_context: Output of threat_intel.enrich() (optional)
        graph_result:   Output of session_graph.detect_anomalies() (optional)

    Returns:
        ScoreBreakdown with final_score, tier, and human-readable reasons.
    """
    bd = ScoreBreakdown(ml_score=ml_score)

    # ── Threat intel deductions ───────────────────────────────────────────────
    if threat_context is not None:
        if threat_context.is_tor:
            bd.threat_penalty += _TOR_PENALTY
            bd.reasons.append("tor_exit_node")
        if threat_context.is_vpn:
            bd.threat_penalty += _VPN_PENALTY
            bd.reasons.append("vpn_or_proxy")
        if threat_context.is_datacenter:
            bd.threat_penalty += _DATACENTER_PENALTY
            bd.reasons.append("datacenter_ip")
        if threat_context.abuse_score >= ABUSEIPDB_MIN_CONFIDENCE:
            bd.threat_penalty += _ABUSE_PENALTY
            bd.reasons.append(f"abuseipdb:{threat_context.abuse_score}")

    # ── Graph anomaly deductions ──────────────────────────────────────────────
    if graph_result is not None:
        if graph_result.impossible_travel:
            bd.graph_penalty += _TRAVEL_PENALTY
            bd.reasons.append("impossible_travel")
        if graph_result.branching:
            bd.graph_penalty += _BRANCHING_PENALTY
            bd.reasons.append("session_branching")

    bd.network_penalty = max(int(network_penalty), 0)
    if network_reasons:
        bd.reasons.extend(network_reasons)

    # ── Final score ───────────────────────────────────────────────────────────
    bd.final_score = max(
        ml_score - bd.threat_penalty - bd.graph_penalty - bd.network_penalty,
        0,
    )

    # ── Risk tier ─────────────────────────────────────────────────────────────
    if bd.final_score < SCORE_REVOKE_THRESHOLD:
        bd.tier = RiskTier.REVOKE
        bd.reasons.append("revoke_threshold_breached")
    elif bd.final_score < SCORE_BLOCK_THRESHOLD:
        bd.tier = RiskTier.BLOCK
    elif bd.final_score < SCORE_STEPUP_THRESHOLD:
        bd.tier = RiskTier.STEP_UP
    else:
        bd.tier = RiskTier.ALLOW

    return bd

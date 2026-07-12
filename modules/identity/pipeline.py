"""TokenDNA — the risk-scoring pipeline (P2.3).

Two halves of one job, previously split across two ~150-line modules:

  * DNA fingerprint (was ``token_dna.py``) — derive a stable device/agent
    fingerprint from a request, and migrate older fingerprint formats forward.
  * Risk scoring (was ``scoring.py``) — turn that fingerprint, plus threat and
    graph signals, into a RiskTier and a ScoreBreakdown.

Nothing here changed but the file it lives in: same functions, same signatures,
same behaviour.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Optional
from enum import Enum
from dataclasses import dataclass, field
from config import (
    SCORE_ALLOW_THRESHOLD,
    SCORE_BLOCK_THRESHOLD,
    SCORE_REVOKE_THRESHOLD,
    SCORE_STEPUP_THRESHOLD,
    ABUSEIPDB_MIN_CONFIDENCE,
)


# ── DNA fingerprint (was token_dna.py) ───────────────────────────────────────

# ── HMAC key for privacy-preserving IP/UA hashing ────────────────────────────
# Plain SHA-256 of an IPv4 address is reversible (rainbow table over 4B addrs).
# HMAC-SHA256 with a platform secret prevents reversal even with full DB access.
# Set DNA_HMAC_KEY in production (load from AWS Secrets Manager or Vault).
# FedRAMP SC-28 / privacy requirement.
_DNA_HMAC_KEY: bytes = os.getenv("DNA_HMAC_KEY", "").encode() or b"dev-only-insecure-key"


# ── Schema version — bump when DNA structure changes ─────────────────────────
DNA_VERSION = 2


# ── User-Agent parsing helpers ────────────────────────────────────────────────

_OS_PATTERNS = [
    (re.compile(r"Windows", re.I),  "Windows"),
    (re.compile(r"Macintosh|Mac OS X", re.I), "macOS"),
    (re.compile(r"Android", re.I),  "Android"),
    (re.compile(r"iPhone|iPad|iPod", re.I), "iOS"),
    (re.compile(r"Linux", re.I),    "Linux"),
    (re.compile(r"CrOS", re.I),     "ChromeOS"),
]

_BROWSER_PATTERNS = [
    (re.compile(r"Edg/|Edge/", re.I),    "Edge"),
    (re.compile(r"Chrome/", re.I),       "Chrome"),
    (re.compile(r"Firefox/", re.I),      "Firefox"),
    (re.compile(r"Safari/", re.I),       "Safari"),
    (re.compile(r"OPR/|Opera/", re.I),   "Opera"),
    (re.compile(r"curl/", re.I),         "curl"),
    (re.compile(r"python-requests", re.I), "requests"),
]

_MOBILE_RE = re.compile(r"Mobile|Android|iPhone|iPad|iPod", re.I)


def _extract_os(ua: str) -> str:
    for pattern, name in _OS_PATTERNS:
        if pattern.search(ua):
            return name
    return "Other"


def _extract_browser(ua: str) -> str:
    for pattern, name in _BROWSER_PATTERNS:
        if pattern.search(ua):
            return name
    return "Other"


def _is_mobile(ua: str) -> bool:
    return bool(_MOBILE_RE.search(ua))


# ── Hashing ───────────────────────────────────────────────────────────────────

def _sha256(val: str) -> str:
    """HMAC-SHA256(val, platform_key) → first 32 hex chars.

    Using HMAC-SHA256 instead of plain SHA-256 prevents rainbow table
    reversal of IP addresses (the 32-bit IPv4 space is fully enumerable).
    Truncation to 32 chars preserves uniqueness for comparison while
    keeping stored fingerprints compact.

    FedRAMP SC-28 / IL6 privacy requirement.
    """
    return hmac.new(
        _DNA_HMAC_KEY,
        val.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:32]


# ── Public API ────────────────────────────────────────────────────────────────

def generate_dna(
    user_agent: str,
    ip: str,
    country: str,
    asn: str,
) -> dict:
    """
    Build a versioned DNA fingerprint from request signals.

    Args:
        user_agent: HTTP User-Agent header value
        ip:         Client IP address (IPv4 or IPv6)
        country:    ISO-3166-1 alpha-2 country code from GeoIP
        asn:        Autonomous System Number string (e.g. "AS15169")

    Returns:
        DNA dict ready for scoring, caching, or ClickHouse insertion.
    """
    ua = user_agent.strip() if user_agent else ""
    ip = ip.strip() if ip else ""
    country = (country or "XX").upper()[:2]
    asn = (asn or "unknown").upper()

    return {
        "version":    DNA_VERSION,
        "device":     _sha256(ua) if ua else "unknown",
        "ip":         _sha256(ip) if ip else "unknown",
        "country":    country,
        "asn":        asn,
        "ua_os":      _extract_os(ua),
        "ua_browser": _extract_browser(ua),
        "is_mobile":  _is_mobile(ua),
    }


def dna_matches(a: dict, b: dict) -> bool:
    """True if two DNA records represent the same device on the same network."""
    return (
        a.get("device") == b.get("device")
        and a.get("ip") == b.get("ip")
        and a.get("country") == b.get("country")
        and a.get("asn") == b.get("asn")
    )


def migrate_dna(dna: dict) -> dict:
    """Upgrade a v1 DNA (abbreviated keys) to v2 (descriptive keys)."""
    version = dna.get("version", 1)
    if version >= DNA_VERSION:
        return dna
    if version == 1:
        return {
            "version":    DNA_VERSION,
            "device":     dna.get("d", "unknown"),
            "ip":         dna.get("i", "unknown"),
            "country":    dna.get("c", "XX"),
            "asn":        dna.get("a", "unknown"),
            "ua_os":      "Other",
            "ua_browser": "Other",
            "is_mobile":  False,
        }
    return dna


# ── Risk scoring (was scoring.py) ────────────────────────────────────────────

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

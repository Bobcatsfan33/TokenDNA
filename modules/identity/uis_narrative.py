"""
TokenDNA — Unified Identity Signal (UIS) Exploit Narrative Layer.

Sprint 1-1: Enriches UIS events with human-readable attack narratives and
MITRE ATT&CK mapping.  Every downstream differentiation feature (Blast Radius,
Intent Correlation, Trust Graph) depends on this schema.

UIS Schema v1.1 — Four narrative fields (all optional, backward-compatible):
    precondition  : What the attacker already had (foothold, credential, access)
    pivot         : How the attacker moved (technique, lateral move, escalation)
    payload       : What the attacker delivered or executed
    objective     : What the attacker was trying to achieve

Each narrative-enriched event also carries:
    mitre_tactic    : MITRE ATT&CK tactic ID (e.g. "TA0001")
    mitre_technique : MITRE ATT&CK technique ID (e.g. "T1078")
    narrative       : Human-readable one-line attack story
    confidence      : Narrative confidence score (0.0 – 1.0)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ── UIS Schema Version ────────────────────────────────────────────────────────

UIS_SCHEMA_VERSION = "1.1"
UIS_SCHEMA_VERSION_PREV = "1.0"


# ── UIS Event Categories ─────────────────────────────────────────────────────
# The five canonical UIS event categories that all TokenDNA events fall into.

class UISEventCategory(str, Enum):
    """Five canonical UIS event categories."""
    AUTH_ANOMALY = "auth_anomaly"              # Abnormal authentication pattern
    CREDENTIAL_ABUSE = "credential_abuse"      # Stolen/reused/stuffed credentials
    LATERAL_MOVEMENT = "lateral_movement"      # Movement between systems/identities
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Unauthorized privilege gain
    EXFILTRATION = "exfiltration"              # Data theft or unauthorized access


# ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
# Maps UIS event categories + specific signals to MITRE ATT&CK tactics/techniques.

@dataclass(frozen=True)
class MITREMapping:
    """Single MITRE ATT&CK mapping entry."""
    tactic_id: str        # e.g. "TA0001"
    tactic_name: str      # e.g. "Initial Access"
    technique_id: str     # e.g. "T1078"
    technique_name: str   # e.g. "Valid Accounts"


# Canonical MITRE mappings for each UIS event category
MITRE_MAPPINGS: dict[UISEventCategory, list[MITREMapping]] = {
    UISEventCategory.AUTH_ANOMALY: [
        MITREMapping("TA0001", "Initial Access", "T1078", "Valid Accounts"),
        MITREMapping("TA0005", "Defense Evasion", "T1078.004", "Valid Accounts: Cloud Accounts"),
        MITREMapping("TA0006", "Credential Access", "T1110", "Brute Force"),
    ],
    UISEventCategory.CREDENTIAL_ABUSE: [
        MITREMapping("TA0006", "Credential Access", "T1110.004", "Brute Force: Credential Stuffing"),
        MITREMapping("TA0006", "Credential Access", "T1528", "Steal Application Access Token"),
        MITREMapping("TA0006", "Credential Access", "T1539", "Steal Web Session Cookie"),
    ],
    UISEventCategory.LATERAL_MOVEMENT: [
        MITREMapping("TA0008", "Lateral Movement", "T1550", "Use Alternate Authentication Material"),
        MITREMapping("TA0008", "Lateral Movement", "T1550.001", "Application Access Token"),
        MITREMapping("TA0005", "Defense Evasion", "T1036", "Masquerading"),
    ],
    UISEventCategory.PRIVILEGE_ESCALATION: [
        MITREMapping("TA0004", "Privilege Escalation", "T1078", "Valid Accounts"),
        MITREMapping("TA0004", "Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism"),
        MITREMapping("TA0003", "Persistence", "T1098", "Account Manipulation"),
    ],
    UISEventCategory.EXFILTRATION: [
        MITREMapping("TA0010", "Exfiltration", "T1537", "Transfer Data to Cloud Account"),
        MITREMapping("TA0009", "Collection", "T1530", "Data from Cloud Storage"),
        MITREMapping("TA0010", "Exfiltration", "T1567", "Exfiltration Over Web Service"),
    ],
}


# ── Narrative Data Model ──────────────────────────────────────────────────────

@dataclass
class NarrativeFields:
    """The four narrative fields that extend UIS v1 → v1.1."""
    precondition: Optional[str] = None   # What attacker already had
    pivot: Optional[str] = None          # How attacker moved
    payload: Optional[str] = None        # What attacker delivered
    objective: Optional[str] = None      # What attacker wanted

    def to_dict(self) -> dict:
        return {
            "precondition": self.precondition,
            "pivot": self.pivot,
            "payload": self.payload,
            "objective": self.objective,
        }

    @classmethod
    def from_dict(cls, d: dict) -> NarrativeFields:
        return cls(
            precondition=d.get("precondition"),
            pivot=d.get("pivot"),
            payload=d.get("payload"),
            objective=d.get("objective"),
        )

    @property
    def is_populated(self) -> bool:
        """True if at least one narrative field is set."""
        return any([self.precondition, self.pivot, self.payload, self.objective])


@dataclass
class UISNarrativeEvent:
    """A UIS event enriched with narrative context."""
    category: UISEventCategory
    narrative_fields: NarrativeFields
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    narrative: Optional[str] = None       # Human-readable one-liner
    confidence: float = 0.0               # 0.0 – 1.0
    schema_version: str = UIS_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "category": self.category.value,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "narrative": self.narrative,
            "confidence": self.confidence,
            **self.narrative_fields.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> UISNarrativeEvent:
        return cls(
            category=UISEventCategory(d["category"]),
            narrative_fields=NarrativeFields.from_dict(d),
            mitre_tactic=d.get("mitre_tactic"),
            mitre_technique=d.get("mitre_technique"),
            narrative=d.get("narrative"),
            confidence=float(d.get("confidence", 0.0)),
            schema_version=d.get("schema_version", UIS_SCHEMA_VERSION),
        )


# ── Narrative Templates ──────────────────────────────────────────────────────
# Human-readable narrative templates for each UIS event category.
# Placeholders: {user}, {country}, {device}, {reasons}, {score}

NARRATIVE_TEMPLATES: dict[UISEventCategory, str] = {
    UISEventCategory.AUTH_ANOMALY: (
        "Authentication anomaly detected for {user} from {country} on {device}. "
        "Risk signals: {reasons}. Score: {score}/100. "
        "This pattern is consistent with valid-account abuse (MITRE T1078) "
        "where a compromised credential is used from an unusual context."
    ),
    UISEventCategory.CREDENTIAL_ABUSE: (
        "Credential abuse detected for {user} from {country}. "
        "Signals indicate {reasons}. Score: {score}/100. "
        "This pattern matches credential stuffing or token theft (MITRE T1110/T1528) "
        "where stolen credentials are replayed from attacker infrastructure."
    ),
    UISEventCategory.LATERAL_MOVEMENT: (
        "Lateral movement detected for {user}. "
        "Session observed from {country} on {device} with {reasons}. Score: {score}/100. "
        "Impossible travel or session branching indicates token reuse across "
        "distinct environments (MITRE T1550), suggesting credential sharing or theft."
    ),
    UISEventCategory.PRIVILEGE_ESCALATION: (
        "Privilege escalation attempt for {user} from {country}. "
        "Risk indicators: {reasons}. Score: {score}/100. "
        "This event suggests unauthorized elevation (MITRE T1548) where an agent "
        "or user attempts to access resources beyond their normal scope."
    ),
    UISEventCategory.EXFILTRATION: (
        "Potential data exfiltration by {user} from {country} on {device}. "
        "Signals: {reasons}. Score: {score}/100. "
        "High-volume or anomalous access patterns suggest data collection or "
        "transfer to unauthorized destinations (MITRE T1537/T1567)."
    ),
}


# ── Signal → Category Classification ─────────────────────────────────────────
# Maps scoring reasons (from scoring.py) to UIS event categories.

_REASON_TO_CATEGORY: dict[str, UISEventCategory] = {
    # Auth anomaly signals
    "tor_exit_node": UISEventCategory.AUTH_ANOMALY,
    "vpn_or_proxy": UISEventCategory.AUTH_ANOMALY,
    "datacenter_ip": UISEventCategory.AUTH_ANOMALY,
    # Credential abuse signals
    "session_branching": UISEventCategory.CREDENTIAL_ABUSE,
    # Lateral movement signals
    "impossible_travel": UISEventCategory.LATERAL_MOVEMENT,
    # Tier breach signals
    "revoke_threshold_breached": UISEventCategory.PRIVILEGE_ESCALATION,
}

# AbuseIPDB reason pattern
_ABUSEIPDB_PREFIX = "abuseipdb:"


def classify_event(reasons: list[str]) -> UISEventCategory:
    """
    Classify a UIS event into one of the five canonical categories
    based on the scoring reasons present.

    Priority order: lateral_movement > credential_abuse > privilege_escalation
    > exfiltration > auth_anomaly (default).

    Returns the highest-priority matching category.
    """
    categories_found: set[UISEventCategory] = set()

    for reason in reasons:
        if reason.startswith(_ABUSEIPDB_PREFIX):
            categories_found.add(UISEventCategory.CREDENTIAL_ABUSE)
        elif reason in _REASON_TO_CATEGORY:
            categories_found.add(_REASON_TO_CATEGORY[reason])

    # Priority ordering
    priority = [
        UISEventCategory.LATERAL_MOVEMENT,
        UISEventCategory.CREDENTIAL_ABUSE,
        UISEventCategory.PRIVILEGE_ESCALATION,
        UISEventCategory.EXFILTRATION,
        UISEventCategory.AUTH_ANOMALY,
    ]
    for cat in priority:
        if cat in categories_found:
            return cat

    return UISEventCategory.AUTH_ANOMALY  # default


# ── Narrative Inference ──────────────────────────────────────────────────────

def infer_narrative_fields(
    category: UISEventCategory,
    reasons: list[str],
    dna: dict,
    threat_context=None,
    graph_result=None,
) -> NarrativeFields:
    """
    Infer narrative fields from available event signals.

    Confidence levels for inferred fields:
    - Direct signal match (e.g. impossible_travel → lateral movement): HIGH (0.8-0.9)
    - Composite signal (multiple weak signals): MEDIUM (0.5-0.7)
    - Default/fallback: LOW (0.3-0.4)
    """
    fields = NarrativeFields()

    if category == UISEventCategory.AUTH_ANOMALY:
        fields.precondition = "Valid credential obtained via unknown vector"
        if "tor_exit_node" in reasons:
            fields.pivot = "Authentication routed through Tor exit node to mask origin"
            fields.payload = "Valid token presented from anonymized network"
        elif "vpn_or_proxy" in reasons:
            fields.pivot = "Authentication routed through VPN/proxy to obscure location"
            fields.payload = "Valid token presented from proxy infrastructure"
        elif "datacenter_ip" in reasons:
            fields.pivot = "Authentication from datacenter IP (possible bot/automation)"
            fields.payload = "Automated credential replay from cloud infrastructure"
        else:
            fields.pivot = "Authentication pattern deviates from established baseline"
            fields.payload = "Session initiated with anomalous context signals"
        fields.objective = "Establish foothold using valid credentials while evading detection"

    elif category == UISEventCategory.CREDENTIAL_ABUSE:
        fields.precondition = "Stolen or leaked credentials acquired externally"
        if "session_branching" in reasons:
            fields.pivot = "Credential used simultaneously from multiple devices"
            fields.payload = "Parallel sessions indicating credential sharing or theft"
        else:
            fields.pivot = "Credential replayed from attacker-controlled infrastructure"
            fields.payload = "Automated credential stuffing or token replay attack"
        fields.objective = "Gain persistent access through compromised credentials"

    elif category == UISEventCategory.LATERAL_MOVEMENT:
        fields.precondition = "Active session or token from prior compromise"
        if "impossible_travel" in reasons:
            country = dna.get("country", "XX")
            fields.pivot = f"Token used from geographically impossible location ({country})"
            fields.payload = "Session token replayed from distant location within impossible timeframe"
        else:
            fields.pivot = "Token or session reused across distinct environments"
            fields.payload = "Cross-environment session hijacking"
        fields.objective = "Expand access footprint across organizational boundaries"

    elif category == UISEventCategory.PRIVILEGE_ESCALATION:
        fields.precondition = "Standard-privilege access to target system"
        fields.pivot = "Attempt to access resources beyond authorized scope"
        fields.payload = "Elevated API calls or resource access beyond baseline"
        fields.objective = "Obtain administrative or elevated privileges"

    elif category == UISEventCategory.EXFILTRATION:
        fields.precondition = "Authenticated access to data resources"
        fields.pivot = "Anomalous data access pattern detected"
        fields.payload = "High-volume or unusual data retrieval sequence"
        fields.objective = "Extract sensitive data to attacker-controlled destination"

    return fields


def compute_confidence(
    category: UISEventCategory,
    reasons: list[str],
    threat_context=None,
    graph_result=None,
) -> float:
    """
    Compute narrative confidence based on signal strength and corroboration.

    Returns float between 0.0 and 1.0.
    """
    base = 0.3  # minimum confidence for any classified event

    # Direct high-confidence signal matches
    high_confidence_signals = {
        "impossible_travel": 0.4,
        "session_branching": 0.3,
        "tor_exit_node": 0.3,
        "revoke_threshold_breached": 0.3,
    }

    # Medium-confidence signals
    medium_signals = {
        "vpn_or_proxy": 0.2,
        "datacenter_ip": 0.15,
    }

    boost = 0.0
    for reason in reasons:
        if reason in high_confidence_signals:
            boost = max(boost, high_confidence_signals[reason])
        elif reason in medium_signals:
            boost = max(boost, medium_signals[reason])
        elif reason.startswith(_ABUSEIPDB_PREFIX):
            # Higher AbuseIPDB score = higher confidence
            try:
                abuse_score = int(reason.split(":")[1])
                boost = max(boost, min(abuse_score / 100.0 * 0.4, 0.4))
            except (IndexError, ValueError):
                boost = max(boost, 0.2)

    # Corroboration bonus: multiple distinct signals increase confidence
    distinct_signals = len([r for r in reasons if r != "revoke_threshold_breached"])
    if distinct_signals >= 3:
        boost += 0.1
    elif distinct_signals >= 2:
        boost += 0.05

    return min(base + boost, 1.0)


def select_mitre_mapping(
    category: UISEventCategory,
    reasons: list[str],
) -> MITREMapping:
    """
    Select the most specific MITRE ATT&CK mapping for the given event.

    Returns the first (most relevant) mapping for the category, with
    signal-specific overrides for higher precision.
    """
    mappings = MITRE_MAPPINGS.get(category, MITRE_MAPPINGS[UISEventCategory.AUTH_ANOMALY])

    # Signal-specific overrides for higher precision
    if "impossible_travel" in reasons and category == UISEventCategory.LATERAL_MOVEMENT:
        return MITREMapping("TA0008", "Lateral Movement", "T1550.001", "Application Access Token")
    if "session_branching" in reasons and category == UISEventCategory.CREDENTIAL_ABUSE:
        return MITREMapping("TA0006", "Credential Access", "T1528", "Steal Application Access Token")
    if "tor_exit_node" in reasons:
        return MITREMapping("TA0005", "Defense Evasion", "T1090.003", "Proxy: Multi-hop Proxy")

    return mappings[0]  # default: first mapping for the category


def render_narrative(
    category: UISEventCategory,
    user_id: str,
    dna: dict,
    reasons: list[str],
    score: int,
) -> str:
    """
    Render a human-readable narrative from the template for this category.
    """
    template = NARRATIVE_TEMPLATES.get(category, NARRATIVE_TEMPLATES[UISEventCategory.AUTH_ANOMALY])

    return template.format(
        user=user_id,
        country=dna.get("country", "XX"),
        device=f"{dna.get('ua_os', 'Unknown')}/{dna.get('ua_browser', 'Unknown')}",
        reasons=", ".join(reasons) if reasons else "none",
        score=score,
    )


# ── Main Enrichment Entry Point ──────────────────────────────────────────────

def enrich_event(
    user_id: str,
    dna: dict,
    score_breakdown,
    threat_context=None,
    graph_result=None,
) -> UISNarrativeEvent:
    """
    Enrich a UIS event with narrative fields, MITRE mapping, and
    human-readable story.

    This is the primary entry point. Call after scoring is complete.

    Args:
        user_id:         Authenticated user identifier
        dna:             DNA fingerprint dict from token_dna.generate_dna()
        score_breakdown: ScoreBreakdown from scoring.compute()
        threat_context:  ThreatContext from threat_intel.enrich() (optional)
        graph_result:    GraphAnomalyResult from session_graph.detect_anomalies() (optional)

    Returns:
        UISNarrativeEvent with all narrative fields populated.
    """
    # Extract reasons from score_breakdown (supports both dict and dataclass)
    if hasattr(score_breakdown, "reasons"):
        reasons = list(score_breakdown.reasons)
        final_score = score_breakdown.final_score
    else:
        reasons = list(score_breakdown.get("reasons", []))
        final_score = score_breakdown.get("final_score", 0)

    # 1. Classify
    category = classify_event(reasons)

    # 2. Select MITRE mapping
    mitre = select_mitre_mapping(category, reasons)

    # 3. Infer narrative fields
    narrative_fields = infer_narrative_fields(
        category, reasons, dna, threat_context, graph_result,
    )

    # 4. Compute confidence
    confidence = compute_confidence(category, reasons, threat_context, graph_result)

    # 5. Render human-readable narrative
    narrative = render_narrative(category, user_id, dna, reasons, final_score)

    return UISNarrativeEvent(
        category=category,
        narrative_fields=narrative_fields,
        mitre_tactic=mitre.tactic_id,
        mitre_technique=mitre.technique_id,
        narrative=narrative,
        confidence=confidence,
    )


# ── Migration: UIS v1.0 → v1.1 ──────────────────────────────────────────────

def migrate_event_v1_to_v1_1(event: dict) -> dict:
    """
    Migrate a UIS v1.0 event dict to v1.1 by adding null narrative fields.

    Backward-compatible: all new fields default to None/null.
    Existing event data is preserved unchanged.
    """
    if event.get("schema_version") == UIS_SCHEMA_VERSION:
        return event  # already v1.1

    migrated = dict(event)
    migrated["schema_version"] = UIS_SCHEMA_VERSION

    # Add narrative fields with null defaults
    for fld in ("precondition", "pivot", "payload", "objective"):
        migrated.setdefault(fld, None)

    # Add MITRE/narrative metadata with null defaults
    migrated.setdefault("mitre_tactic", None)
    migrated.setdefault("mitre_technique", None)
    migrated.setdefault("narrative", None)
    migrated.setdefault("confidence", 0.0)
    migrated.setdefault("category", None)

    return migrated

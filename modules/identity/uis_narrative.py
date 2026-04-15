"""
TokenDNA — UIS Exploit Narrative Layer (UIS v1.1)

Converts raw UIS events into machine-readable attack stories by attaching four
chain-semantic narrative fields to every event:

  precondition — state or prerequisite that must have held for this event to occur
  pivot        — transition type (e.g., privilege_escalation, lateral_movement)
  payload      — what was executed or transmitted (scope, tool, credential type)
  objective    — inferred or declared attacker/actor intent

Each field is optional. Where data is sufficient for high-confidence inference
the engine populates it automatically; otherwise fields default to None.

MITRE ATT&CK for Containers / Enterprise mapping is included for every
recognized pivot type.

Confidence levels:
  HIGH   — inference from hard signals (impossible_travel, lateral_movement
            flag, explicit scope escalation, revocation + re-auth, etc.)
  MEDIUM — inference from correlated soft signals (velocity anomaly + risk
            tier, pattern deviation above threshold, tool-call scope mismatch)
  LOW    — heuristic inference with limited evidence; downstream consumers
            should treat as advisory only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# Key: pivot_type value.  Value: (tactic, technique_id, technique_name)
# Sources: ATT&CK for Containers v14, ATT&CK Enterprise v14
# ---------------------------------------------------------------------------
MITRE_PIVOT_MAP: dict[str, dict[str, str]] = {
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "lateral_movement": {
        "tactic": "Lateral Movement",
        "technique_id": "T1550",
        "technique_name": "Use Alternate Authentication Material",
        "url": "https://attack.mitre.org/techniques/T1550/",
    },
    "credential_access": {
        "tactic": "Credential Access",
        "technique_id": "T1528",
        "technique_name": "Steal Application Access Token",
        "url": "https://attack.mitre.org/techniques/T1528/",
    },
    "scope_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1134",
        "technique_name": "Access Token Manipulation",
        "url": "https://attack.mitre.org/techniques/T1134/",
    },
    "token_replay": {
        "tactic": "Credential Access",
        "technique_id": "T1550.001",
        "technique_name": "Use Alternate Authentication Material: Application Access Token",
        "url": "https://attack.mitre.org/techniques/T1550/001/",
    },
    "impossible_travel": {
        "tactic": "Defense Evasion",
        "technique_id": "T1556",
        "technique_name": "Modify Authentication Process",
        "url": "https://attack.mitre.org/techniques/T1556/",
    },
    "identity_compromise": {
        "tactic": "Initial Access",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "delegation_abuse": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1134.001",
        "technique_name": "Access Token Manipulation: Token Impersonation/Theft",
        "url": "https://attack.mitre.org/techniques/T1134/001/",
    },
    "context_switch": {
        "tactic": "Defense Evasion",
        "technique_id": "T1036",
        "technique_name": "Masquerading",
        "url": "https://attack.mitre.org/techniques/T1036/",
    },
    "agent_hijack": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    "supply_chain_compromise": {
        "tactic": "Initial Access",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise",
        "url": "https://attack.mitre.org/techniques/T1195/",
    },
    "mfa_bypass": {
        "tactic": "Defense Evasion",
        "technique_id": "T1556.006",
        "technique_name": "Modify Authentication Process: Multi-Factor Authentication",
        "url": "https://attack.mitre.org/techniques/T1556/006/",
    },
    "persistence": {
        "tactic": "Persistence",
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "url": "https://attack.mitre.org/techniques/T1048/",
    },
    "reconnaissance": {
        "tactic": "Reconnaissance",
        "technique_id": "T1598",
        "technique_name": "Phishing for Information",
        "url": "https://attack.mitre.org/techniques/T1598/",
    },
}

# ---------------------------------------------------------------------------
# UIS event category → default objective mapping
# Five UIS event categories from the protocol spec
# ---------------------------------------------------------------------------
CATEGORY_OBJECTIVE_MAP: dict[str, str] = {
    "auth_success":       "establish_session",
    "auth_failure":       "probe_credentials",
    "scope_change":       "acquire_privilege",
    "lifecycle_event":    "maintain_persistence",
    "threat_detected":    "execute_attack",
}


@dataclass
class NarrativeBlock:
    """
    The four chain-semantic fields added to every UIS v1.1 event.
    All fields default to None; None means inference was not possible.
    """
    precondition: str | None = None          # prerequisite state
    pivot: str | None = None                 # transition type (matches MITRE_PIVOT_MAP key)
    payload: str | None = None               # what was executed / transmitted
    objective: str | None = None             # inferred/declared intent
    confidence: str | None = None            # HIGH / MEDIUM / LOW
    mitre: dict[str, str] | None = None      # MITRE ATT&CK metadata for the pivot
    inference_rules: list[str] = field(default_factory=list)   # which rules fired

    def as_dict(self) -> dict[str, Any]:
        return {
            "precondition": self.precondition,
            "pivot": self.pivot,
            "payload": self.payload,
            "objective": self.objective,
            "confidence": self.confidence,
            "mitre": self.mitre,
            "inference_rules": self.inference_rules,
        }


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------

def infer_narrative(event: dict[str, Any]) -> NarrativeBlock:
    """
    Analyse a fully-formed UIS event dict and return a NarrativeBlock.
    Rules are ordered by confidence; the first matching rule wins for pivot/
    confidence but multiple rules may contribute to precondition and objective.
    """
    nb = NarrativeBlock()
    rules_fired: list[str] = []

    identity  = event.get("identity") or {}
    auth      = event.get("auth") or {}
    token     = event.get("token") or {}
    session   = event.get("session") or {}
    behavior  = event.get("behavior") or {}
    lifecycle = event.get("lifecycle") or {}
    threat    = event.get("threat") or {}
    binding   = event.get("binding") or {}

    risk_score: int = int(threat.get("risk_score") or 0)
    risk_tier: str  = str(threat.get("risk_tier") or "unknown")
    indicators: list = threat.get("indicators") or []

    # ── HIGH confidence rules ─────────────────────────────────────────────

    # R-01: Impossible travel → lateral_movement
    if session.get("impossible_travel"):
        _set_pivot(nb, "impossible_travel", "HIGH", rules_fired, "R-01:impossible_travel")
        nb.precondition = "valid_session_established_at_prior_location"
        nb.objective = nb.objective or "evade_geofencing"

    # R-02: Lateral movement flag → lateral_movement
    if threat.get("lateral_movement"):
        _set_pivot(nb, "lateral_movement", "HIGH", rules_fired, "R-02:lateral_movement_flag")
        nb.precondition = nb.precondition or "prior_foothold_in_tenant"
        nb.objective = nb.objective or "expand_access"

    # R-03: lifecycle revoked + new auth → persistence / token replay
    if lifecycle.get("revoked_at") and auth.get("method"):
        _set_pivot(nb, "token_replay", "HIGH", rules_fired, "R-03:revoked_identity_reauthed")
        nb.precondition = "identity_previously_revoked"
        nb.objective = nb.objective or "maintain_persistence"

    # R-04: MFA not asserted on high-risk event
    if risk_tier in ("high", "critical") and not auth.get("mfa_asserted"):
        _set_pivot(nb, "mfa_bypass", "HIGH", rules_fired, "R-04:high_risk_no_mfa")
        nb.precondition = nb.precondition or "mfa_policy_enabled"
        nb.objective = nb.objective or "bypass_authentication"

    # R-05: Supply chain hash present but mismatch hinted via indicators
    if binding.get("supply_chain_hash") and any("supply_chain" in str(i).lower() for i in indicators):
        _set_pivot(nb, "supply_chain_compromise", "HIGH", rules_fired, "R-05:supply_chain_indicator")
        nb.precondition = "trusted_supply_chain_assumed"
        nb.objective = nb.objective or "inject_malicious_component"

    # ── MEDIUM confidence rules ───────────────────────────────────────────

    # R-06: Velocity anomaly + elevated risk tier
    if behavior.get("velocity_anomaly") and risk_tier in ("medium", "high", "critical"):
        _set_pivot(nb, "credential_access", "MEDIUM", rules_fired, "R-06:velocity_anomaly")
        nb.precondition = nb.precondition or "credential_valid_at_normal_rate"
        nb.objective = nb.objective or "harvest_tokens"

    # R-07: Pattern deviation score > 0.6
    deviation = float(behavior.get("pattern_deviation_score") or 0.0)
    if deviation > 0.6:
        _set_pivot(nb, "context_switch", "MEDIUM", rules_fired, "R-07:pattern_deviation")
        nb.precondition = nb.precondition or "established_behavioral_baseline"

    # R-08: Scope broader than historical (hinted by scope indicator)
    if any("scope" in str(i).lower() for i in indicators):
        _set_pivot(nb, "scope_escalation", "MEDIUM", rules_fired, "R-08:scope_indicator")
        nb.precondition = nb.precondition or "minimal_scope_previously_granted"
        nb.objective = nb.objective or "acquire_privilege"

    # R-09: Machine/agent identity with no DPoP or mTLS binding
    is_machine = identity.get("entity_type") == "machine"
    dpop_bound = token.get("dpop_bound") or bool(binding.get("dpop_jkt"))
    mtls_bound = bool(binding.get("mtls_subject"))
    if is_machine and not dpop_bound and not mtls_bound:
        _set_pivot(nb, "identity_compromise", "MEDIUM", rules_fired, "R-09:unbound_machine_identity")
        nb.precondition = nb.precondition or "machine_identity_without_proof_of_possession"
        nb.objective = nb.objective or "impersonate_service"

    # R-10: Agent with delegation chain signal
    if identity.get("agent_id") and any("delegation" in str(i).lower() for i in indicators):
        _set_pivot(nb, "delegation_abuse", "MEDIUM", rules_fired, "R-10:agent_delegation")
        nb.precondition = nb.precondition or "agent_granted_delegation_rights"
        nb.objective = nb.objective or "escalate_via_agent_chain"

    # ── LOW confidence rules ──────────────────────────────────────────────

    # R-11: Risk score > 50 with no other signal
    if risk_score > 50 and not nb.pivot:
        _set_pivot(nb, "reconnaissance", "LOW", rules_fired, "R-11:elevated_risk_score")

    # R-12: Auth failure (lifecycle dormant)
    if lifecycle.get("dormant"):
        _set_pivot(nb, "persistence", "LOW", rules_fired, "R-12:dormant_identity_active")
        nb.precondition = nb.precondition or "identity_marked_dormant"
        nb.objective = nb.objective or "reactivate_abandoned_identity"

    # ── Payload inference ─────────────────────────────────────────────────
    nb.payload = _infer_payload(auth, token, binding, identity)

    # ── Objective fallback via event category ─────────────────────────────
    if not nb.objective:
        category = _classify_event_category(auth, lifecycle, threat)
        nb.objective = CATEGORY_OBJECTIVE_MAP.get(category)

    nb.inference_rules = rules_fired
    return nb


def _set_pivot(
    nb: NarrativeBlock,
    pivot: str,
    confidence: str,
    rules_fired: list[str],
    rule_id: str,
) -> None:
    """Set pivot only if not already set or new confidence is higher."""
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if nb.pivot is None or order.get(confidence, 0) > order.get(nb.confidence or "", 0):
        nb.pivot = pivot
        nb.confidence = confidence
        nb.mitre = MITRE_PIVOT_MAP.get(pivot)
    rules_fired.append(rule_id)


def _infer_payload(
    auth: dict,
    token: dict,
    binding: dict,
    identity: dict,
) -> str | None:
    """Construct a human-readable payload description from available fields."""
    parts: list[str] = []
    method = auth.get("method")
    if method and method != "unknown":
        parts.append(f"auth:{method}")
    protocol = auth.get("protocol")
    if protocol and protocol != "custom":
        parts.append(f"protocol:{protocol}")
    token_type = token.get("type")
    if token_type and token_type != "bearer":
        parts.append(f"token:{token_type}")
    if token.get("dpop_bound"):
        parts.append("binding:dpop")
    if binding.get("mtls_subject"):
        parts.append("binding:mtls")
    if binding.get("attestation_id"):
        parts.append("binding:attestation")
    entity_type = identity.get("entity_type")
    if entity_type == "machine":
        agent_id = identity.get("agent_id")
        if agent_id:
            parts.append(f"agent:{agent_id}")
        else:
            parts.append("entity:machine")
    return "|".join(parts) if parts else None


def _classify_event_category(
    auth: dict,
    lifecycle: dict,
    threat: dict,
) -> str:
    """Map UIS fields to one of the five UIS event categories."""
    if lifecycle.get("revoked_at") or lifecycle.get("state") in ("revoked", "expired"):
        return "lifecycle_event"
    risk_score = int(threat.get("risk_score") or 0)
    risk_tier = str(threat.get("risk_tier") or "")
    if risk_score >= 70 or risk_tier in ("high", "critical"):
        return "threat_detected"
    indicators = threat.get("indicators") or []
    if any("scope" in str(i).lower() for i in indicators):
        return "scope_change"
    method = auth.get("method") or ""
    if "fail" in method.lower() or "deny" in method.lower():
        return "auth_failure"
    return "auth_success"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def attach_narrative(event: dict[str, Any]) -> dict[str, Any]:
    """
    Return a copy of the UIS event dict with a 'narrative' block added
    and uis_version bumped to '1.1'.  The original dict is not mutated.
    """
    result = dict(event)
    nb = infer_narrative(event)
    result["narrative"] = nb.as_dict()
    result["uis_version"] = "1.1"
    return result


def backfill_narrative(event: dict[str, Any]) -> dict[str, Any]:
    """
    Same as attach_narrative but explicitly signals this is a backfill
    operation on a pre-v1.1 event.  Adds backfill=True to the narrative block.
    """
    result = attach_narrative(event)
    if isinstance(result.get("narrative"), dict):
        result["narrative"]["backfill"] = True
    return result

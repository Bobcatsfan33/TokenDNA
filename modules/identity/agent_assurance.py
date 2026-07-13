"""Buyer-facing agent assurance verdicts.

This module is intentionally small: it turns TokenDNA's lower-level identity,
policy, compromise, and blast-radius signals into the product answer an IdP or
AI-security buyer needs before an agent acts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Literal

Outcome = Literal["allow", "review", "block"]
IdentityStatus = Literal["verified", "unverified", "revoked"]
PolicyStatus = Literal["allowed", "denied"]
CompromiseStatus = Literal["clear", "suspected", "compromised"]

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class CredentialEvidence:
    credential_id: str
    agent_id: str
    status: Literal["active", "revoked", "expired"] = "active"
    trust_score: float = 1.0
    evidence_type: str = "passport"


@dataclass(frozen=True)
class PermissionGrant:
    permission: str
    resource_pattern: str
    source: str = "policy"


@dataclass(frozen=True)
class CompromiseSignal:
    signal_type: str
    severity: Literal["low", "medium", "high", "critical"]
    detail: str


@dataclass(frozen=True)
class BlastRadiusSummary:
    impact_score: int
    risk_tier: Literal["low", "medium", "high", "critical"]
    total_nodes_reached: int
    affected_assets: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AgentActionRequest:
    tenant_id: str
    agent_id: str
    action: str
    resource: str
    credentials: list[CredentialEvidence] = field(default_factory=list)
    permission_grants: list[PermissionGrant] = field(default_factory=list)
    compromise_signals: list[CompromiseSignal] = field(default_factory=list)
    blast_radius: BlastRadiusSummary | None = None


@dataclass(frozen=True)
class AgentAssuranceVerdict:
    tenant_id: str
    agent_id: str
    outcome: Outcome
    identity_status: IdentityStatus
    policy_status: PolicyStatus
    compromise_status: CompromiseStatus
    reasons: list[str]
    blast_radius: dict[str, Any] | None
    remediation: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "outcome": self.outcome,
            "identity_status": self.identity_status,
            "policy_status": self.policy_status,
            "compromise_status": self.compromise_status,
            "reasons": self.reasons,
            "blast_radius": self.blast_radius,
            "remediation": self.remediation,
        }


def assess_agent_action(request: AgentActionRequest) -> AgentAssuranceVerdict:
    """Return the single yes/review/no answer for an agent action."""
    identity_status, identity_reasons = _identity_status(request)
    policy_status, policy_reasons = _policy_status(request)
    compromise_status, compromise_reasons = _compromise_status(request)
    reasons = identity_reasons + policy_reasons + compromise_reasons

    outcome: Outcome = "allow"
    if identity_status == "revoked" or compromise_status == "compromised":
        outcome = "block"
    elif identity_status == "unverified" or policy_status == "denied":
        outcome = "block"
    elif compromise_status == "suspected":
        outcome = "review"

    blast = _blast_dict(request.blast_radius)
    remediation = _remediation(request, outcome, identity_status, policy_status, compromise_status)

    return AgentAssuranceVerdict(
        tenant_id=request.tenant_id,
        agent_id=request.agent_id,
        outcome=outcome,
        identity_status=identity_status,
        policy_status=policy_status,
        compromise_status=compromise_status,
        reasons=reasons,
        blast_radius=blast,
        remediation=remediation,
    )


def _identity_status(request: AgentActionRequest) -> tuple[IdentityStatus, list[str]]:
    matching = [c for c in request.credentials if c.agent_id == request.agent_id]
    if any(c.status == "revoked" for c in matching):
        return "revoked", ["agent credential has been revoked"]
    active = [c for c in matching if c.status == "active" and c.trust_score >= 0.5]
    if active:
        return "verified", [f"agent identity verified by {active[0].evidence_type}:{active[0].credential_id}"]
    return "unverified", ["no active credential evidence matched this agent"]


def _policy_status(request: AgentActionRequest) -> tuple[PolicyStatus, list[str]]:
    for grant in request.permission_grants:
        if grant.permission == request.action and fnmatchcase(request.resource, grant.resource_pattern):
            return "allowed", [f"policy grant {grant.source} permits {request.action} on {request.resource}"]
    return "denied", [f"no policy grant permits {request.action} on {request.resource}"]


def _compromise_status(request: AgentActionRequest) -> tuple[CompromiseStatus, list[str]]:
    if not request.compromise_signals:
        return "clear", ["no compromise signals attached to this action"]
    highest = max(_SEVERITY_RANK[s.severity] for s in request.compromise_signals)
    details = [f"{s.severity}:{s.signal_type}" for s in request.compromise_signals]
    if highest >= _SEVERITY_RANK["critical"]:
        return "compromised", ["critical compromise signal present: " + ", ".join(details)]
    if highest >= _SEVERITY_RANK["high"]:
        return "suspected", ["high-confidence compromise signal present: " + ", ".join(details)]
    return "suspected", ["low/medium compromise signal present: " + ", ".join(details)]


def _blast_dict(blast: BlastRadiusSummary | None) -> dict[str, Any] | None:
    if blast is None:
        return None
    return {
        "impact_score": blast.impact_score,
        "risk_tier": blast.risk_tier,
        "total_nodes_reached": blast.total_nodes_reached,
        "affected_assets": blast.affected_assets,
    }


def _remediation(
    request: AgentActionRequest,
    outcome: Outcome,
    identity_status: IdentityStatus,
    policy_status: PolicyStatus,
    compromise_status: CompromiseStatus,
) -> list[str]:
    steps: list[str] = []
    if identity_status in {"unverified", "revoked"}:
        steps.append("rotate or re-issue the agent credential before allowing this action")
    if policy_status == "denied":
        steps.append("require an explicit policy grant for the requested action/resource pair")
    if compromise_status in {"suspected", "compromised"}:
        steps.append("suspend the agent and revoke active sessions while the signal is investigated")
    if request.blast_radius and request.blast_radius.risk_tier in {"high", "critical"}:
        steps.append("notify owners of affected assets and run the blast-radius containment plan")
    if outcome == "allow":
        steps.append("allow and continue monitoring")
    return steps

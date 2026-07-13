"""The single evaluate() core (P2.4 / D-6).

One entry point — ``evaluate(question, subject) -> Verdict`` — behind the three
questions the product exists to answer:

    VERIFY     is this a legitimate agent identity, and are its credentials valid?
    AUTHORIZE  is it allowed to do what it's doing, where it's going?
    CONTAIN    has it been compromised — blast radius, and can I trace it?

This is a **dispatcher, not a framework** (D-6's hard guardrail). It owns no
detection logic. It gathers evidence from the pillar modules, hands the scoring
to the existing ``agent_assurance`` facade — the verdict brain from PR #144,
which is a pure function over pre-fetched evidence — and maps its answer into the
shared Verdict schema. There is exactly one place a verdict is decided; this file
is the only thing that knows how to feed it.

**On ``confidence``** — it is not a probability, and it is not decoration. It
answers "how much did we actually know when we said that?":

  * 1.0  a decisive signal was present (revoked passport, active kill switch,
         critical anomaly, explicit policy BLOCK). We are not guessing.
  * ~0.6 the verdict rests on inference (drift, a suspected-but-uncorroborated
         signal).
  * low  we said ALLOW while the pillars returned little or nothing about this
         agent. An ALLOW on an empty evidence set is a confession of ignorance,
         and it should read like one rather than looking identical to an ALLOW
         backed by a fresh attestation and a clean policy evaluation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from modules.identity import agent_assurance

Question = Literal["verify", "authorize", "contain"]

# Verdict states, in ascending severity.
ALLOW = "ALLOW"
STEP_UP = "STEP_UP"
BLOCK = "BLOCK"
REVOKE = "REVOKE"

DECISIVE = 1.0
INFERRED = 0.6


@dataclass(frozen=True)
class Subject:
    """Everything the three questions can be asked *about*. Each question reads
    only the fields it needs; the rest stay None."""
    tenant_id: str
    agent_id: str
    # VERIFY
    passport: dict[str, Any] | None = None
    dpop_proof: str | None = None
    dpop_method: str = "POST"
    dpop_uri: str = ""
    # AUTHORIZE
    action: str = ""
    resource: str = ""
    destination: str = ""
    claims: dict[str, Any] | None = None   # the agent's verified token claims
    # CONTAIN
    window_hours: int = 24
    max_hops: int = 6


@dataclass(frozen=True)
class Verdict:
    agent_id: str
    question: str
    verdict: str
    confidence: float
    reasons: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    blast_radius: dict[str, Any] | None = None
    recommended_action: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "question": self.question,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 2),
            "reasons": self.reasons,
            "evidence": self.evidence,
            "blast_radius": self.blast_radius,
            "recommended_action": self.recommended_action,
        }


def evaluate(question: str, subject: Subject) -> Verdict:
    """The one code path. Every /v1 endpoint, the SDK, and the console call this."""
    if question == "verify":
        return _verify(subject)
    if question == "authorize":
        return _authorize(subject)
    if question == "contain":
        return _contain(subject)
    raise ValueError(f"unknown question: {question!r} (expected verify|authorize|contain)")


# ── Shared: hand scoring to agent_assurance, map its answer to a Verdict ───────
#
# agent_assurance scores THREE dimensions at once — identity, policy, compromise —
# and blocks if any one of them is unsatisfied. That is right for a single
# all-evidence assessment, but each of our three questions deliberately owns only
# one dimension. Passing an empty list for a dimension a question does not ask
# about would silently read as "denied" (no credentials → unverified → BLOCK; no
# grants → denied → BLOCK), so every question must mark its out-of-scope
# dimensions as explicitly neutral. That is the contract of the three-question
# split: /v1/authorize does not re-verify identity, it presumes /v1/verify
# answered that. Composing them is the caller's job, and the console/SDK do.

def _neutral_credential(agent_id: str) -> agent_assurance.CredentialEvidence:
    """Identity is not this question's business — do not let it vote."""
    return agent_assurance.CredentialEvidence(
        credential_id="not-in-scope", agent_id=agent_id, status="active",
        trust_score=1.0, evidence_type="out-of-scope",
    )


def _neutral_grant() -> agent_assurance.PermissionGrant:
    """Policy is not this question's business — do not let it vote."""
    return agent_assurance.PermissionGrant(
        permission="*", resource_pattern="*", source="out-of-scope",
    )


def _score(
    subject: Subject,
    *,
    credentials: list[agent_assurance.CredentialEvidence],
    grants: list[agent_assurance.PermissionGrant],
    signals: list[agent_assurance.CompromiseSignal],
    blast: agent_assurance.BlastRadiusSummary | None,
) -> agent_assurance.AgentAssuranceVerdict:
    return agent_assurance.assess_agent_action(agent_assurance.AgentActionRequest(
        tenant_id=subject.tenant_id,
        agent_id=subject.agent_id,
        action=subject.action or "*",
        resource=subject.resource or "*",
        credentials=credentials,
        permission_grants=grants,
        compromise_signals=signals,
        blast_radius=blast,
    ))


def _map_outcome(assurance: agent_assurance.AgentAssuranceVerdict) -> str:
    """agent_assurance answers allow/review/block. The product surface needs a
    fourth state — REVOKE — for the case where containment, not refusal, is the
    correct action: the agent is already compromised, so blocking this one request
    is not enough."""
    if assurance.outcome == "block":
        if assurance.compromise_status == "compromised":
            return REVOKE
        return BLOCK
    if assurance.outcome == "review":
        return STEP_UP
    return ALLOW


def _confidence(verdict: str, *, decisive: bool, evidence_count: int) -> float:
    if decisive:
        return DECISIVE
    if verdict == ALLOW:
        # An ALLOW backed by nothing is not the same as an ALLOW backed by a fresh
        # attestation and a clean policy evaluation. Say so.
        return min(0.9, 0.3 + 0.2 * evidence_count)
    return INFERRED


# ── VERIFY ────────────────────────────────────────────────────────────────────

def _verify(subject: Subject) -> Verdict:
    from modules.identity import passport as passport_mod
    from modules.identity import proof_of_control

    evidence: list[dict[str, Any]] = []
    reasons: list[str] = []
    credentials: list[agent_assurance.CredentialEvidence] = []
    decisive = False

    # 1. Passport — the credential of record.
    if subject.passport:
        result = passport_mod.verify_passport(subject.passport)
        evidence.append({"check": "passport", **result})
        valid = bool(result.get("valid"))
        reason = result.get("reason") or ""
        status = "active" if valid else (
            "revoked" if "revoked" in reason.lower() else "expired"
        )
        credentials.append(agent_assurance.CredentialEvidence(
            credential_id=str(subject.passport.get("passport_id", "unknown")),
            agent_id=subject.agent_id,
            status=status,
            trust_score=1.0 if valid else 0.0,
            evidence_type="passport",
        ))
        if not valid:
            decisive = True  # an explicit revocation/expiry is not an inference
            reasons.append(f"passport verification failed: {reason}")
    else:
        reasons.append("no passport presented")

    # 2. DPoP proof-of-possession (D-2: wire dpop into the VERIFY verdict).
    #
    #    A failed proof is not a footnote. Proof-of-possession failing means the
    #    presenter cannot demonstrate they hold the key the credential is bound to
    #    — so the credential is not theirs, whatever the passport says. We model
    #    that by dropping the credential's trust to zero, which makes the identity
    #    UNVERIFIED in the scoring brain, rather than by bolting a special case
    #    onto the verdict afterwards.
    if subject.dpop_proof:
        from modules.identity import dpop
        dpop_ok = True
        try:
            proof = dpop.verify_dpop_proof(
                subject.dpop_proof, subject.dpop_method, subject.dpop_uri,
            )
            dpop_ok = bool(getattr(proof, "valid", True))
            evidence.append({"check": "dpop", "valid": dpop_ok,
                             "jkt": getattr(proof, "jkt", None)})
            if not dpop_ok:
                reasons.append("DPoP proof-of-possession failed")
        except Exception as exc:  # noqa: BLE001 — a bad proof is a finding, not a 500
            dpop_ok = False
            evidence.append({"check": "dpop", "valid": False, "error": str(exc)})
            reasons.append(f"DPoP proof rejected: {exc}")

        if not dpop_ok:
            decisive = True
            credentials = [
                agent_assurance.CredentialEvidence(
                    credential_id=c.credential_id, agent_id=c.agent_id,
                    status=c.status, trust_score=0.0,
                    evidence_type=c.evidence_type,
                )
                for c in credentials
            ]

    # 3. Proof-of-control freshness — a passport says who; this says still-in-control.
    try:
        status = proof_of_control.get_proof_status(subject.agent_id, subject.tenant_id)
    except Exception:  # noqa: BLE001
        status = None
    if status is not None:
        overdue = bool(getattr(status, "overdue", False))
        evidence.append({"check": "proof_of_control", "overdue": overdue})
        if overdue:
            reasons.append("proof-of-control is overdue — step up before trusting")

    # Identity is the question; policy is not. (Absent credentials DO vote here —
    # "no passport presented" is a real verify failure, not an out-of-scope dimension.)
    assurance = _score(subject, credentials=credentials, grants=[_neutral_grant()],
                       signals=[], blast=None)
    verdict = _map_outcome(assurance)

    # A valid passport with a stale proof-of-control is not a BLOCK — it is a
    # step-up: the identity is real, our evidence that it is still controlled is not.
    if verdict == ALLOW and any(
        e.get("check") == "proof_of_control" and e.get("overdue") for e in evidence
    ):
        verdict = STEP_UP

    reasons = reasons + [r for r in assurance.reasons if r not in reasons]
    return Verdict(
        agent_id=subject.agent_id,
        question="verify",
        verdict=verdict,
        confidence=_confidence(verdict, decisive=decisive, evidence_count=len(evidence)),
        reasons=reasons,
        evidence=evidence,
        recommended_action=_recommend(verdict, assurance),
    )


# ── AUTHORIZE ─────────────────────────────────────────────────────────────────

def _authorize(subject: Subject) -> Verdict:
    from modules.identity import enforcement_plane, permission_drift

    evidence: list[dict[str, Any]] = []
    reasons: list[str] = []
    signals: list[agent_assurance.CompromiseSignal] = []
    grants: list[agent_assurance.PermissionGrant] = []
    decisive = False

    # 1. The enforcement plane already composes kill-switch + active policies.
    decision = enforcement_plane.evaluate(
        subject.tenant_id, subject.agent_id, subject.action or "*",
        resource=subject.resource or "*",
        context={"destination": subject.destination} if subject.destination else {},
    )
    evidence.append({"check": "enforcement_plane", **decision})
    reasons.extend(decision.get("reasons") or [])

    blocked = bool(decision.get("blocked"))
    if blocked:
        decisive = True  # a kill switch or an explicit policy BLOCK is not a guess
        if decision.get("kill_switched"):
            signals.append(agent_assurance.CompromiseSignal(
                signal_type="kill_switch_active", severity="critical",
                detail="agent credentials have been ripped",
            ))
    else:
        # The plane allowed it, so the action is permitted for this agent.
        grants.append(agent_assurance.PermissionGrant(
            permission=subject.action or "*",
            resource_pattern=subject.resource or "*",
            source="enforcement_plane",
        ))

    # 2. Permission drift — allowed today, but has its authority been creeping?
    try:
        alerts = permission_drift.list_alerts(
            subject.tenant_id, status="open", agent_id=subject.agent_id,
        )
    except Exception:  # noqa: BLE001
        alerts = []
    for alert in alerts:
        sev = str(getattr(alert, "severity", "medium")).lower()
        evidence.append({"check": "permission_drift", "severity": sev,
                         "detail": str(getattr(alert, "reason", ""))})
        signals.append(agent_assurance.CompromiseSignal(
            signal_type="permission_drift",
            severity=sev if sev in ("low", "medium", "high", "critical") else "medium",
            detail=str(getattr(alert, "reason", "permission drift detected")),
        ))

    # 3. Token scopes (D-2: wire modules.auth.scopes into the AUTHORIZE verdict).
    #    Only meaningful when the caller passes the agent's verified token claims.
    #    We honour the module's own rollout switch: scopes are log-only until
    #    TOKENDNA_SCOPES_ENFORCE is on, so turning this on cannot silently start
    #    denying traffic that used to flow.
    scope_denied = False
    if subject.claims:
        from modules.auth import scopes as scopes_mod

        held = scopes_mod.held_scopes(subject.claims)
        needed = subject.action or "*"
        covered = bool(held) and (needed in held or "*" in held)
        enforcing = scopes_mod.enforcement_enabled()
        evidence.append({"check": "scopes", "held": sorted(held), "needed": needed,
                         "covered": covered, "enforcing": enforcing})
        if not covered:
            if enforcing:
                scope_denied = True
                decisive = True
                reasons.append(f"token does not hold the '{needed}' scope — denied")
            else:
                reasons.append(
                    f"token does not hold the '{needed}' scope "
                    "(scope enforcement is in log-only rollout — not denied)"
                )

    if subject.destination:
        reasons.append(f"destination {subject.destination} evaluated against agent scope")

    # Policy is the question; identity is /v1/verify's job.
    assurance = _score(subject, credentials=[_neutral_credential(subject.agent_id)],
                       grants=grants, signals=signals, blast=None)
    # The enforcement plane is authoritative on allow/deny; agent_assurance layers
    # the compromise view on top. Never soften a BLOCK the plane already issued.
    verdict = _map_outcome(assurance)
    if (blocked or scope_denied) and verdict == ALLOW:
        verdict = BLOCK

    reasons = reasons + [r for r in assurance.reasons if r not in reasons]
    return Verdict(
        agent_id=subject.agent_id,
        question="authorize",
        verdict=verdict,
        confidence=_confidence(verdict, decisive=decisive, evidence_count=len(evidence)),
        reasons=reasons,
        evidence=evidence,
        recommended_action=_recommend(verdict, assurance),
    )


# ── CONTAIN ───────────────────────────────────────────────────────────────────

def _contain(subject: Subject) -> Verdict:
    from modules.identity import behavioral_dna, mcp_inspector, trace_report, trust_graph

    evidence: list[dict[str, Any]] = []
    signals: list[agent_assurance.CompromiseSignal] = []
    decisive = False

    # 1. Trust-graph anomalies.
    for a in _safe(lambda: trust_graph.get_anomalies(subject.tenant_id, limit=100), []):
        ctx = a.get("context") or {}
        if ctx.get("agent_label") not in (None, subject.agent_id):
            continue
        sev = str(a.get("severity", "medium")).lower()
        evidence.append({"check": "trust_graph_anomaly",
                         "type": a.get("anomaly_type"), "severity": sev})
        signals.append(agent_assurance.CompromiseSignal(
            signal_type=str(a.get("anomaly_type", "anomaly")),
            severity=sev if sev in ("low", "medium", "high", "critical") else "medium",
            detail=str(a.get("detail", "")),
        ))
        if sev == "critical":
            decisive = True

    # 2. Behavioural drift.
    for alert in _safe(lambda: behavioral_dna.list_drift_alerts(
            subject.tenant_id, agent_id=subject.agent_id), []):
        evidence.append({"check": "behavioral_drift", "detail": alert})
        signals.append(agent_assurance.CompromiseSignal(
            signal_type="behavioral_drift", severity="high",
            detail=str(alert.get("reason", "behavioural drift detected")),
        ))

    # 3. Open MCP violations (chain hits).
    for v in _safe(lambda: mcp_inspector.list_violations(
            tenant_id=subject.tenant_id, resolved=False), []):
        if v.get("agent_id") not in (None, subject.agent_id):
            continue
        evidence.append({"check": "mcp_violation", "detail": v.get("violation_type")})
        signals.append(agent_assurance.CompromiseSignal(
            signal_type="mcp_violation", severity="high",
            detail=str(v.get("violation_type", "MCP violation")),
        ))

    # 4. Blast radius + the tamper-evident trace (P2.2).
    report = trace_report.build_trace_report(
        subject.tenant_id, subject.agent_id,
        window_hours=subject.window_hours, max_hops=subject.max_hops,
    )
    blast = report.blast_radius or {}
    summary = agent_assurance.BlastRadiusSummary(
        impact_score=int(blast.get("impact_score", 0)),
        risk_tier=blast.get("risk_tier", "low"),
        total_nodes_reached=int(blast.get("total_nodes_reached", 0)),
        affected_assets=list(blast.get("affected_resources", [])),
    ) if blast else None

    # Compromise is the question; identity and policy are the other two endpoints'.
    assurance = _score(subject, credentials=[_neutral_credential(subject.agent_id)],
                       grants=[_neutral_grant()], signals=signals, blast=summary)
    verdict = _map_outcome(assurance)

    blast_out = {
        **blast,
        "trace": [r.as_dict() for r in report.rows],
        "trace_report_hash": report.report_hash,
        "trace_verification": trace_report.verify_trace_report(report),
    }

    return Verdict(
        agent_id=subject.agent_id,
        question="contain",
        verdict=verdict,
        confidence=_confidence(verdict, decisive=decisive, evidence_count=len(evidence)),
        reasons=assurance.reasons,
        evidence=evidence,
        blast_radius=blast_out,
        recommended_action=_recommend(verdict, assurance),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(fn, default):
    """A pillar with no data yet must not sink the verdict — but it must not be
    silently treated as 'clean' either: the missing evidence lowers confidence."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        return default


def _recommend(verdict: str, assurance: agent_assurance.AgentAssuranceVerdict) -> str:
    if verdict == REVOKE:
        return "revoke credentials across every plane (POST /v1/contain/{agent}/revoke)"
    if verdict == BLOCK:
        return assurance.remediation[0] if assurance.remediation else "deny this action"
    if verdict == STEP_UP:
        return "require step-up verification before allowing this action"
    return "allow and continue monitoring"

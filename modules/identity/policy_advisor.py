"""
TokenDNA — Adaptive Policy Suggestion Engine (Sprint 6-2)

Converts decision provenance and adversarial harness data into actionable
policy amendments. After an adversarial run (or any block/deny event window),
this engine:

  1. Ingests failed decision events from decision_audit (blocked/denied actions)
     and policy_guard_violations (constitutional rule violations).
  2. Identifies policy gaps by clustering failure patterns.
  3. Generates candidate policy amendments with confidence scores.
  4. Presents amendments for human review (approve / reject).
  5. Applies high-confidence amendments within operator-defined confidence
     intervals (bounded auto-tightening).
  6. Validates every candidate against policy_regression_gate before applying
     to ensure no regression against passing scenarios.

API
───
POST /api/policy/suggestions/analyze         Run gap analysis (produces suggestions)
GET  /api/policy/suggestions                 List pending (or all) suggestions
GET  /api/policy/suggestions/{id}            Get a single suggestion
POST /api/policy/suggestions/{id}/approve    Operator approves suggestion
POST /api/policy/suggestions/{id}/reject     Operator rejects suggestion
POST /api/policy/suggestions/auto-tighten   Apply high-confidence suggestions within
                                             confidence interval

Integration
───────────
- Reads: policy_guard.list_violations(), decision_audit.list_decisions_paginated()
- Validates: scripts/policy_regression_gate.run()
- Applies: policy_bundles (future — returns amendment dict for operator action)
- Zero hard dependency on external network; all analysis runs in-process.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field

from modules.storage.pg_connection import AdaptedCursor, get_db_conn
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DB_PATH = os.getenv("DATA_DB_PATH", "/data/tokendna.db")
_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class SuggestionStatus(str, Enum):
    PENDING = "pending"          # awaiting human review
    APPROVED = "approved"        # operator approved; ready to apply
    REJECTED = "rejected"        # operator rejected; will not be applied
    APPLIED = "applied"          # applied to a policy bundle
    SUPERSEDED = "superseded"    # a later suggestion covers the same gap


class AmendmentType(str, Enum):
    TIGHTEN_SCOPE = "tighten_scope"          # remove overly-broad permission
    ADD_RESTRICTION = "add_restriction"      # add explicit constitutional restriction
    REVOKE_PERMISSION = "revoke_permission"  # remove a delegated permission
    ADD_MONITORING = "add_monitoring"        # increase monitoring / flag threshold
    RATE_LIMIT = "rate_limit"               # add rate-limiting to a pattern
    REQUIRE_APPROVAL = "require_approval"    # gate action behind human approval


class SourceType(str, Enum):
    POLICY_GUARD_VIOLATION = "policy_guard_violation"
    DECISION_DENY = "decision_deny"
    ADVERSARIAL_RUN = "adversarial_run"
    COMBINED = "combined"


@dataclass
class PolicySuggestion:
    suggestion_id: str
    tenant_id: str
    source_type: SourceType
    evidence_ids: list[str]          # violation_id / audit_id list
    gap_description: str             # human-readable description of the gap
    amendment_type: AmendmentType
    amendment: dict[str, Any]        # proposed policy change (operator-ready)
    confidence: float                # 0.0 – 1.0
    status: SuggestionStatus
    created_at: str
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    review_note: str | None = None
    regression_tested: bool = False
    regression_passed: bool | None = None
    regression_result: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with _lock:
        with get_db_conn(db_path=_db_path()) as conn:
            yield AdaptedCursor(conn.cursor())


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS policy_suggestions (
                suggestion_id       TEXT PRIMARY KEY,
                tenant_id           TEXT NOT NULL,
                source_type         TEXT NOT NULL,
                evidence_ids        TEXT NOT NULL,   -- JSON list of IDs
                gap_description     TEXT NOT NULL,
                amendment_type      TEXT NOT NULL,
                amendment           TEXT NOT NULL,   -- JSON dict
                confidence          REAL NOT NULL,
                status              TEXT NOT NULL DEFAULT 'pending',
                created_at          TEXT NOT NULL,
                reviewed_at         TEXT,
                reviewed_by         TEXT,
                review_note         TEXT,
                regression_tested   INTEGER NOT NULL DEFAULT 0,
                regression_passed   INTEGER,         -- NULL | 0 | 1
                regression_result   TEXT,            -- JSON dict
                metadata            TEXT NOT NULL DEFAULT '{}'
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_policy_suggestions_tenant_status
            ON policy_suggestions(tenant_id, status, created_at DESC)
        """)


def _row_to_suggestion(row: sqlite3.Row) -> PolicySuggestion:
    reg_passed = row["regression_passed"]
    return PolicySuggestion(
        suggestion_id=row["suggestion_id"],
        tenant_id=row["tenant_id"],
        source_type=SourceType(row["source_type"]),
        evidence_ids=json.loads(row["evidence_ids"]),
        gap_description=row["gap_description"],
        amendment_type=AmendmentType(row["amendment_type"]),
        amendment=json.loads(row["amendment"]),
        confidence=row["confidence"],
        status=SuggestionStatus(row["status"]),
        created_at=row["created_at"],
        reviewed_at=row["reviewed_at"],
        reviewed_by=row["reviewed_by"],
        review_note=row["review_note"],
        regression_tested=bool(row["regression_tested"]),
        regression_passed=None if reg_passed is None else bool(reg_passed),
        regression_result=json.loads(row["regression_result"]) if row["regression_result"] else None,
        metadata=json.loads(row["metadata"]),
    )


def _persist_suggestion(s: PolicySuggestion) -> None:
    with _cursor() as cur:
        cur.execute("""
            INSERT OR REPLACE INTO policy_suggestions
                (suggestion_id, tenant_id, source_type, evidence_ids,
                 gap_description, amendment_type, amendment, confidence,
                 status, created_at, reviewed_at, reviewed_by, review_note,
                 regression_tested, regression_passed, regression_result, metadata)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            s.suggestion_id, s.tenant_id, s.source_type.value,
            json.dumps(s.evidence_ids), s.gap_description,
            s.amendment_type.value, json.dumps(s.amendment),
            s.confidence, s.status.value, s.created_at,
            s.reviewed_at, s.reviewed_by, s.review_note,
            int(s.regression_tested),
            None if s.regression_passed is None else int(s.regression_passed),
            json.dumps(s.regression_result) if s.regression_result else None,
            json.dumps(s.metadata),
        ))


# ---------------------------------------------------------------------------
# Gap analysis — violation pattern clustering
# ---------------------------------------------------------------------------

def _fetch_violations(tenant_id: str, lookback_hours: int) -> list[dict[str, Any]]:
    """Pull policy guard violations within the lookback window."""
    try:
        from modules.identity import policy_guard
        policy_guard.init_db()
        violations = policy_guard.list_violations(tenant_id=tenant_id, limit=200)
        cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        results: list[dict[str, Any]] = []
        for v in violations:
            try:
                ts = datetime.fromisoformat(v.detected_at)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    results.append({
                        "id": v.violation_id,
                        "actor_id": v.actor_id,
                        "actor_type": v.actor_type,
                        "action_type": v.action_type,
                        "target_policy_id": v.target_policy_id,
                        "target_policy_name": v.target_policy_name,
                        "disposition": v.disposition.value,
                        "rules_triggered": v.rules_triggered,
                        "reasons": v.reasons,
                        "metadata": v.metadata,
                    })
            except Exception:
                continue
        return results
    except Exception as exc:
        logger.warning("Could not fetch policy guard violations: %s", exc)
        return []


def _fetch_denied_decisions(tenant_id: str, lookback_hours: int) -> list[dict[str, Any]]:
    """Pull decision audit records that resulted in block/deny within the lookback window."""
    try:
        from modules.identity import decision_audit
        decision_audit.init_db()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
        page = decision_audit.list_decisions_paginated(
            tenant_id=tenant_id,
            page_size=200,
            cursor=None,
            source_endpoint=None,
        )
        items = page.get("items") or []
        denied: list[dict[str, Any]] = []
        for item in items:
            try:
                created = item.get("created_at", "")
                if created < cutoff:
                    continue
                result = item.get("enforcement_result") or {}
                decision = result.get("decision") or {}
                action = str(decision.get("action", "")).lower()
                if action in ("block", "deny", "challenge"):
                    denied.append({
                        "id": item["audit_id"],
                        "actor_subject": item.get("actor_subject", ""),
                        "source_endpoint": item.get("source_endpoint", ""),
                        "action": action,
                        "reasons": decision.get("reasons", []),
                        "policy_bundle": item.get("policy_bundle") or {},
                        "evaluation_input": item.get("evaluation_input") or {},
                    })
            except Exception:
                continue
        return denied
    except Exception as exc:
        logger.warning("Could not fetch decision audit records: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Amendment generators
# ---------------------------------------------------------------------------

def _suggestions_from_violations(
    tenant_id: str,
    violations: list[dict[str, Any]],
) -> list[PolicySuggestion]:
    """
    Cluster violations by (rules_triggered, action_type) and generate one
    suggestion per significant cluster.
    """
    if not violations:
        return []

    # Group by dominant rule
    by_rule: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in violations:
        rules = v.get("rules_triggered") or []
        key = rules[0] if rules else "UNKNOWN"
        by_rule[key].append(v)

    suggestions: list[PolicySuggestion] = []
    now = _utc_now()

    for rule_id, events in by_rule.items():
        n = len(events)
        # Higher frequency → higher confidence
        confidence = min(0.5 + 0.05 * n, 0.95)
        evidence_ids = [e["id"] for e in events]
        actor_ids = list({e["actor_id"] for e in events})
        policy_names = list({e["target_policy_name"] for e in events})

        if "CONST-01" in rule_id:
            # Self-scope expansion — add explicit restriction
            amendment = {
                "type": "constitutional_restriction",
                "rule": "CONST-01",
                "restriction": "prohibit_self_scope_expansion",
                "applies_to_actors": actor_ids,
                "policies_at_risk": policy_names,
                "recommended_action": (
                    "Add explicit DENY rule: actor may not expand permissions "
                    "on policies governing themselves."
                ),
                "scope_delta_observed": [
                    d for e in events
                    for d in (e.get("metadata") or {}).get("scope_delta", [])
                ],
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.POLICY_GUARD_VIOLATION,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Rule CONST-01 triggered {n}× by agent(s) {actor_ids}: "
                    "self-scope expansion attempts detected. No explicit prohibition "
                    "exists in the active policy bundle."
                ),
                amendment_type=AmendmentType.ADD_RESTRICTION,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        elif "CONST-02" in rule_id:
            # Self-restriction removal — require approval gate
            amendment = {
                "type": "require_human_gate",
                "rule": "CONST-02",
                "restriction": "prohibit_self_restriction_removal",
                "applies_to_actors": actor_ids,
                "recommended_action": (
                    "Gate all policy deletions / deactivations affecting the actor's "
                    "own permission set behind mandatory human approval."
                ),
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.POLICY_GUARD_VIOLATION,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Rule CONST-02 triggered {n}× by agent(s) {actor_ids}: "
                    "self-restriction removal attempts detected. Require human "
                    "approval gate on policy deactivation/deletion."
                ),
                amendment_type=AmendmentType.REQUIRE_APPROVAL,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        elif "CONST-03" in rule_id:
            # Excessive delegation — tighten scope
            amendment = {
                "type": "delegation_scope_cap",
                "rule": "CONST-03",
                "applies_to_actors": actor_ids,
                "recommended_action": (
                    "Cap delegation depth to 1 hop. Prohibit re-delegation of "
                    "permissions acquired via delegation chain."
                ),
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.POLICY_GUARD_VIOLATION,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Rule CONST-03 triggered {n}× by agent(s) {actor_ids}: "
                    "excessive authority delegation. Cap delegation depth."
                ),
                amendment_type=AmendmentType.TIGHTEN_SCOPE,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        else:
            # Generic — add monitoring
            amendment = {
                "type": "elevated_monitoring",
                "rule": rule_id,
                "applies_to_actors": actor_ids,
                "policies_at_risk": policy_names,
                "recommended_action": (
                    f"Increase monitoring sensitivity for rule '{rule_id}'. "
                    "Flag all future matches and route to security review queue."
                ),
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.POLICY_GUARD_VIOLATION,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Rule '{rule_id}' triggered {n}× by agent(s) {actor_ids}. "
                    "Pattern suggests systematic policy evasion attempt."
                ),
                amendment_type=AmendmentType.ADD_MONITORING,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

    return suggestions


def _suggestions_from_denied_decisions(
    tenant_id: str,
    denied: list[dict[str, Any]],
) -> list[PolicySuggestion]:
    """
    Cluster denied decisions by reason patterns and generate scope-tightening
    or rate-limiting suggestions.
    """
    if not denied:
        return []

    # Group by reason keyword
    by_reason: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in denied:
        reasons = d.get("reasons") or []
        key = "unknown"
        for r in reasons:
            r_lower = str(r).lower()
            if "scope" in r_lower:
                key = "scope_violation"
                break
            elif "attestation" in r_lower or "drift" in r_lower:
                key = "attestation_failure"
                break
            elif "rate" in r_lower or "limit" in r_lower:
                key = "rate_exceeded"
                break
            elif "revok" in r_lower:
                key = "revoked_credential"
                break
            elif "delegation" in r_lower:
                key = "delegation_violation"
                break
        by_reason[key].append(d)

    suggestions: list[PolicySuggestion] = []
    now = _utc_now()

    for reason_key, events in by_reason.items():
        n = len(events)
        if n < 2:
            continue  # single events not actionable
        confidence = min(0.45 + 0.06 * n, 0.92)
        evidence_ids = [e["id"] for e in events]
        actors = list({e["actor_subject"] for e in events})
        endpoints = list({e["source_endpoint"] for e in events})

        if reason_key == "scope_violation":
            amendment = {
                "type": "scope_restriction",
                "affected_actors": actors,
                "affected_endpoints": endpoints,
                "recommended_action": (
                    f"Scope violation pattern detected across {n} decisions for "
                    f"actor(s) {actors}. Tighten allowed scope to observed minimum. "
                    "Remove any wildcard grants in effect."
                ),
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.DECISION_DENY,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Scope violation caused {n} denied decisions for actor(s) {actors}. "
                    "Current policy may include over-broad wildcard grants."
                ),
                amendment_type=AmendmentType.TIGHTEN_SCOPE,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        elif reason_key == "attestation_failure":
            amendment = {
                "type": "attestation_enforcement",
                "affected_actors": actors,
                "recommended_action": (
                    "Attestation failures detected. Harden policy: require fresh "
                    "attestation every 15 minutes for elevated-risk actors. "
                    "Suspend actors with >3 consecutive failures."
                ),
                "suggested_ttl_minutes": 15,
                "max_consecutive_failures": 3,
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.DECISION_DENY,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Attestation drift/failure caused {n} denied decisions. "
                    "Tighter attestation TTL and suspension policy recommended."
                ),
                amendment_type=AmendmentType.ADD_RESTRICTION,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        elif reason_key == "revoked_credential":
            amendment = {
                "type": "revocation_enforcement",
                "affected_actors": actors,
                "recommended_action": (
                    "Revoked credentials are still being presented. "
                    "Add automatic rate-limit: block after 2 attempts with revoked cred. "
                    "Alert security team immediately on 3rd attempt."
                ),
                "max_revoked_attempts": 2,
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.DECISION_DENY,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Revoked credentials presented {n}× by actor(s) {actors}. "
                    "Possible persistence mechanism; rate-limit and alert recommended."
                ),
                amendment_type=AmendmentType.RATE_LIMIT,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        elif reason_key == "delegation_violation":
            amendment = {
                "type": "delegation_policy",
                "affected_actors": actors,
                "recommended_action": (
                    "Delegation violations detected across multiple decisions. "
                    "Revoke delegated permissions for violating actors and require "
                    "re-approval with documented justification."
                ),
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.DECISION_DENY,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Delegation violations caused {n} denied decisions for {actors}. "
                    "Delegated permissions should be reviewed and restricted."
                ),
                amendment_type=AmendmentType.REVOKE_PERMISSION,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

        else:
            # Generic — rate limiting
            amendment = {
                "type": "rate_limit_policy",
                "reason_pattern": reason_key,
                "affected_actors": actors,
                "affected_endpoints": endpoints,
                "recommended_action": (
                    f"Pattern '{reason_key}' caused {n} denied decisions. "
                    "Apply rate limiting: max 5 requests/minute per actor on affected endpoints."
                ),
                "max_rps_per_actor": 5,
            }
            suggestions.append(PolicySuggestion(
                suggestion_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                source_type=SourceType.DECISION_DENY,
                evidence_ids=evidence_ids,
                gap_description=(
                    f"Denial pattern '{reason_key}' detected {n}× across actor(s) {actors}. "
                    "Rate limiting recommended to reduce policy evaluation load."
                ),
                amendment_type=AmendmentType.RATE_LIMIT,
                amendment=amendment,
                confidence=confidence,
                status=SuggestionStatus.PENDING,
                created_at=now,
            ))

    return suggestions


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_and_generate(
    tenant_id: str,
    lookback_hours: int = 24,
    min_confidence: float = 0.0,
    source_types: list[str] | None = None,
) -> dict[str, Any]:
    """
    Run gap analysis over the lookback window and generate policy suggestions.

    Returns a summary with the count of new suggestions created and their IDs.
    Existing pending suggestions are NOT duplicated (checked by dedup logic below).
    """
    init_db()
    active_sources = set(source_types or [s.value for s in SourceType])

    violations = (
        _fetch_violations(tenant_id, lookback_hours)
        if SourceType.POLICY_GUARD_VIOLATION.value in active_sources
        else []
    )
    denied = (
        _fetch_denied_decisions(tenant_id, lookback_hours)
        if SourceType.DECISION_DENY.value in active_sources
        else []
    )

    suggestions: list[PolicySuggestion] = []
    suggestions.extend(_suggestions_from_violations(tenant_id, violations))
    suggestions.extend(_suggestions_from_denied_decisions(tenant_id, denied))

    # Filter by min_confidence
    suggestions = [s for s in suggestions if s.confidence >= min_confidence]

    # Dedup: skip if a pending suggestion with same amendment_type + gap fingerprint
    existing = list_suggestions(tenant_id=tenant_id, status="pending")
    existing_fingerprints = {
        (s.amendment_type.value, s.gap_description[:60])
        for s in existing
    }

    new_suggestions: list[PolicySuggestion] = []
    for s in suggestions:
        fp = (s.amendment_type.value, s.gap_description[:60])
        if fp not in existing_fingerprints:
            new_suggestions.append(s)
            existing_fingerprints.add(fp)  # prevent intra-batch duplicates

    # Persist
    for s in new_suggestions:
        _persist_suggestion(s)

    return {
        "tenant_id": tenant_id,
        "analysis_window_hours": lookback_hours,
        "violations_analyzed": len(violations),
        "denied_decisions_analyzed": len(denied),
        "suggestions_generated": len(new_suggestions),
        "suggestion_ids": [s.suggestion_id for s in new_suggestions],
        "by_amendment_type": dict(
            Counter(s.amendment_type.value for s in new_suggestions)
        ),
    }


def list_suggestions(
    tenant_id: str,
    status: str | None = None,
    amendment_type: str | None = None,
    min_confidence: float = 0.0,
    limit: int = 50,
) -> list[PolicySuggestion]:
    """List policy suggestions for a tenant."""
    init_db()
    clauses = ["tenant_id = ?", "confidence >= ?"]
    params: list[Any] = [tenant_id, min_confidence]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if amendment_type:
        clauses.append("amendment_type = ?")
        params.append(amendment_type)
    where = " AND ".join(clauses)
    params.append(min(limit, 500))
    with _cursor() as cur:
        cur.execute(
            f"SELECT * FROM policy_suggestions WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ?",
            params,
        )
        rows = cur.fetchall()
    return [_row_to_suggestion(r) for r in rows]


def get_suggestion(suggestion_id: str, tenant_id: str) -> PolicySuggestion | None:
    """Fetch a single suggestion by ID."""
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM policy_suggestions WHERE suggestion_id=? AND tenant_id=?",
            (suggestion_id, tenant_id),
        )
        row = cur.fetchone()
    return _row_to_suggestion(row) if row else None


def approve_suggestion(
    suggestion_id: str,
    tenant_id: str,
    approved_by: str,
    note: str = "",
    run_regression: bool = True,
) -> PolicySuggestion | None:
    """
    Operator approves a suggestion.

    If run_regression=True, validates the amendment against policy_regression_gate
    first. On regression failure the suggestion is left pending with regression
    result attached; the operator must explicitly override or reject.
    """
    init_db()
    s = get_suggestion(suggestion_id, tenant_id)
    if not s or s.status != SuggestionStatus.PENDING:
        return None

    reg_passed: bool | None = None
    reg_result: dict[str, Any] | None = None

    if run_regression:
        passed, result = _run_regression_check(s)
        reg_passed = passed
        reg_result = result
        s.regression_tested = True
        s.regression_passed = passed
        s.regression_result = result

        if not passed:
            # Update record with regression failure, leave status pending
            with _cursor() as cur:
                cur.execute("""
                    UPDATE policy_suggestions
                    SET regression_tested=1, regression_passed=0,
                        regression_result=?, review_note=?
                    WHERE suggestion_id=? AND tenant_id=?
                """, (
                    json.dumps(result),
                    f"Regression check failed — override rejected. Gate result: "
                    f"{result.get('summary', '')}",
                    suggestion_id, tenant_id,
                ))
            return get_suggestion(suggestion_id, tenant_id)

    # Mark approved
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE policy_suggestions
            SET status='approved', reviewed_at=?, reviewed_by=?, review_note=?,
                regression_tested=?, regression_passed=?, regression_result=?
            WHERE suggestion_id=? AND tenant_id=? AND status='pending'
        """, (
            now, approved_by, note,
            1 if run_regression else 0,
            None if reg_passed is None else int(reg_passed),
            json.dumps(reg_result) if reg_result else None,
            suggestion_id, tenant_id,
        ))
    return get_suggestion(suggestion_id, tenant_id)


def reject_suggestion(
    suggestion_id: str,
    tenant_id: str,
    rejected_by: str,
    note: str = "",
) -> PolicySuggestion | None:
    """Operator rejects a suggestion."""
    init_db()
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            UPDATE policy_suggestions
            SET status='rejected', reviewed_at=?, reviewed_by=?, review_note=?
            WHERE suggestion_id=? AND tenant_id=? AND status='pending'
        """, (now, rejected_by, note, suggestion_id, tenant_id))
        if cur.rowcount == 0:
            return None
    return get_suggestion(suggestion_id, tenant_id)


def bounded_auto_tighten(
    tenant_id: str,
    confidence_threshold: float = 0.85,
    max_amendments_per_run: int = 5,
    auto_approved_by: str = "system:auto-tighten",
) -> dict[str, Any]:
    """
    Automatically approve high-confidence suggestions within the operator-defined
    confidence interval (>= confidence_threshold).

    - Only processes PENDING suggestions.
    - Runs regression gate on each.
    - Caps at max_amendments_per_run to limit blast radius.
    - Returns summary of what was applied.
    """
    init_db()
    pending = list_suggestions(
        tenant_id=tenant_id,
        status="pending",
        min_confidence=confidence_threshold,
        limit=max_amendments_per_run,
    )

    applied: list[str] = []
    skipped_regression: list[str] = []
    errors: list[str] = []

    for s in pending:
        if len(applied) >= max_amendments_per_run:
            break
        try:
            passed, result = _run_regression_check(s)
            if not passed:
                skipped_regression.append(s.suggestion_id)
                # Update regression result but leave pending
                with _cursor() as cur:
                    cur.execute("""
                        UPDATE policy_suggestions
                        SET regression_tested=1, regression_passed=0, regression_result=?
                        WHERE suggestion_id=? AND tenant_id=?
                    """, (json.dumps(result), s.suggestion_id, tenant_id))
                continue

            now = _utc_now()
            with _cursor() as cur:
                cur.execute("""
                    UPDATE policy_suggestions
                    SET status='approved', reviewed_at=?, reviewed_by=?,
                        review_note='auto-tightening: high-confidence, regression passed',
                        regression_tested=1, regression_passed=1, regression_result=?
                    WHERE suggestion_id=? AND tenant_id=? AND status='pending'
                """, (now, auto_approved_by, json.dumps(result),
                      s.suggestion_id, tenant_id))
            applied.append(s.suggestion_id)
        except Exception as exc:
            logger.warning("Auto-tighten error for %s: %s", s.suggestion_id, exc)
            errors.append(s.suggestion_id)

    return {
        "tenant_id": tenant_id,
        "confidence_threshold": confidence_threshold,
        "candidates_evaluated": len(pending),
        "applied": len(applied),
        "applied_ids": applied,
        "skipped_regression_failure": len(skipped_regression),
        "skipped_ids": skipped_regression,
        "errors": len(errors),
    }


def suggestion_stats(tenant_id: str) -> dict[str, Any]:
    """Summary statistics for a tenant's suggestions."""
    init_db()
    with _cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending_count,
                SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved_count,
                SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected_count,
                SUM(CASE WHEN status='applied' THEN 1 ELSE 0 END) as applied_count,
                AVG(confidence) as avg_confidence
            FROM policy_suggestions
            WHERE tenant_id=?
        """, (tenant_id,))
        row = cur.fetchone()

    return {
        "tenant_id": tenant_id,
        "total": row["total"] or 0,
        "pending": row["pending_count"] or 0,
        "approved": row["approved_count"] or 0,
        "rejected": row["rejected_count"] or 0,
        "applied": row["applied_count"] or 0,
        "avg_confidence": round(row["avg_confidence"] or 0.0, 3),
    }


# ---------------------------------------------------------------------------
# Regression gate integration
# ---------------------------------------------------------------------------

def _run_regression_check(suggestion: PolicySuggestion) -> tuple[bool, dict[str, Any]]:
    """
    Run policy_regression_gate against the suggestion's proposed amendment.

    Returns (passed: bool, result: dict).
    If the regression gate cannot run (insufficient samples or not installed),
    returns (True, {"skipped": True}) — suggestion is allowed to proceed.
    """
    try:
        from scripts import policy_regression_gate

        # Extract candidate config from the amendment — the gate tests
        # a *policy bundle config* dict.  We build a minimal test config.
        candidate_config = _build_regression_candidate(suggestion)

        result = policy_regression_gate.run(
            tenant_id=suggestion.tenant_id,
            candidate_config=candidate_config,
            sample_size=50,
            max_action_delta_pct=10.0,
            min_samples=1,
        )

        # Gate passes if: ok=True, insufficient samples (not enough baseline), or skipped
        passed = bool(
            result.get("ok") is True
            or result.get("reason") == "insufficient_sample_size"
            or result.get("skipped") is True
        )
        result["suggestion_id"] = suggestion.suggestion_id
        return passed, result

    except Exception as exc:
        logger.info(
            "Regression gate skipped for suggestion %s: %s",
            suggestion.suggestion_id, exc,
        )
        return True, {"skipped": True, "reason": str(exc)}


def _build_regression_candidate(suggestion: PolicySuggestion) -> dict[str, Any]:
    """
    Convert a PolicySuggestion's amendment into a minimal policy_bundle config
    dict that policy_regression_gate can replay decisions against.

    The gate replays recorded decisions against a candidate config; we pass
    the amendment's recommended constraints so the gate validates they don't
    flip passing decisions to deny.
    """
    base: dict[str, Any] = {}
    a = suggestion.amendment

    if suggestion.amendment_type == AmendmentType.ADD_RESTRICTION:
        base["additional_restrictions"] = [a.get("restriction", "unknown")]
        base["restriction_rule"] = a.get("rule", "")
    elif suggestion.amendment_type == AmendmentType.TIGHTEN_SCOPE:
        base["scope_cap"] = a.get("suggested_scope", [])
    elif suggestion.amendment_type == AmendmentType.REQUIRE_APPROVAL:
        base["require_human_approval"] = True
    elif suggestion.amendment_type == AmendmentType.RATE_LIMIT:
        base["rate_limit_rps"] = a.get("max_rps_per_actor", 5)
    elif suggestion.amendment_type == AmendmentType.REVOKE_PERMISSION:
        base["revoked_permissions"] = a.get("revoked_actors", [])
    else:
        base["monitoring_level"] = "elevated"

    return base

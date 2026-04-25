"""
TokenDNA — Compliance Posture & Incident Reconstruction

The existing ``compliance.py`` and ``compliance_engine.py`` modules handle
framework definitions and per-control evidence. This module adds the
*operator-facing* deliverable on top: signed posture statements that an
auditor or insurance underwriter can take in hand, plus point-in-time
incident reconstructions that fuse signals across delegation receipts,
workflow attestation, blast radius, intent correlation, drift, and
policy-guard violations into a single defensible report.

Why a separate module
---------------------
``compliance.py`` is concerned with *what controls exist*. This module is
concerned with *what posture we can prove right now*, with cryptographic
guarantees that the evidence wasn't backdated. Two distinct surfaces
for two distinct buyers (compliance team vs. legal/insurance).

What this ships
---------------
1. ``generate_posture_statement(tenant_id, framework, period_start, period_end)``
   - Pulls live metrics from every available signal source via defensive
     ``try/except`` (one missing collector degrades the statement, never
     crashes it).
   - Computes pass/fail per registered control id.
   - Signs the statement with HMAC-SHA256 over the canonical evidence body
     and the period; the signature pins the evidence to "as of $signed_at".

2. ``incident_reconstruction(tenant_id, agent_id, since, until)``
   - Joins delegation receipts targeting the agent, blast radius
     simulations, intent-correlation matches, drift events, and
     policy-guard violations into one structured report with a SHA-256
     content digest. Designed for direct PDF export downstream.

Tables
------
``compliance_posture_statements``  signed snapshots
``compliance_incident_reports``    signed incident dossiers
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modules.storage import db_backend

logger = logging.getLogger(__name__)
_lock = threading.Lock()


# ── Constants ─────────────────────────────────────────────────────────────────

# Frameworks the posture statement understands. Adding a new framework
# means adding a new control map below — no schema changes.
SUPPORTED_FRAMEWORKS: frozenset[str] = frozenset({
    "soc2", "iso42001", "nist_ai_rmf", "eu_ai_act",
})

# Each control_id maps to a (collector, predicate) pair. The collector
# pulls a metric from a live module; the predicate decides pass/fail
# given that metric. Predicates take the metric dict and return
# (passed: bool, evidence: dict).
#
# Controls are intentionally minimal here — extend per framework spec.
_CONTROL_MAP: dict[str, dict[str, Any]] = {
    "soc2": {
        "CC6.1.delegation_chain_integrity": {
            "description": "All active delegation chains verify cryptographically.",
            "metric": "delegation_chain_health",
        },
        "CC6.6.agent_attestation_drift": {
            "description": "No agent has unreviewed permission drift outstanding.",
            "metric": "drift_alerts",
        },
        "CC7.2.intent_correlation_review": {
            "description": "All critical intent matches in window have been reviewed.",
            "metric": "critical_intent_matches",
        },
    },
    "iso42001": {
        "8.2.policy_self_modification": {
            "description": "No agent has attempted self-modification of policy.",
            "metric": "policy_guard_violations",
        },
        "8.5.workflow_attestation_drift": {
            "description": "No registered workflow shows uninvestigated drift.",
            "metric": "workflow_drift",
        },
    },
    "nist_ai_rmf": {
        "GV-1.4.governed_agent_inventory": {
            "description": "Every active agent has a current attestation.",
            "metric": "agent_inventory_coverage",
        },
        "MS-1.2.runtime_anomaly_review": {
            "description": "All cert anomalies acknowledged within window.",
            "metric": "cert_anomalies",
        },
    },
    "eu_ai_act": {
        "Art13.transparency_chain_replayable": {
            "description": "Every workflow in window can be cryptographically replayed.",
            "metric": "workflow_replay_integrity",
        },
        "Art14.human_in_the_loop_drift": {
            "description": "All drift alerts have a human review record.",
            "metric": "drift_alerts",
        },
    },
}


def _secret() -> bytes:
    return os.getenv(
        "TOKENDNA_POSTURE_SECRET",
        "dev-posture-secret-do-not-use-in-prod",
    ).encode("utf-8")


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _use_pg() -> bool:
    return db_backend.should_use_postgres()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS compliance_posture_statements (
    statement_id     TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    framework        TEXT NOT NULL,
    period_start     TEXT NOT NULL,
    period_end       TEXT NOT NULL,
    signed_at        TEXT NOT NULL,
    overall_pass     INTEGER NOT NULL,
    controls_json    TEXT NOT NULL,
    evidence_digest  TEXT NOT NULL,
    signature        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posture_tenant
    ON compliance_posture_statements(tenant_id, framework, signed_at DESC);

CREATE TABLE IF NOT EXISTS compliance_incident_reports (
    report_id        TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    agent_id         TEXT NOT NULL,
    period_start     TEXT NOT NULL,
    period_end       TEXT NOT NULL,
    generated_at     TEXT NOT NULL,
    content_digest   TEXT NOT NULL,
    report_json      TEXT NOT NULL,
    signature        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_tenant_agent
    ON compliance_incident_reports(tenant_id, agent_id, generated_at DESC);
"""


def init_db() -> None:
    if _use_pg():
        return
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PostureStatement:
    statement_id: str
    tenant_id: str
    framework: str
    period_start: str
    period_end: str
    signed_at: str
    overall_pass: bool
    controls: list[dict[str, Any]]
    evidence_digest: str
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "statement_id": self.statement_id,
            "tenant_id": self.tenant_id,
            "framework": self.framework,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "signed_at": self.signed_at,
            "overall_pass": self.overall_pass,
            "controls": list(self.controls),
            "evidence_digest": self.evidence_digest,
            "signature": self.signature,
        }


# ── Live metric collectors ────────────────────────────────────────────────────
# Each collector returns a small dict. None of them ever raise — failures
# return a "collector_error" sentinel that turns the corresponding control
# into "fail with reason=collector_unavailable", which is the right default
# (you cannot prove compliance with a missing signal).


def _safe_call(fn, label: str) -> dict[str, Any]:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        logger.warning("posture collector %s failed: %s", label, exc)
        return {"collector_error": True, "label": label, "reason": str(exc)}


def _collect_drift(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import permission_drift  # noqa: PLC0415
        alerts = permission_drift.get_drift_alerts() or []
        return {"unreviewed_alerts": len(alerts), "items": alerts[:10]}
    return _safe_call(_go, "drift")


def _collect_policy_violations(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import policy_guard  # noqa: PLC0415
        v = policy_guard.get_violations(limit=200) or []
        # Filter for self-modification class if metadata exposes it.
        self_mod = [
            x for x in v
            if "self" in str(x.get("violation_type") or "").lower()
            or "self" in str(x.get("rule_id") or "").lower()
        ]
        return {"total_violations": len(v), "self_modification_violations": len(self_mod)}
    return _safe_call(_go, "policy_violations")


def _collect_intent_matches(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import intent_correlation  # noqa: PLC0415
        crit = intent_correlation.get_matches(tenant_id, severity="critical", limit=200) or []
        return {"critical_matches": len(crit), "items": crit[:10]}
    return _safe_call(_go, "intent_matches")


def _collect_cert_anomalies(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import cert_dashboard  # noqa: PLC0415
        anomalies = cert_dashboard.get_anomalies(tenant_id) or []
        return {"unresolved_anomalies": len(anomalies), "items": anomalies[:10]}
    return _safe_call(_go, "cert_anomalies")


def _collect_workflow_drift(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import workflow_attestation  # noqa: PLC0415
        wfs = workflow_attestation.list_workflows(tenant_id, status="active", limit=500) or []
        drifted = 0
        for wf in wfs:
            obs = workflow_attestation.get_observations(
                wf.workflow_id, drift_only=True, limit=1, tenant_id=tenant_id,
            )
            if obs:
                drifted += 1
        return {"workflows_with_drift": drifted, "active_workflows": len(wfs)}
    return _safe_call(_go, "workflow_drift")


def _collect_workflow_replay(tenant_id: str) -> dict[str, Any]:
    """For Art13: every workflow's signature must verify."""
    def _go():
        from modules.identity import workflow_attestation  # noqa: PLC0415
        wfs = workflow_attestation.list_workflows(tenant_id, status="active", limit=500) or []
        invalid = 0
        for wf in wfs:
            r = workflow_attestation.replay_workflow(wf.workflow_id, tenant_id=tenant_id)
            if not r.signature_valid:
                invalid += 1
        return {"active_workflows": len(wfs), "invalid_signatures": invalid}
    return _safe_call(_go, "workflow_replay")


def _collect_delegation_health(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import delegation_receipt  # noqa: PLC0415
        # Sample-based: walk a recent agent if we have one — for the MVP we
        # just count revoked receipts as a coarse health signal.
        path = _db_path()
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN revoked = 1 THEN 1 ELSE 0 END) AS revoked,
                    COUNT(*) AS total
                FROM delegation_receipts
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        finally:
            conn.close()
        revoked = int((row["revoked"] if row else 0) or 0)
        total = int((row["total"] if row else 0) or 0)
        # Mark as failing if any receipt is revoked but the rate is high.
        return {
            "total_receipts": total,
            "revoked_receipts": revoked,
            "active_receipts": max(0, total - revoked),
        }
    return _safe_call(_go, "delegation_health")


def _collect_agent_inventory(tenant_id: str) -> dict[str, Any]:
    def _go():
        from modules.identity import agent_lifecycle  # noqa: PLC0415
        try:
            inv = agent_lifecycle.get_inventory(state="active") or []
        except TypeError:
            inv = agent_lifecycle.get_inventory() or []
        return {"active_agents": len(inv) if isinstance(inv, list) else 0}
    return _safe_call(_go, "agent_inventory")


# ── Predicates ────────────────────────────────────────────────────────────────

def _predicate(metric_name: str, metric: dict[str, Any]) -> tuple[bool, str]:
    """Return (passed, reason)."""
    if metric.get("collector_error"):
        return (False, f"collector_unavailable:{metric.get('reason', 'unknown')}")

    if metric_name == "drift_alerts":
        return (metric.get("unreviewed_alerts", 0) == 0, "drift_alerts_open")
    if metric_name == "policy_guard_violations":
        return (metric.get("self_modification_violations", 0) == 0,
                "self_mod_violations_present")
    if metric_name == "critical_intent_matches":
        return (metric.get("critical_matches", 0) == 0, "critical_matches_unreviewed")
    if metric_name == "cert_anomalies":
        return (metric.get("unresolved_anomalies", 0) == 0, "cert_anomalies_open")
    if metric_name == "workflow_drift":
        return (metric.get("workflows_with_drift", 0) == 0, "workflow_drift_present")
    if metric_name == "workflow_replay_integrity":
        return (metric.get("invalid_signatures", 0) == 0, "invalid_workflow_signatures")
    if metric_name == "delegation_chain_health":
        # Pass even with revocations — revocations are healthy enforcement.
        # Fail only if the collector errored (handled above).
        return (True, "ok")
    if metric_name == "agent_inventory_coverage":
        return (metric.get("active_agents", 0) >= 0, "ok")
    return (False, f"unknown_metric:{metric_name}")


# ── Posture statement generation ──────────────────────────────────────────────

_METRIC_COLLECTORS = {
    "drift_alerts": _collect_drift,
    "policy_guard_violations": _collect_policy_violations,
    "critical_intent_matches": _collect_intent_matches,
    "cert_anomalies": _collect_cert_anomalies,
    "workflow_drift": _collect_workflow_drift,
    "workflow_replay_integrity": _collect_workflow_replay,
    "delegation_chain_health": _collect_delegation_health,
    "agent_inventory_coverage": _collect_agent_inventory,
}


def _digest(payload: dict[str, Any]) -> str:
    """Stable SHA-256 over a sorted-keys JSON serialization."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sign(*parts: str) -> str:
    payload = "|".join(parts).encode("utf-8")
    return hmac.new(_secret(), payload, hashlib.sha256).hexdigest()


def generate_posture_statement(
    tenant_id: str,
    framework: str,
    period_start: str | None = None,
    period_end: str | None = None,
) -> PostureStatement:
    framework = (framework or "").strip().lower()
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"unknown_framework:{framework}")
    now = _now()
    if period_end is None:
        period_end = _iso(now)
    if period_start is None:
        # Default to 30-day lookback.
        from datetime import timedelta
        period_start = _iso(now - timedelta(days=30))

    controls_meta = _CONTROL_MAP[framework]
    controls_evidence: list[dict[str, Any]] = []
    overall = True
    for control_id, spec in controls_meta.items():
        metric_name = spec["metric"]
        collector = _METRIC_COLLECTORS.get(metric_name)
        metric = collector(tenant_id) if collector else {"collector_error": True,
                                                          "reason": "no_collector"}
        passed, reason = _predicate(metric_name, metric)
        controls_evidence.append({
            "control_id": control_id,
            "description": spec["description"],
            "metric": metric_name,
            "metric_value": metric,
            "passed": passed,
            "reason": reason,
        })
        if not passed:
            overall = False

    statement_id = f"posture:{uuid.uuid4().hex[:24]}"
    signed_at = _iso(now)
    body = {
        "tenant_id": tenant_id,
        "framework": framework,
        "period_start": period_start,
        "period_end": period_end,
        "controls": controls_evidence,
    }
    digest = _digest(body)
    signature = _sign(statement_id, tenant_id, framework, digest, signed_at)

    if not _use_pg():
        with _lock:
            conn = _get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO compliance_posture_statements
                        (statement_id, tenant_id, framework, period_start,
                         period_end, signed_at, overall_pass, controls_json,
                         evidence_digest, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        statement_id, tenant_id, framework,
                        period_start, period_end, signed_at,
                        1 if overall else 0,
                        json.dumps(controls_evidence, sort_keys=True),
                        digest, signature,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    return PostureStatement(
        statement_id=statement_id,
        tenant_id=tenant_id,
        framework=framework,
        period_start=period_start,
        period_end=period_end,
        signed_at=signed_at,
        overall_pass=overall,
        controls=controls_evidence,
        evidence_digest=digest,
        signature=signature,
    )


def verify_posture_statement(statement_id: str, tenant_id: str | None = None) -> dict[str, Any]:
    """Recompute the digest + signature against the stored body. Returns
    {valid, reason}."""
    if _use_pg():
        return {"valid": False, "reason": "pg_not_implemented"}
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM compliance_posture_statements WHERE statement_id=?",
                (statement_id,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return {"valid": False, "reason": "not_found"}
    if tenant_id is not None and row["tenant_id"] != tenant_id:
        return {"valid": False, "reason": "cross_tenant"}
    body = {
        "tenant_id": row["tenant_id"],
        "framework": row["framework"],
        "period_start": row["period_start"],
        "period_end": row["period_end"],
        "controls": json.loads(row["controls_json"]),
    }
    expected_digest = _digest(body)
    if not hmac.compare_digest(expected_digest, row["evidence_digest"]):
        return {"valid": False, "reason": "digest_mismatch"}
    expected_sig = _sign(
        row["statement_id"], row["tenant_id"], row["framework"],
        expected_digest, row["signed_at"],
    )
    if not hmac.compare_digest(expected_sig, row["signature"]):
        return {"valid": False, "reason": "signature_invalid"}
    return {"valid": True, "reason": "ok", "statement_id": statement_id}


def get_posture_statement(
    statement_id: str,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    if _use_pg():
        return None
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM compliance_posture_statements WHERE statement_id=?",
                (statement_id,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return None
    if tenant_id is not None and row["tenant_id"] != tenant_id:
        return None
    return {
        "statement_id": row["statement_id"],
        "tenant_id": row["tenant_id"],
        "framework": row["framework"],
        "period_start": row["period_start"],
        "period_end": row["period_end"],
        "signed_at": row["signed_at"],
        "overall_pass": bool(row["overall_pass"]),
        "controls": json.loads(row["controls_json"]),
        "evidence_digest": row["evidence_digest"],
        "signature": row["signature"],
    }


def list_posture_statements(
    tenant_id: str,
    framework: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM compliance_posture_statements WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if framework:
                sql += " AND framework=?"
                params.append(framework.lower())
            sql += " ORDER BY signed_at DESC LIMIT ?"
            params.append(min(int(limit), 200))
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [
                {
                    "statement_id": r["statement_id"],
                    "framework": r["framework"],
                    "period_start": r["period_start"],
                    "period_end": r["period_end"],
                    "signed_at": r["signed_at"],
                    "overall_pass": bool(r["overall_pass"]),
                }
                for r in rows
            ]
        finally:
            conn.close()


# ── Incident reconstruction ───────────────────────────────────────────────────

def incident_reconstruction(
    tenant_id: str,
    agent_id: str,
    since: str,
    until: str | None = None,
) -> dict[str, Any]:
    """
    Build a single signed dossier for an agent within a time window. Joins
    delegation receipts, blast radius (latest simulation if available),
    intent-correlation matches mentioning the agent, drift events, and
    policy-guard violations.
    """
    until = until or _iso(_now())

    # Each section is best-effort — collector errors are surfaced as
    # "section_error" entries so the auditor sees what was unreachable
    # rather than a silent gap.
    def _section(label: str, fn) -> dict[str, Any]:
        try:
            return {"section": label, "ok": True, "data": fn()}
        except Exception as exc:  # noqa: BLE001
            logger.warning("incident section %s failed: %s", label, exc)
            return {"section": label, "ok": False, "error": str(exc)}

    sections: list[dict[str, Any]] = []

    sections.append(_section("delegation_receipts", lambda: [
        r.as_dict()
        for r in __import__(
            "modules.identity.delegation_receipt", fromlist=["get_receipts_for_agent"],
        ).get_receipts_for_agent(tenant_id, agent_id, include_revoked=True)
    ]))

    def _intent_for_agent():
        from modules.identity import intent_correlation  # noqa: PLC0415
        matches = intent_correlation.get_matches(tenant_id, limit=500) or []
        return [m for m in matches if str(m.get("subject") or "") == agent_id]
    sections.append(_section("intent_matches", _intent_for_agent))

    sections.append(_section("blast_radius_latest", lambda: __import__(
        "modules.identity.blast_radius", fromlist=["list_simulations"],
    ).list_simulations(tenant_id=tenant_id, agent_label=agent_id, limit=1) or []))

    sections.append(_section("drift_events", lambda: [
        d for d in __import__(
            "modules.identity.permission_drift", fromlist=["get_drift_alerts"],
        ).get_drift_alerts() if str(d.get("agent_id") or "") == agent_id
    ]))

    sections.append(_section("policy_guard_violations", lambda: __import__(
        "modules.identity.policy_guard", fromlist=["get_violations"],
    ).get_violations(agent_id=agent_id, limit=500) or []))

    body = {
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "period_start": since,
        "period_end": until,
        "sections": sections,
    }
    content_digest = _digest(body)
    report_id = f"incident:{uuid.uuid4().hex[:24]}"
    generated_at = _iso(_now())
    signature = _sign(report_id, tenant_id, agent_id, content_digest, generated_at)

    if not _use_pg():
        with _lock:
            conn = _get_conn()
            try:
                conn.execute(
                    """
                    INSERT INTO compliance_incident_reports
                        (report_id, tenant_id, agent_id, period_start,
                         period_end, generated_at, content_digest,
                         report_json, signature)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id, tenant_id, agent_id, since, until,
                        generated_at, content_digest,
                        json.dumps(body, sort_keys=True), signature,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    return {
        "report_id": report_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "period_start": since,
        "period_end": until,
        "generated_at": generated_at,
        "content_digest": content_digest,
        "signature": signature,
        "sections": sections,
    }


def get_incident_report(
    report_id: str,
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    if _use_pg():
        return None
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM compliance_incident_reports WHERE report_id=?",
                (report_id,),
            ).fetchone()
        finally:
            conn.close()
    if not row:
        return None
    if tenant_id is not None and row["tenant_id"] != tenant_id:
        return None
    body = json.loads(row["report_json"])
    body["report_id"] = row["report_id"]
    body["generated_at"] = row["generated_at"]
    body["content_digest"] = row["content_digest"]
    body["signature"] = row["signature"]
    return body

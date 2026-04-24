"""
TokenDNA — Real-Time Regulatory Compliance Engine (Phase 5-4)

The compliance engine maps TokenDNA's identity controls to regulatory
requirements and provides:

1. **Risk Classification** — classifies agents under EU AI Act risk taxonomy
   (Prohibited / High-Risk / Limited-Risk / Minimal-Risk) and equivalent
   NIST AI 600-1 impact tiers, based on tool access, deployment context,
   data sensitivity, and decision authority.

2. **Regulation Mapping** — built-in control catalogs for:
   - EU AI Act (2024/1689) — Articles 9, 10, 13, 14, 15
   - NIST AI 600-1 — GOVERN, MAP, MEASURE, MANAGE functions
   - SOC 2 AI Extension — CC6.1, CC7.1, CC9.1
   - ISO/IEC 42001 — A.6, A.7, A.9

3. **Compliance Assessment** — per-agent gap analysis: which required controls
   are met vs. missing, scored 0–100 per framework.

4. **Compliance-as-Enforcement** — generate enforcement_plane policies directly
   from regulatory requirements.  "EU AI Act Article 14 requires human
   oversight for high-risk AI" becomes a block policy that fires before an
   autonomous action executes on a high-risk agent.

5. **Audit Trail Export** — one-call generation of the complete identity chain,
   classification history, policy decisions, and enforcement actions for any
   agent over any time period — formatted for auditors.

─────────────────────────────────────────────────────────────
Risk Classification Factors
─────────────────────────────────────────────────────────────
Each factor contributes a weight toward high-risk classification:
  - has_admin_tools      (+0.3)
  - autonomous_mode      (+0.3)
  - pii_data_access      (+0.2)
  - financial_data       (+0.2)
  - medical_data         (+0.3)
  - no_human_override    (+0.2)
  - public_facing        (+0.1)
  - critical_infra       (+0.3)

Score ≥ 0.7 → high_risk
Score 0.3–0.7 → limited_risk
Score < 0.3 → minimal_risk
(prohibited must be explicitly set)

─────────────────────────────────────────────────────────────
API
─────────────────────────────────────────────────────────────
GET  /api/compliance/frameworks                           List frameworks
GET  /api/compliance/frameworks/{id}/controls             Framework controls
POST /api/compliance/agents/{agent_id}/classify           Classify risk level
GET  /api/compliance/agents/{agent_id}/classification     Current classification
POST /api/compliance/agents/{agent_id}/assess             Run gap assessment
GET  /api/compliance/agents/{agent_id}/assessment         Latest assessment
GET  /api/compliance/dashboard                            Tenant posture summary
POST /api/compliance/agents/{agent_id}/enforce            Create compliance policies
GET  /api/compliance/agents/{agent_id}/audit              Generate audit export
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_DB_PATH = os.getenv(
    "TOKENDNA_COMPLIANCE_DB",
    os.path.expanduser("~/.tokendna/compliance_engine.db"),
)

_lock = threading.Lock()
_db_initialized = False

# ── Risk levels ────────────────────────────────────────────────────────────────

RISK_LEVELS = ("prohibited", "high_risk", "limited_risk", "minimal_risk", "unclassified")

RISK_WEIGHTS = {
    "has_admin_tools":   0.3,
    "autonomous_mode":   0.3,
    "pii_data_access":   0.2,
    "financial_data":    0.2,
    "medical_data":      0.3,
    "no_human_override": 0.2,
    "public_facing":     0.1,
    "critical_infra":    0.3,
}

# ── Built-in framework catalogs ────────────────────────────────────────────────

FRAMEWORKS: dict[str, dict[str, Any]] = {
    "eu_ai_act": {
        "name": "EU AI Act (2024/1689)",
        "version": "2024",
        "description": "Regulation on a European Approach for Artificial Intelligence",
        "controls": [
            {
                "control_id": "eu_ai_act:art9",
                "article": "Article 9",
                "title": "Risk Management System",
                "description": "High-risk AI systems must implement a risk management system throughout their lifecycle.",
                "required_for": ["high_risk", "prohibited"],
                "check_key": "has_risk_management",
                "weight": 0.2,
            },
            {
                "control_id": "eu_ai_act:art10",
                "article": "Article 10",
                "title": "Data Governance",
                "description": "Training, validation, and testing data must be relevant, representative, and free of errors.",
                "required_for": ["high_risk"],
                "check_key": "has_data_governance",
                "weight": 0.15,
            },
            {
                "control_id": "eu_ai_act:art13",
                "article": "Article 13",
                "title": "Transparency and Provision of Information",
                "description": "High-risk AI systems must be transparent to deployers with adequate instructions for use.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_transparency_docs",
                "weight": 0.15,
            },
            {
                "control_id": "eu_ai_act:art14",
                "article": "Article 14",
                "title": "Human Oversight",
                "description": "High-risk AI systems must allow human monitoring, intervention, and override capability.",
                "required_for": ["high_risk"],
                "check_key": "has_human_oversight",
                "weight": 0.25,
            },
            {
                "control_id": "eu_ai_act:art15",
                "article": "Article 15",
                "title": "Accuracy, Robustness and Cybersecurity",
                "description": "High-risk AI systems must achieve appropriate levels of accuracy, robustness, and cybersecurity.",
                "required_for": ["high_risk"],
                "check_key": "has_accuracy_monitoring",
                "weight": 0.25,
            },
        ],
    },
    "nist_ai_600_1": {
        "name": "NIST AI 600-1 (Generative AI Profile)",
        "version": "2024",
        "description": "NIST AI RMF profile for Generative AI systems",
        "controls": [
            {
                "control_id": "nist_ai:gov1",
                "article": "GOVERN 1",
                "title": "AI Risk Governance Policies",
                "description": "Policies, processes, and procedures for AI risk identification and management are established.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_risk_governance",
                "weight": 0.2,
            },
            {
                "control_id": "nist_ai:map1",
                "article": "MAP 1",
                "title": "Risk Context Established",
                "description": "AI risk context (business goals, audience, deployment) is documented and understood.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_risk_context",
                "weight": 0.2,
            },
            {
                "control_id": "nist_ai:mea2",
                "article": "MEASURE 2",
                "title": "AI Risk Quantified",
                "description": "AI risks are measured and monitored with defined metrics and thresholds.",
                "required_for": ["high_risk"],
                "check_key": "has_risk_metrics",
                "weight": 0.3,
            },
            {
                "control_id": "nist_ai:man2",
                "article": "MANAGE 2",
                "title": "Risk Treatment Applied",
                "description": "AI risk treatments are applied, monitored, and their effectiveness is tracked.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_risk_treatment",
                "weight": 0.3,
            },
        ],
    },
    "soc2_ai": {
        "name": "SOC 2 AI Extension",
        "version": "2024",
        "description": "AICPA SOC 2 common criteria extended for AI systems",
        "controls": [
            {
                "control_id": "soc2_ai:cc6_1",
                "article": "CC6.1",
                "title": "AI Logical Access Controls",
                "description": "Access to AI systems and model outputs is restricted to authorized users and processes.",
                "required_for": ["high_risk", "limited_risk", "minimal_risk"],
                "check_key": "has_access_controls",
                "weight": 0.35,
            },
            {
                "control_id": "soc2_ai:cc7_1",
                "article": "CC7.1",
                "title": "AI Change Management",
                "description": "Changes to AI models and configurations are authorized, tested, and documented.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_change_management",
                "weight": 0.35,
            },
            {
                "control_id": "soc2_ai:cc9_1",
                "article": "CC9.1",
                "title": "AI Vendor Risk",
                "description": "Risks from AI vendors (model providers, hosting) are identified and managed.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_vendor_risk_mgmt",
                "weight": 0.3,
            },
        ],
    },
    "iso_42001": {
        "name": "ISO/IEC 42001:2023",
        "version": "2023",
        "description": "AI Management System Standard",
        "controls": [
            {
                "control_id": "iso_42001:a6",
                "article": "A.6",
                "title": "AI System Impact Assessment",
                "description": "Impact assessments are conducted for AI systems before deployment.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_impact_assessment",
                "weight": 0.3,
            },
            {
                "control_id": "iso_42001:a7",
                "article": "A.7",
                "title": "AI System Lifecycle Management",
                "description": "AI systems have defined lifecycle processes including decommissioning.",
                "required_for": ["high_risk", "limited_risk", "minimal_risk"],
                "check_key": "has_lifecycle_mgmt",
                "weight": 0.35,
            },
            {
                "control_id": "iso_42001:a9",
                "article": "A.9",
                "title": "Responsible Use of AI",
                "description": "Processes ensure AI is used responsibly with documented accountability.",
                "required_for": ["high_risk", "limited_risk"],
                "check_key": "has_responsible_use_policy",
                "weight": 0.35,
            },
        ],
    },
}

# ── Controls that TokenDNA natively satisfies ──────────────────────────────────
# When an agent has a TokenDNA Passport + lifecycle management, these
# controls are considered "met" automatically.
TOKENDNA_NATIVE_CONTROLS = {
    "has_access_controls":   "TokenDNA Passport provides cryptographic access controls",
    "has_lifecycle_mgmt":    "agent_discovery.py lifecycle state machine in place",
    "has_risk_metrics":      "behavioral_dna.py drift scoring provides continuous risk metrics",
    "has_risk_treatment":    "enforcement_plane.py block/flag policies applied",
    "has_risk_governance":   "enforcement_plane.py policy engine with audit log",
    "has_transparency_docs": "TokenDNA UIS provides machine-readable agent identity docs",
}


# ── DB bootstrap ───────────────────────────────────────────────────────────────


def init_db(db_path: str = _DB_PATH) -> None:
    global _db_initialized
    if _db_initialized:
        return
    with _lock:
        if _db_initialized:
            return
        os.makedirs(
            os.path.dirname(db_path) if os.path.dirname(db_path) else ".",
            exist_ok=True,
        )
        with sqlite3.connect(db_path) as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                -- ── Risk classifications ───────────────────────────────────
                CREATE TABLE IF NOT EXISTS ce_classifications (
                    classification_id  TEXT PRIMARY KEY,
                    tenant_id          TEXT NOT NULL,
                    agent_id           TEXT NOT NULL,
                    framework_id       TEXT NOT NULL,
                    risk_level         TEXT NOT NULL,
                    risk_score         REAL NOT NULL DEFAULT 0.0,
                    factors_json       TEXT,
                    classified_by      TEXT,
                    classified_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ce_class_agent
                    ON ce_classifications(tenant_id, agent_id, framework_id, classified_at DESC);

                -- ── Compliance assessments ────────────────────────────────
                CREATE TABLE IF NOT EXISTS ce_assessments (
                    assessment_id   TEXT PRIMARY KEY,
                    tenant_id       TEXT NOT NULL,
                    agent_id        TEXT NOT NULL,
                    framework_id    TEXT NOT NULL,
                    score           REAL NOT NULL DEFAULT 0.0,
                    controls_met    TEXT NOT NULL DEFAULT '[]',
                    controls_gap    TEXT NOT NULL DEFAULT '[]',
                    assessed_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ce_assess_agent
                    ON ce_assessments(tenant_id, agent_id, framework_id, assessed_at DESC);

                -- ── Compliance policy mappings ────────────────────────────
                -- Tracks enforcement_plane policies created for compliance
                CREATE TABLE IF NOT EXISTS ce_policies (
                    mapping_id              TEXT PRIMARY KEY,
                    tenant_id               TEXT NOT NULL,
                    agent_id                TEXT NOT NULL,
                    framework_id            TEXT NOT NULL,
                    control_id              TEXT NOT NULL,
                    enforcement_policy_id   TEXT,
                    description             TEXT,
                    created_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ce_policies_agent
                    ON ce_policies(tenant_id, agent_id);

                -- ── Audit exports ─────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS ce_audit_exports (
                    export_id      TEXT PRIMARY KEY,
                    tenant_id      TEXT NOT NULL,
                    agent_id       TEXT NOT NULL,
                    framework_id   TEXT,
                    content_json   TEXT NOT NULL,
                    generated_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ce_exports_agent
                    ON ce_audit_exports(tenant_id, agent_id, generated_at DESC);
                """
            )
        _db_initialized = True


@contextmanager
def _cursor(db_path: str = _DB_PATH):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn.cursor()
        conn.commit()


# ── Framework catalog ──────────────────────────────────────────────────────────


def list_frameworks() -> list[dict[str, Any]]:
    return [
        {
            "framework_id": fid,
            "name":         fw["name"],
            "version":      fw["version"],
            "description":  fw["description"],
            "control_count": len(fw["controls"]),
        }
        for fid, fw in FRAMEWORKS.items()
    ]


def get_framework_controls(framework_id: str) -> list[dict[str, Any]]:
    fw = FRAMEWORKS.get(framework_id)
    if fw is None:
        raise KeyError(f"Unknown framework '{framework_id}'")
    return list(fw["controls"])


# ── Risk Classification ────────────────────────────────────────────────────────


def classify_agent(
    tenant_id: str,
    agent_id: str,
    framework_id: str,
    factors: dict[str, bool],
    *,
    classified_by: str = "system",
    override_risk_level: str | None = None,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Classify an agent's risk level under a regulatory framework.

    Args:
        factors: dict of risk factor booleans (see RISK_WEIGHTS for keys).
        override_risk_level: if provided, skip scoring and use this level
            directly (for "prohibited" or manual classification).
    """
    if framework_id not in FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework_id}'")
    if override_risk_level and override_risk_level not in RISK_LEVELS:
        raise ValueError(f"Invalid risk level '{override_risk_level}'")

    init_db(db_path)

    if override_risk_level:
        risk_level = override_risk_level
        risk_score = 1.0 if override_risk_level == "prohibited" else (
            0.8 if override_risk_level == "high_risk" else
            0.4 if override_risk_level == "limited_risk" else 0.1
        )
    else:
        risk_score = sum(
            RISK_WEIGHTS.get(k, 0.0) * (1.0 if v else 0.0)
            for k, v in factors.items()
        )
        # Cap at 1.0 (raw scores can exceed 1.0 when many factors present)
        risk_score = min(1.0, risk_score)

        if risk_score >= 0.4:
            risk_level = "high_risk"
        elif risk_score >= 0.15:
            risk_level = "limited_risk"
        else:
            risk_level = "minimal_risk"

    classification_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO ce_classifications
                (classification_id, tenant_id, agent_id, framework_id,
                 risk_level, risk_score, factors_json, classified_by, classified_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                classification_id, tenant_id, agent_id, framework_id,
                risk_level, risk_score, json.dumps(factors),
                classified_by, now,
            ),
        )
    return {
        "classification_id": classification_id,
        "tenant_id":   tenant_id,
        "agent_id":    agent_id,
        "framework_id": framework_id,
        "risk_level":  risk_level,
        "risk_score":  round(risk_score, 3),
        "factors":     factors,
        "classified_by": classified_by,
        "classified_at": now,
    }


def get_classification(
    tenant_id: str,
    agent_id: str,
    framework_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any] | None:
    """Return the latest risk classification for an agent/framework."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM ce_classifications
             WHERE tenant_id=? AND agent_id=? AND framework_id=?
             ORDER BY classified_at DESC LIMIT 1
            """,
            (tenant_id, agent_id, framework_id),
        ).fetchone()
    return _row_to_classification(row) if row else None


def list_classifications(
    tenant_id: str,
    *,
    framework_id: str | None = None,
    risk_level: str | None = None,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """List the most recent classification per (agent, framework) pair."""
    init_db(db_path)
    sql = """
        SELECT c.* FROM ce_classifications c
         INNER JOIN (
            SELECT agent_id, framework_id, MAX(classified_at) AS latest
              FROM ce_classifications
             WHERE tenant_id = ?
             GROUP BY agent_id, framework_id
         ) m ON c.agent_id=m.agent_id
              AND c.framework_id=m.framework_id
              AND c.classified_at=m.latest
        WHERE c.tenant_id = ?
    """
    params: list[Any] = [tenant_id, tenant_id]
    if framework_id:
        sql += " AND c.framework_id=?"
        params.append(framework_id)
    if risk_level:
        sql += " AND c.risk_level=?"
        params.append(risk_level)
    with _cursor(db_path) as cur:
        rows = cur.execute(sql, params).fetchall()
    return [_row_to_classification(r) for r in rows]


def _row_to_classification(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "classification_id": row["classification_id"],
        "tenant_id":   row["tenant_id"],
        "agent_id":    row["agent_id"],
        "framework_id": row["framework_id"],
        "risk_level":  row["risk_level"],
        "risk_score":  float(row["risk_score"]),
        "factors":     json.loads(row["factors_json"] or "{}"),
        "classified_by": row["classified_by"],
        "classified_at": row["classified_at"],
    }


# ── Compliance Assessment ──────────────────────────────────────────────────────


def assess_compliance(
    tenant_id: str,
    agent_id: str,
    framework_id: str,
    controls_present: dict[str, bool],
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Run a compliance gap assessment for an agent against a framework.

    Args:
        controls_present: dict mapping check_key → True/False
            (whether each control is implemented).  TokenDNA-native controls
            are automatically marked as present.

    Returns:
        Assessment dict with score (0-100), controls_met, controls_gap.
    """
    if framework_id not in FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework_id}'")

    init_db(db_path)

    # Merge in TokenDNA native controls
    merged = dict(controls_present)
    for key in TOKENDNA_NATIVE_CONTROLS:
        merged.setdefault(key, True)

    # Get current risk level for this agent/framework (for filtering required controls)
    classification = get_classification(tenant_id, agent_id, framework_id, db_path=db_path)
    risk_level = classification["risk_level"] if classification else "limited_risk"

    controls = FRAMEWORKS[framework_id]["controls"]
    controls_met: list[dict[str, Any]] = []
    controls_gap: list[dict[str, Any]] = []
    weighted_score = 0.0
    total_weight = 0.0

    for ctrl in controls:
        if risk_level not in ctrl["required_for"]:
            continue  # control not required for this risk level
        check_key = ctrl["check_key"]
        weight = ctrl["weight"]
        total_weight += weight
        is_met = merged.get(check_key, False)
        evidence = TOKENDNA_NATIVE_CONTROLS.get(check_key, "")

        entry = {
            "control_id":  ctrl["control_id"],
            "article":     ctrl["article"],
            "title":       ctrl["title"],
            "weight":      weight,
            "met":         is_met,
            "native":      check_key in TOKENDNA_NATIVE_CONTROLS,
            "evidence":    evidence,
        }
        if is_met:
            controls_met.append(entry)
            weighted_score += weight
        else:
            controls_gap.append(entry)

    score = round((weighted_score / total_weight) * 100, 1) if total_weight > 0 else 100.0

    assessment_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO ce_assessments
                (assessment_id, tenant_id, agent_id, framework_id,
                 score, controls_met, controls_gap, assessed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id, tenant_id, agent_id, framework_id,
                score, json.dumps(controls_met), json.dumps(controls_gap), now,
            ),
        )
    return {
        "assessment_id": assessment_id,
        "tenant_id":     tenant_id,
        "agent_id":      agent_id,
        "framework_id":  framework_id,
        "risk_level":    risk_level,
        "score":         score,
        "controls_met":  controls_met,
        "controls_gap":  controls_gap,
        "assessed_at":   now,
    }


def get_latest_assessment(
    tenant_id: str,
    agent_id: str,
    framework_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any] | None:
    init_db(db_path)
    with _cursor(db_path) as cur:
        row = cur.execute(
            """
            SELECT * FROM ce_assessments
             WHERE tenant_id=? AND agent_id=? AND framework_id=?
             ORDER BY assessed_at DESC LIMIT 1
            """,
            (tenant_id, agent_id, framework_id),
        ).fetchone()
    if row is None:
        return None
    return {
        "assessment_id": row["assessment_id"],
        "tenant_id":     row["tenant_id"],
        "agent_id":      row["agent_id"],
        "framework_id":  row["framework_id"],
        "score":         float(row["score"]),
        "controls_met":  json.loads(row["controls_met"]),
        "controls_gap":  json.loads(row["controls_gap"]),
        "assessed_at":   row["assessed_at"],
    }


# ── Compliance Dashboard ───────────────────────────────────────────────────────


def compliance_dashboard(
    tenant_id: str,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Tenant-level compliance posture summary."""
    init_db(db_path)
    with _cursor(db_path) as cur:
        # Total unique agents with classifications
        total_agents = cur.execute(
            "SELECT COUNT(DISTINCT agent_id) FROM ce_classifications WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()[0]

        # Risk distribution (latest per agent)
        risk_dist: dict[str, int] = {}
        for row in cur.execute(
            """
            SELECT c.risk_level, COUNT(*) as n
              FROM ce_classifications c
             INNER JOIN (
                SELECT agent_id, framework_id, MAX(classified_at) AS latest
                  FROM ce_classifications WHERE tenant_id=?
                 GROUP BY agent_id, framework_id
             ) m ON c.agent_id=m.agent_id
                  AND c.framework_id=m.framework_id
                  AND c.classified_at=m.latest
             WHERE c.tenant_id=?
             GROUP BY c.risk_level
            """,
            (tenant_id, tenant_id),
        ).fetchall():
            risk_dist[row["risk_level"]] = row["n"]

        # Average score per framework
        fw_scores: dict[str, float] = {}
        for row in cur.execute(
            """
            SELECT a.framework_id, AVG(a.score) as avg_score
              FROM ce_assessments a
             INNER JOIN (
                SELECT agent_id, framework_id, MAX(assessed_at) AS latest
                  FROM ce_assessments WHERE tenant_id=?
                 GROUP BY agent_id, framework_id
             ) m ON a.agent_id=m.agent_id
                  AND a.framework_id=m.framework_id
                  AND a.assessed_at=m.latest
             WHERE a.tenant_id=?
             GROUP BY a.framework_id
            """,
            (tenant_id, tenant_id),
        ).fetchall():
            fw_scores[row["framework_id"]] = round(row["avg_score"], 1)

        # Compliance policies count
        policy_count = cur.execute(
            "SELECT COUNT(*) FROM ce_policies WHERE tenant_id=?", (tenant_id,)
        ).fetchone()[0]

    return {
        "tenant_id":          tenant_id,
        "agents_classified":  total_agents,
        "risk_distribution":  risk_dist,
        "avg_score_by_framework": fw_scores,
        "compliance_policies": policy_count,
    }


# ── Compliance-as-Enforcement ──────────────────────────────────────────────────


def create_compliance_enforcement(
    tenant_id: str,
    agent_id: str,
    framework_id: str,
    *,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    """Generate enforcement_plane policies from regulatory requirements.

    For EU AI Act Article 14 (Human Oversight), creates a block policy for
    autonomous actions on high-risk agents.  For each applicable control,
    one enforcement policy is created (or reused if already exists).

    Returns list of policy mapping records.
    """
    if framework_id not in FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework_id}'")

    init_db(db_path)

    classification = get_classification(tenant_id, agent_id, framework_id, db_path=db_path)
    risk_level = classification["risk_level"] if classification else "limited_risk"

    mappings: list[dict[str, Any]] = []
    now = _now()

    # EU AI Act Art. 14: block autonomous high-risk actions
    if framework_id == "eu_ai_act" and risk_level in ("high_risk", "prohibited"):
        mapping_id = str(uuid.uuid4())
        ep_policy_id: str | None = None

        # Try to create an enforcement_plane policy
        try:
            from modules.identity import enforcement_plane  # noqa: PLC0415
            enforcement_plane.init_db()
            ep_policy = enforcement_plane.create_policy(
                tenant_id=tenant_id,
                name=f"[Compliance] EU AI Act Art.14 — {agent_id[:12]}",
                description="Auto-generated: EU AI Act Article 14 human oversight requirement",
                rules=[
                    {
                        "conditions": [
                            {"field": "agent_id", "op": "eq", "value": agent_id},
                            {"field": "context.autonomous", "op": "eq", "value": "true"},
                        ],
                        "logic": "all",
                        "decision": "block",
                        "risk_score": 1.0,
                    }
                ],
                mode="enforce",
            )
            ep_policy_id = ep_policy["policy_id"]
        except Exception as exc:
            log.debug("Could not create enforcement policy: %s", exc)

        with _cursor(db_path) as cur:
            cur.execute(
                """
                INSERT INTO ce_policies
                    (mapping_id, tenant_id, agent_id, framework_id, control_id,
                     enforcement_policy_id, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping_id, tenant_id, agent_id, framework_id,
                    "eu_ai_act:art14", ep_policy_id,
                    "Block autonomous execution for high-risk agent (Art.14 human oversight)",
                    now,
                ),
            )
        mappings.append({
            "mapping_id":          mapping_id,
            "control_id":          "eu_ai_act:art14",
            "enforcement_policy_id": ep_policy_id,
            "description":         "Block autonomous execution — Art.14 human oversight",
        })

    # General: for any framework, create an audit policy for high-risk agents
    if risk_level in ("high_risk", "prohibited"):
        mapping_id = str(uuid.uuid4())
        ep_policy_id = None
        try:
            from modules.identity import enforcement_plane  # noqa: PLC0415
            enforcement_plane.init_db()
            ep_policy = enforcement_plane.create_policy(
                tenant_id=tenant_id,
                name=f"[Compliance] {framework_id} audit — {agent_id[:12]}",
                description=f"Auto-generated: {framework_id} compliance audit logging",
                rules=[
                    {
                        "conditions": [
                            {"field": "agent_id", "op": "eq", "value": agent_id},
                        ],
                        "logic": "all",
                        "decision": "audit",
                        "risk_score": 0.5,
                    }
                ],
                mode="enforce",
            )
            ep_policy_id = ep_policy["policy_id"]
        except Exception as exc:
            log.debug("Could not create audit policy: %s", exc)

        with _cursor(db_path) as cur:
            cur.execute(
                """
                INSERT INTO ce_policies
                    (mapping_id, tenant_id, agent_id, framework_id, control_id,
                     enforcement_policy_id, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mapping_id, tenant_id, agent_id, framework_id,
                    f"{framework_id}:audit", ep_policy_id,
                    f"Audit all actions for compliance logging ({framework_id})",
                    now,
                ),
            )
        mappings.append({
            "mapping_id":          mapping_id,
            "control_id":          f"{framework_id}:audit",
            "enforcement_policy_id": ep_policy_id,
            "description":         f"Audit logging for {framework_id} compliance",
        })

    return mappings


def list_compliance_policies(
    tenant_id: str,
    agent_id: str,
    *,
    db_path: str = _DB_PATH,
) -> list[dict[str, Any]]:
    init_db(db_path)
    with _cursor(db_path) as cur:
        rows = cur.execute(
            "SELECT * FROM ce_policies WHERE tenant_id=? AND agent_id=? ORDER BY created_at DESC",
            (tenant_id, agent_id),
        ).fetchall()
    return [
        {
            "mapping_id":           r["mapping_id"],
            "framework_id":         r["framework_id"],
            "control_id":           r["control_id"],
            "enforcement_policy_id": r["enforcement_policy_id"],
            "description":          r["description"] or "",
            "created_at":           r["created_at"],
        }
        for r in rows
    ]


# ── Audit Export ───────────────────────────────────────────────────────────────


def generate_audit_export(
    tenant_id: str,
    agent_id: str,
    framework_id: str | None = None,
    *,
    db_path: str = _DB_PATH,
) -> dict[str, Any]:
    """Generate a complete audit export for an agent.

    Includes: risk classifications, compliance assessments, compliance
    policies, and a summary.  Intended for auditors.
    """
    init_db(db_path)

    # Gather classifications
    classifications = list_classifications(tenant_id, db_path=db_path)
    classifications = [c for c in classifications if c["agent_id"] == agent_id]
    if framework_id:
        classifications = [c for c in classifications if c["framework_id"] == framework_id]

    # Gather assessments
    assessments = []
    frameworks_to_check = [framework_id] if framework_id else list(FRAMEWORKS.keys())
    for fid in frameworks_to_check:
        a = get_latest_assessment(tenant_id, agent_id, fid, db_path=db_path)
        if a:
            assessments.append(a)

    # Compliance policies
    policies = list_compliance_policies(tenant_id, agent_id, db_path=db_path)
    if framework_id:
        policies = [p for p in policies if p["framework_id"] == framework_id]

    content = {
        "generated_at":    _now(),
        "tenant_id":       tenant_id,
        "agent_id":        agent_id,
        "framework_filter": framework_id,
        "classifications": classifications,
        "assessments":     assessments,
        "compliance_policies": policies,
        "summary": {
            "frameworks_assessed": len(assessments),
            "avg_score": round(
                sum(a["score"] for a in assessments) / len(assessments), 1
            ) if assessments else 0.0,
            "risk_levels": {c["framework_id"]: c["risk_level"] for c in classifications},
            "open_gaps": sum(len(a.get("controls_gap", [])) for a in assessments),
        },
    }

    export_id = str(uuid.uuid4())
    now = _now()
    with _cursor(db_path) as cur:
        cur.execute(
            """
            INSERT INTO ce_audit_exports
                (export_id, tenant_id, agent_id, framework_id, content_json, generated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (export_id, tenant_id, agent_id, framework_id, json.dumps(content), now),
        )

    return {"export_id": export_id, "generated_at": now, "content": content}


# ── Helpers ────────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

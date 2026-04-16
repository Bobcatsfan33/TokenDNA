"""
TokenDNA — Exploit Intent Correlation Engine (Sprint 2-2)

Correlates sequences of narrative-enriched UIS events against a library of
hand-authored attack playbooks to emit `exploit_intent_match` events with
severity and confidence scores.

Architecture
------------
Playbooks are declarative YAML-like dicts stored in the `intent_playbooks`
table.  Each playbook defines an ordered sequence of "steps", where each step
is a set of conditions that must match a UIS event's narrative fields.

The engine uses a sliding-window approach: for each incoming event it evaluates
all active playbooks, advancing any in-progress match sequences. When all steps
of a playbook are matched within the configured time window, an
`exploit_intent_match` record is written to `intent_matches`.

Match conditions (per step):
  category      — UIS event category (auth_anomaly, credential_abuse, etc.)
  mitre_technique — exact or prefix match on MITRE technique ID
  pivot          — exact match on narrative pivot field
  objective      — substring match on narrative objective field
  min_confidence — minimum narrative confidence score (0.0–1.0)
  risk_tier      — minimum risk tier (low/medium/high/critical)

All conditions within a step are AND-ed.  Steps within a playbook are AND-ed
in order (sequential).  A match is emitted when all steps match in sequence
within `window_seconds` of the first step match.

Built-in playbooks
------------------
Fifteen hand-authored playbooks covering the most common AI/agent attack
patterns are seeded on init_db().  Custom playbooks can be added via the API.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modules.storage import db_backend


# ── Constants ──────────────────────────────────────────────────────────────────

DEFAULT_WINDOW_SECONDS = int(os.getenv("ICE_WINDOW_SECONDS", "3600"))  # 1h
MAX_MATCHES_STORED = int(os.getenv("ICE_MAX_MATCHES", "10000"))

RISK_TIER_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_lock = threading.Lock()


# ── DB helpers ─────────────────────────────────────────────────────────────────

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


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_ts() -> float:
    return time.time()


# ── Schema ─────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intent_playbooks (
    playbook_id     TEXT PRIMARY KEY,
    tenant_id       TEXT,           -- NULL = global (applies to all tenants)
    name            TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,  -- low|medium|high|critical
    steps_json      TEXT NOT NULL,  -- JSON array of step condition objects
    window_seconds  INTEGER NOT NULL DEFAULT 3600,
    enabled         INTEGER NOT NULL DEFAULT 1,
    builtin         INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intent_matches (
    match_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    playbook_id     TEXT NOT NULL,
    playbook_name   TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL NOT NULL,
    detected_at     TEXT NOT NULL,
    first_event_at  TEXT NOT NULL,
    last_event_at   TEXT NOT NULL,
    matched_events  TEXT NOT NULL,  -- JSON array of event_id strings
    subject         TEXT,
    detail          TEXT,
    context_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_intent_matches_tenant_ts
    ON intent_matches(tenant_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS intent_match_state (
    state_id        TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    playbook_id     TEXT NOT NULL,
    subject         TEXT NOT NULL,
    step_index      INTEGER NOT NULL DEFAULT 0,
    matched_events  TEXT NOT NULL DEFAULT '[]',
    first_event_at  TEXT NOT NULL,
    last_event_at   TEXT NOT NULL,
    expires_at      REAL NOT NULL   -- unix timestamp
);

CREATE INDEX IF NOT EXISTS idx_intent_state_tenant_playbook
    ON intent_match_state(tenant_id, playbook_id, subject);
"""


def init_db() -> None:
    if _use_pg():
        return  # PG path: stub
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _lock:
        conn = _get_conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
            _seed_builtin_playbooks(conn)
        finally:
            conn.close()


# ── Built-in playbook library ──────────────────────────────────────────────────

BUILTIN_PLAYBOOKS: list[dict[str, Any]] = [
    # 1. Credential stuffing → session establishment
    {
        "name": "Credential Stuffing → Session Hijack",
        "description": "Attacker stuffs credentials at high velocity then establishes a session.",
        "severity": "high",
        "window_seconds": 1800,
        "steps": [
            {"category": "credential_abuse", "mitre_technique": "T1110.004", "min_confidence": 0.5},
            {"category": "auth_anomaly", "mitre_technique": "T1078", "min_confidence": 0.4},
        ],
    },
    # 2. Auth anomaly → privilege escalation
    {
        "name": "Auth Anomaly → Privilege Escalation",
        "description": "Attacker gains initial access via valid accounts then escalates privileges.",
        "severity": "high",
        "window_seconds": 3600,
        "steps": [
            {"category": "auth_anomaly", "min_confidence": 0.5},
            {"category": "privilege_escalation", "min_confidence": 0.5},
        ],
    },
    # 3. Privilege escalation → lateral movement
    {
        "name": "Privilege Escalation → Lateral Movement",
        "description": "Attacker escalates privileges then pivots to adjacent systems.",
        "severity": "critical",
        "window_seconds": 3600,
        "steps": [
            {"category": "privilege_escalation", "min_confidence": 0.5},
            {"category": "lateral_movement", "min_confidence": 0.5},
        ],
    },
    # 4. Three-stage: credential → privilege → exfil
    {
        "name": "Credential Abuse → Escalation → Exfiltration",
        "description": "Classic three-stage attack: credential theft, privilege escalation, data exfiltration.",
        "severity": "critical",
        "window_seconds": 7200,
        "steps": [
            {"category": "credential_abuse", "min_confidence": 0.4},
            {"category": "privilege_escalation", "min_confidence": 0.4},
            {"category": "exfiltration", "min_confidence": 0.4},
        ],
    },
    # 5. Token replay attack
    {
        "name": "Token Replay Attack",
        "description": "Stolen application access token replayed from a different context.",
        "severity": "high",
        "window_seconds": 900,
        "steps": [
            {"category": "credential_abuse", "mitre_technique": "T1528", "min_confidence": 0.6},
            {"category": "auth_anomaly", "risk_tier": "high", "min_confidence": 0.5},
        ],
    },
    # 6. Agent tool-call privilege pivot
    {
        "name": "Agent Tool-Call Privilege Pivot",
        "description": "Agent abuses tool-call chain to gain elevated privileges.",
        "severity": "high",
        "window_seconds": 1800,
        "steps": [
            {"category": "auth_anomaly", "objective": "escalat", "min_confidence": 0.4},
            {"category": "privilege_escalation", "mitre_technique": "T1548", "min_confidence": 0.5},
        ],
    },
    # 7. Prompt injection → RCE chain
    {
        "name": "Prompt Injection → Privilege Escalation",
        "description": "Agent receives malicious prompt leading to privilege escalation.",
        "severity": "critical",
        "window_seconds": 900,
        "steps": [
            {"category": "auth_anomaly", "pivot": "context_switch", "min_confidence": 0.4},
            {"category": "privilege_escalation", "min_confidence": 0.6},
        ],
    },
    # 8. Multi-hop AI-assisted exploit
    {
        "name": "Multi-Hop AI-Assisted Exploit Chain",
        "description": "AI agent orchestrates a multi-hop attack across multiple systems.",
        "severity": "critical",
        "window_seconds": 7200,
        "steps": [
            {"category": "auth_anomaly", "min_confidence": 0.4},
            {"category": "lateral_movement", "min_confidence": 0.5},
            {"category": "privilege_escalation", "min_confidence": 0.5},
            {"category": "exfiltration", "min_confidence": 0.4},
        ],
    },
    # 9. Session cookie theft
    {
        "name": "Session Cookie Theft",
        "description": "Web session cookie stolen and replayed.",
        "severity": "high",
        "window_seconds": 1800,
        "steps": [
            {"category": "credential_abuse", "mitre_technique": "T1539", "min_confidence": 0.6},
            {"category": "auth_anomaly", "min_confidence": 0.4},
        ],
    },
    # 10. Cloud storage exfiltration
    {
        "name": "Cloud Storage Exfiltration",
        "description": "Attacker transfers data to adversary-controlled cloud storage.",
        "severity": "critical",
        "window_seconds": 3600,
        "steps": [
            {"category": "privilege_escalation", "min_confidence": 0.4},
            {"category": "exfiltration", "mitre_technique": "T1537", "min_confidence": 0.5},
        ],
    },
    # 11. Account manipulation persistence
    {
        "name": "Account Manipulation for Persistence",
        "description": "Attacker manipulates accounts to maintain long-term access.",
        "severity": "high",
        "window_seconds": 86400,  # 24h window
        "steps": [
            {"category": "privilege_escalation", "mitre_technique": "T1098", "min_confidence": 0.5},
            {"category": "auth_anomaly", "min_confidence": 0.3},
        ],
    },
    # 12. Lateral movement via alternate auth material
    {
        "name": "Lateral Movement via Alternate Auth Material",
        "description": "Attacker uses stolen tokens/cookies to move laterally.",
        "severity": "high",
        "window_seconds": 3600,
        "steps": [
            {"category": "lateral_movement", "mitre_technique": "T1550", "min_confidence": 0.6},
            {"category": "privilege_escalation", "min_confidence": 0.4},
        ],
    },
    # 13. Masquerading + exfiltration
    {
        "name": "Identity Masquerading → Data Exfiltration",
        "description": "Attacker masquerades as legitimate identity to exfiltrate data.",
        "severity": "critical",
        "window_seconds": 3600,
        "steps": [
            {"category": "lateral_movement", "mitre_technique": "T1036", "min_confidence": 0.5},
            {"category": "exfiltration", "min_confidence": 0.4},
        ],
    },
    # 14. Brute force → valid account access
    {
        "name": "Brute Force → Valid Account",
        "description": "Brute force attack succeeds and attacker gains legitimate-looking access.",
        "severity": "high",
        "window_seconds": 1800,
        "steps": [
            {"category": "credential_abuse", "mitre_technique": "T1110", "min_confidence": 0.5},
            {"category": "auth_anomaly", "mitre_technique": "T1078.004", "min_confidence": 0.4},
        ],
    },
    # 15. Full kill chain (five-stage)
    {
        "name": "Full Kill Chain: Credential → Escalation → Lateral → Escalation → Exfil",
        "description": "Complete adversary kill chain across five stages.",
        "severity": "critical",
        "window_seconds": 14400,  # 4h window
        "steps": [
            {"category": "credential_abuse", "min_confidence": 0.3},
            {"category": "privilege_escalation", "min_confidence": 0.3},
            {"category": "lateral_movement", "min_confidence": 0.3},
            {"category": "privilege_escalation", "min_confidence": 0.3},
            {"category": "exfiltration", "min_confidence": 0.3},
        ],
    },
]


def _seed_builtin_playbooks(conn: sqlite3.Connection) -> None:
    """Insert built-in playbooks if not already present."""
    now = _now_iso()
    for pb in BUILTIN_PLAYBOOKS:
        pid = f"builtin:{pb['name'].lower().replace(' ', '_').replace('→','_')[:40]}"
        existing = conn.execute(
            "SELECT 1 FROM intent_playbooks WHERE playbook_id=?", (pid,)
        ).fetchone()
        if not existing:
            conn.execute(
                """
                INSERT INTO intent_playbooks
                    (playbook_id, tenant_id, name, description, severity,
                     steps_json, window_seconds, enabled, builtin,
                     created_at, updated_at)
                VALUES (?, NULL, ?, ?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (
                    pid,
                    pb["name"],
                    pb["description"],
                    pb["severity"],
                    json.dumps(pb["steps"]),
                    pb.get("window_seconds", DEFAULT_WINDOW_SECONDS),
                    now,
                    now,
                ),
            )
    conn.commit()


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class IntentMatch:
    match_id: str
    tenant_id: str
    playbook_id: str
    playbook_name: str
    severity: str
    confidence: float
    detected_at: str
    first_event_at: str
    last_event_at: str
    matched_events: list[str]
    subject: str | None
    detail: str
    context: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "match_id": self.match_id,
            "tenant_id": self.tenant_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "detected_at": self.detected_at,
            "first_event_at": self.first_event_at,
            "last_event_at": self.last_event_at,
            "matched_events": self.matched_events,
            "subject": self.subject,
            "detail": self.detail,
            "context": self.context,
        }


# ── Step matching ──────────────────────────────────────────────────────────────

def _step_matches(step: dict[str, Any], event: dict[str, Any]) -> bool:
    """
    Return True if the event satisfies all conditions in the step.
    event must contain 'uis_narrative' (from uis_narrative.enrich_event)
    or narrative-like fields at the top level.
    """
    narrative = event.get("uis_narrative") or {}
    category = narrative.get("category") or ""
    mitre_technique = narrative.get("mitre_technique") or ""
    pivot = narrative.get("pivot") or narrative.get("precondition") or ""
    objective = narrative.get("objective") or ""
    confidence = float(narrative.get("confidence") or 0.0)

    # Fallback: check threat block for risk_tier
    threat = event.get("threat") or {}
    risk_tier = str(threat.get("risk_tier") or "low")

    # category match
    if step_cat := step.get("category"):
        if step_cat != category:
            return False

    # mitre_technique match (prefix OK: "T1550" matches "T1550.001")
    if step_mitre := step.get("mitre_technique"):
        if not mitre_technique.startswith(step_mitre):
            return False

    # pivot match (exact)
    if step_pivot := step.get("pivot"):
        if step_pivot != pivot:
            return False

    # objective substring match
    if step_obj := step.get("objective"):
        if step_obj.lower() not in objective.lower():
            return False

    # min_confidence
    if (min_conf := step.get("min_confidence")) is not None:
        if confidence < float(min_conf):
            return False

    # risk_tier minimum
    if step_tier := step.get("risk_tier"):
        if RISK_TIER_ORDER.get(risk_tier, 0) < RISK_TIER_ORDER.get(step_tier, 0):
            return False

    return True


# ── Correlation engine ─────────────────────────────────────────────────────────

def correlate_event(tenant_id: str, event: dict[str, Any]) -> list[IntentMatch]:
    """
    Process a single UIS event against all active playbooks for the tenant.
    Updates in-progress match states and returns any completed matches.

    Called from uis_store.insert_event (non-fatal hook).
    """
    if _use_pg():
        return []

    event_id = event.get("event_id") or str(uuid.uuid4())
    event_ts = event.get("event_timestamp") or _now_iso()
    subject = (event.get("identity") or {}).get("subject") or ""

    completed: list[IntentMatch] = []

    with _lock:
        conn = _get_conn()
        try:
            # Load all active playbooks applicable to this tenant
            playbooks = conn.execute(
                """
                SELECT * FROM intent_playbooks
                WHERE enabled=1 AND (tenant_id IS NULL OR tenant_id=?)
                """,
                (tenant_id,),
            ).fetchall()

            for pb in playbooks:
                steps = json.loads(pb["steps_json"])
                if not steps:
                    continue
                pid = pb["playbook_id"]
                window = float(pb["window_seconds"])
                now_ts = _now_ts()

                # Load existing in-progress state for (tenant, playbook, subject)
                state = conn.execute(
                    """
                    SELECT * FROM intent_match_state
                    WHERE tenant_id=? AND playbook_id=? AND subject=?
                    """,
                    (tenant_id, pid, subject),
                ).fetchone()

                # Expire stale state
                if state and state["expires_at"] < now_ts:
                    conn.execute(
                        "DELETE FROM intent_match_state WHERE state_id=?",
                        (state["state_id"],),
                    )
                    state = None

                current_step_idx = state["step_index"] if state else 0

                if not _step_matches(steps[current_step_idx], event):
                    continue  # This event doesn't advance this playbook

                # Advance state
                new_events = json.loads(state["matched_events"]) if state else []
                new_events.append(event_id)
                first_event_at = state["first_event_at"] if state else event_ts
                next_step = current_step_idx + 1

                if next_step >= len(steps):
                    # All steps matched — emit match
                    avg_confidence = _compute_confidence(steps, event, state)
                    match = IntentMatch(
                        match_id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        playbook_id=pid,
                        playbook_name=pb["name"],
                        severity=pb["severity"],
                        confidence=avg_confidence,
                        detected_at=_now_iso(),
                        first_event_at=first_event_at,
                        last_event_at=event_ts,
                        matched_events=new_events,
                        subject=subject or None,
                        detail=(
                            f"Playbook '{pb['name']}' matched {len(new_events)} events "
                            f"for subject '{subject}' with confidence {avg_confidence:.2f}"
                        ),
                        context={
                            "steps_count": len(steps),
                            "window_seconds": window,
                        },
                    )
                    conn.execute(
                        """
                        INSERT INTO intent_matches
                            (match_id, tenant_id, playbook_id, playbook_name, severity,
                             confidence, detected_at, first_event_at, last_event_at,
                             matched_events, subject, detail, context_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            match.match_id,
                            tenant_id,
                            pid,
                            pb["name"],
                            pb["severity"],
                            avg_confidence,
                            match.detected_at,
                            first_event_at,
                            event_ts,
                            json.dumps(new_events),
                            subject or None,
                            match.detail,
                            json.dumps(match.context),
                        ),
                    )
                    # Reset state for next occurrence
                    if state:
                        conn.execute(
                            "DELETE FROM intent_match_state WHERE state_id=?",
                            (state["state_id"],),
                        )
                    completed.append(match)
                else:
                    # Upsert in-progress state
                    if state:
                        conn.execute(
                            """
                            UPDATE intent_match_state SET
                                step_index=?, matched_events=?, last_event_at=?,
                                expires_at=?
                            WHERE state_id=?
                            """,
                            (
                                next_step,
                                json.dumps(new_events),
                                event_ts,
                                now_ts + window,
                                state["state_id"],
                            ),
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO intent_match_state
                                (state_id, tenant_id, playbook_id, subject,
                                 step_index, matched_events, first_event_at,
                                 last_event_at, expires_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                str(uuid.uuid4()),
                                tenant_id,
                                pid,
                                subject,
                                next_step,
                                json.dumps(new_events),
                                event_ts,
                                event_ts,
                                now_ts + window,
                            ),
                        )
            conn.commit()
        finally:
            conn.close()

    return completed


def _compute_confidence(
    steps: list[dict],
    last_event: dict,
    state: Any,
) -> float:
    """
    Average confidence across matched steps.
    Uses last event's narrative confidence for the final step;
    assumes 0.7 for prior steps (stored confidence not tracked per-step
    in this version — a Sprint 2-3 refinement).
    """
    n = last_event.get("uis_narrative") or {}
    last_conf = float(n.get("confidence") or 0.5)
    prior_count = len(steps) - 1
    if prior_count <= 0:
        return last_conf
    total = (0.7 * prior_count) + last_conf
    return round(total / len(steps), 3)


# ── Query API ──────────────────────────────────────────────────────────────────

def get_matches(
    tenant_id: str,
    limit: int = 50,
    severity: str | None = None,
    playbook_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return recent intent matches for a tenant."""
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            params: list[Any] = [tenant_id]
            where = ["tenant_id=?"]
            if severity:
                where.append("severity=?")
                params.append(severity)
            if playbook_id:
                where.append("playbook_id=?")
                params.append(playbook_id)
            rows = conn.execute(
                f"""
                SELECT * FROM intent_matches
                WHERE {' AND '.join(where)}
                ORDER BY detected_at DESC
                LIMIT ?
                """,
                tuple(params) + (min(limit, 200),),
            ).fetchall()
            return [
                {
                    "match_id": r["match_id"],
                    "playbook_id": r["playbook_id"],
                    "playbook_name": r["playbook_name"],
                    "severity": r["severity"],
                    "confidence": r["confidence"],
                    "detected_at": r["detected_at"],
                    "first_event_at": r["first_event_at"],
                    "last_event_at": r["last_event_at"],
                    "matched_events": json.loads(r["matched_events"]),
                    "subject": r["subject"],
                    "detail": r["detail"],
                    "context": json.loads(r["context_json"] or "{}"),
                }
                for r in rows
            ]
        finally:
            conn.close()


def get_playbooks(
    tenant_id: str | None = None,
    include_builtin: bool = True,
) -> list[dict[str, Any]]:
    """Return playbooks (global built-ins + tenant-specific)."""
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            params: list[Any] = []
            where: list[str] = []
            if not include_builtin:
                where.append("builtin=0")
            if tenant_id:
                where.append("(tenant_id IS NULL OR tenant_id=?)")
                params.append(tenant_id)
            w = f"WHERE {' AND '.join(where)}" if where else ""
            rows = conn.execute(
                f"SELECT * FROM intent_playbooks {w} ORDER BY builtin DESC, name",
                tuple(params),
            ).fetchall()
            return [
                {
                    "playbook_id": r["playbook_id"],
                    "tenant_id": r["tenant_id"],
                    "name": r["name"],
                    "description": r["description"],
                    "severity": r["severity"],
                    "steps": json.loads(r["steps_json"]),
                    "window_seconds": r["window_seconds"],
                    "enabled": bool(r["enabled"]),
                    "builtin": bool(r["builtin"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()


def add_playbook(
    tenant_id: str,
    name: str,
    description: str,
    severity: str,
    steps: list[dict[str, Any]],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> str:
    """Create a custom playbook. Returns the new playbook_id."""
    if not steps:
        raise ValueError("playbook must have at least one step")
    if severity not in ("low", "medium", "high", "critical"):
        raise ValueError(f"invalid severity: {severity}")

    pid = f"custom:{uuid.uuid4().hex[:16]}"
    now = _now_iso()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO intent_playbooks
                    (playbook_id, tenant_id, name, description, severity,
                     steps_json, window_seconds, enabled, builtin, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
                """,
                (pid, tenant_id, name, description, severity,
                 json.dumps(steps), window_seconds, now, now),
            )
            conn.commit()
        finally:
            conn.close()
    return pid


def delete_playbook(tenant_id: str, playbook_id: str) -> bool:
    """Delete a custom (non-builtin) playbook. Returns True if deleted."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT builtin FROM intent_playbooks WHERE playbook_id=? AND tenant_id=?",
                (playbook_id, tenant_id),
            ).fetchone()
            if not row:
                return False
            if row["builtin"]:
                return False  # Cannot delete built-in playbooks
            conn.execute(
                "DELETE FROM intent_playbooks WHERE playbook_id=?", (playbook_id,)
            )
            conn.commit()
            return True
        finally:
            conn.close()

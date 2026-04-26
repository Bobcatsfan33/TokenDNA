"""
TokenDNA — Shadow Mode trial framework

Lets a prospect point TokenDNA at their real audit-log streams in pure
**observe-only** mode for a 14-day evaluation.  No enforcement actions are
taken — no policy_guard BLOCKs propagate, no MCP calls are rejected, no
honeypot decoys plant new bait.  All detections still fire and are
captured into the audit log; the trial report renders them at the end.

Why this matters for sales
──────────────────────────

The seeded demo (``scripts/demo_seed_v2.py``) gets a prospect to "yes."
The conversion to a paid pilot needs a **shadow-mode trial** that proves
the value against THEIR data.  Pattern:

  1. Operator points a connector at one of their existing audit log streams
     (CloudTrail JSONL on S3, GitHub audit log export, Okta system log dump).
  2. Connector ingests the events into TokenDNA's UIS event format.
  3. All detection runs but ``shadow_mode.is_active() == True`` short-circuits
     every enforcement code path to a no-op + audit-only emission.
  4. After 14 days, ``scripts/shadow_trial_report.py`` renders the findings
     report — "here are the 23 unattested permission expansions in your real
     environment, here are the 7 agents whose blast radius exceeds policy,
     here is the self-modification attempt your existing tools missed."

That report is what closes the deal.

Connector framework
───────────────────

A connector is anything that produces UIS-formatted dicts.  This module
ships ONE example connector:

  ``FileTailJSONLConnector`` — tails a JSONL file, treating each line
  as one externally-formatted audit event.  Operators map their fields
  to TokenDNA's UIS schema via a simple ``mapping`` dict; the result is
  fed through ``uis_store.insert_event`` exactly like a real event.

Future connectors (CloudTrail, GitHub, Okta) follow the same shape —
file-tail is the lightest dep that proves the pattern works.

Activation
──────────

Set ``TOKENDNA_SHADOW_MODE=true`` in the environment OR call
``set_shadow_active(True, tenant_id)`` programmatically.  Modules that
take enforcement actions should consult ``is_active(tenant_id)`` and
emit a SHADOW_MODE_OBSERVED audit event instead of acting.

The trial report (rendered by ``scripts/shadow_trial_report.py``) reads
from existing audit_log + violation tables and produces a structured
finding bundle suitable for embedding in a customer-facing PDF.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

log = logging.getLogger(__name__)

_lock = threading.Lock()
_shadow_state: dict[str, bool] = {}  # tenant_id -> shadow_active
_GLOBAL_KEY = "__global__"


# ── Activation API ────────────────────────────────────────────────────────────


def is_active(tenant_id: str | None = None) -> bool:
    """
    Return True if shadow mode is active for ``tenant_id`` (or globally).

    Resolution order:
      1. Per-tenant override set via ``set_shadow_active(...)``.
      2. Global override set via ``set_shadow_active(active, None)``.
      3. Environment variable ``TOKENDNA_SHADOW_MODE`` truthy.
    """
    with _lock:
        if tenant_id and tenant_id in _shadow_state:
            return _shadow_state[tenant_id]
        if _GLOBAL_KEY in _shadow_state:
            return _shadow_state[_GLOBAL_KEY]
    raw = str(os.getenv("TOKENDNA_SHADOW_MODE", "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def set_shadow_active(active: bool, tenant_id: str | None = None) -> None:
    """
    Override shadow-mode activation programmatically.  Pass ``tenant_id=None``
    to set the global override.  Tests should call this in setup/teardown.
    """
    key = tenant_id or _GLOBAL_KEY
    with _lock:
        _shadow_state[key] = active


def clear_shadow_state() -> None:
    """Forget all in-memory overrides — falls back to env var."""
    with _lock:
        _shadow_state.clear()


# ── Connector framework ───────────────────────────────────────────────────────


@dataclass
class ConnectorReport:
    connector_name: str
    tenant_id: str
    started_at: str
    completed_at: str
    events_seen: int
    events_ingested: int
    events_skipped: int
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "connector_name": self.connector_name,
            "tenant_id": self.tenant_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "events_seen": self.events_seen,
            "events_ingested": self.events_ingested,
            "events_skipped": self.events_skipped,
            "errors": self.errors,
        }


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FileTailJSONLConnector:
    """
    Read a newline-delimited JSON file (typical of CloudTrail/GitHub/Okta
    exports) and emit UIS events via a caller-provided ``mapping`` callable.

    The mapping is a function that takes a single source-format dict and
    returns a UIS event dict (or ``None`` to skip the row).  Keep mappings
    minimal — the customer's job is to specify which of their fields go
    where; TokenDNA's job is to ingest cleanly.

    Usage::

        def cloudtrail_to_uis(row: dict) -> dict | None:
            if row.get("eventSource") != "iam.amazonaws.com":
                return None
            return {
                "uis_version": "1.0",
                "event_id": row["eventID"],
                "event_timestamp": row["eventTime"],
                "identity": {...},
                ...
            }

        connector = FileTailJSONLConnector(
            tenant_id="prospect-acme",
            source_path="/data/cloudtrail-2026-04-15.jsonl",
            mapping=cloudtrail_to_uis,
        )
        report = connector.run()

    The connector is shadow-aware — when ``is_active(tenant_id) == True``,
    every event is INGESTED but flagged with ``metadata.shadow_observed=True``
    so the trial report can distinguish observed-only events from live ones.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        source_path: str | pathlib.Path,
        mapping: Callable[[dict], dict | None],
        ingest_fn: Callable[[dict], Any] | None = None,
        max_events: int | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.source_path = pathlib.Path(source_path)
        self.mapping = mapping
        self._ingest_fn = ingest_fn
        self.max_events = max_events
        self.name = f"file-tail:{self.source_path.name}"

    def _resolve_ingest(self) -> Callable[[dict], Any]:
        if self._ingest_fn is not None:
            return self._ingest_fn
        # Default — route through uis_store.  Imported lazily so the
        # connector framework has no hard dep on the storage layer at
        # import time (tests can supply their own ingest_fn).
        from modules.identity import uis_store

        return uis_store.insert_event

    def run(self) -> ConnectorReport:
        started = _iso_now()
        events_seen = 0
        events_ingested = 0
        events_skipped = 0
        errors: list[str] = []
        if not self.source_path.exists():
            return ConnectorReport(
                connector_name=self.name, tenant_id=self.tenant_id,
                started_at=started, completed_at=_iso_now(),
                events_seen=0, events_ingested=0, events_skipped=0,
                errors=[f"source file not found: {self.source_path}"],
            )

        ingest = self._resolve_ingest()
        shadow = is_active(self.tenant_id)

        with self.source_path.open("r") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                events_seen += 1
                if self.max_events and events_seen > self.max_events:
                    break
                try:
                    src = json.loads(line)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {line_no}: invalid JSON ({exc})")
                    events_skipped += 1
                    continue
                try:
                    uis_event = self.mapping(src)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"line {line_no}: mapping raised {exc}")
                    events_skipped += 1
                    continue
                if uis_event is None:
                    events_skipped += 1
                    continue
                # Stamp the event with shadow + connector metadata so the
                # trial report can attribute findings.
                meta = uis_event.setdefault("metadata", {})
                meta["shadow_observed"] = shadow
                meta["connector"] = self.name
                meta["source_line"] = line_no
                try:
                    ingest(uis_event)
                    events_ingested += 1
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"line {line_no}: ingest raised {exc}")
                    events_skipped += 1

        return ConnectorReport(
            connector_name=self.name, tenant_id=self.tenant_id,
            started_at=started, completed_at=_iso_now(),
            events_seen=events_seen, events_ingested=events_ingested,
            events_skipped=events_skipped, errors=errors,
        )


# ── Trial report ──────────────────────────────────────────────────────────────


@dataclass
class TrialReport:
    """Structured "what we found" report for a 14-day shadow trial."""
    tenant_id: str
    generated_at: str
    window_days: int
    events_observed: int
    unique_agents_observed: int
    anomalies_by_type: dict[str, int]
    policy_violations_blocked: int
    policy_violations_open: int
    drift_alerts_critical: int
    drift_alerts_total: int
    mcp_chain_pattern_matches: int
    cross_org_blocks: int
    federation_trusts_active: int
    high_blast_radius_agents: list[dict[str, Any]]
    top_findings: list[dict[str, Any]]
    deltas_vs_baseline: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at,
            "window_days": self.window_days,
            "events_observed": self.events_observed,
            "unique_agents_observed": self.unique_agents_observed,
            "anomalies_by_type": self.anomalies_by_type,
            "policy_violations_blocked": self.policy_violations_blocked,
            "policy_violations_open": self.policy_violations_open,
            "drift_alerts_critical": self.drift_alerts_critical,
            "drift_alerts_total": self.drift_alerts_total,
            "mcp_chain_pattern_matches": self.mcp_chain_pattern_matches,
            "cross_org_blocks": self.cross_org_blocks,
            "federation_trusts_active": self.federation_trusts_active,
            "high_blast_radius_agents": self.high_blast_radius_agents,
            "top_findings": self.top_findings,
            "deltas_vs_baseline": self.deltas_vs_baseline,
        }


def generate_trial_report(
    tenant_id: str,
    *,
    window_days: int = 14,
    db_path: str | None = None,
) -> TrialReport:
    """
    Walk the existing TokenDNA tables and synthesize the trial findings.
    Read-only — never writes.  Safe to invoke against a live customer
    instance.
    """
    import sqlite3
    from datetime import timedelta

    db = db_path or os.getenv("DATA_DB_PATH", "/data/tokendna.db")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
    conn = sqlite3.connect(db, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        events_observed = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM uis_events WHERE tenant_id=? AND event_timestamp>=?",
            (tenant_id, cutoff),
        )
        unique_agents = _safe_count(
            conn,
            "SELECT COUNT(DISTINCT agent_id) AS n FROM uis_events WHERE tenant_id=? AND event_timestamp>=? AND agent_id IS NOT NULL",
            (tenant_id, cutoff),
        )
        anomalies_by_type: dict[str, int] = {}
        for row in _safe_query(
            conn,
            "SELECT anomaly_type, COUNT(*) AS n FROM tg_anomalies WHERE tenant_id=? AND detected_at>=? GROUP BY anomaly_type",
            (tenant_id, cutoff),
        ):
            anomalies_by_type[row["anomaly_type"]] = row["n"]
        violations_blocked = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM policy_guard_violations WHERE tenant_id=? AND disposition='block' AND detected_at>=?",
            (tenant_id, cutoff),
        )
        violations_open = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM policy_guard_violations WHERE tenant_id=? AND status='open' AND detected_at>=?",
            (tenant_id, cutoff),
        )
        drift_total = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM drift_alerts WHERE tenant_id=? AND detected_at>=?",
            (tenant_id, cutoff),
        )
        drift_critical = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM drift_alerts WHERE tenant_id=? AND growth_factor>=3.0 AND detected_at>=?",
            (tenant_id, cutoff),
        )
        mcp_chain_matches = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM mcp_call_log WHERE tenant_id=? AND chain_patterns NOT IN ('[]', '') AND created_at>=?",
            (tenant_id, cutoff),
        )
        cross_org_blocks = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM tg_anomalies WHERE tenant_id=? AND anomaly_type='CROSS_ORG_ACTION_WITHOUT_HANDSHAKE' AND detected_at>=?",
            (tenant_id, cutoff),
        )
        federation_active = _safe_count(
            conn,
            "SELECT COUNT(*) AS n FROM federation_trusts WHERE local_org_id=? AND status='active'",
            (tenant_id,),
        )

        # High blast-radius agents — pull the top 5 by reachability count.
        # Best-effort: blast_radius is computed on demand, not stored, so
        # we count reachable nodes via a simple edge-out heuristic.
        high_blast: list[dict[str, Any]] = []
        try:
            for row in conn.execute(
                """
                SELECT n.label AS agent, COUNT(e.dst_node) AS reach
                FROM tg_nodes n
                LEFT JOIN tg_edges e
                  ON e.src_node = n.node_id AND e.tenant_id = n.tenant_id
                WHERE n.tenant_id = ? AND n.node_type IN ('agent', 'workload')
                GROUP BY n.label
                ORDER BY reach DESC
                LIMIT 5
                """,
                (tenant_id,),
            ).fetchall():
                if row["reach"] > 0:
                    high_blast.append({
                        "agent": row["agent"],
                        "reach": row["reach"],
                    })
        except sqlite3.OperationalError:
            pass

        top_findings = _build_top_findings(
            anomalies_by_type=anomalies_by_type,
            drift_critical=drift_critical,
            mcp_chain_matches=mcp_chain_matches,
            violations_blocked=violations_blocked,
            cross_org_blocks=cross_org_blocks,
        )

        return TrialReport(
            tenant_id=tenant_id,
            generated_at=_iso_now(),
            window_days=window_days,
            events_observed=events_observed,
            unique_agents_observed=unique_agents,
            anomalies_by_type=anomalies_by_type,
            policy_violations_blocked=violations_blocked,
            policy_violations_open=violations_open,
            drift_alerts_critical=drift_critical,
            drift_alerts_total=drift_total,
            mcp_chain_pattern_matches=mcp_chain_matches,
            cross_org_blocks=cross_org_blocks,
            federation_trusts_active=federation_active,
            high_blast_radius_agents=high_blast,
            top_findings=top_findings,
        )
    finally:
        conn.close()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _safe_count(conn, sql: str, params: tuple) -> int:
    try:
        row = conn.execute(sql, params).fetchone()
        return int(row["n"]) if row else 0
    except Exception:
        return 0


def _safe_query(conn, sql: str, params: tuple) -> Iterable:
    try:
        return conn.execute(sql, params).fetchall()
    except Exception:
        return []


def _build_top_findings(
    *,
    anomalies_by_type: dict[str, int],
    drift_critical: int,
    mcp_chain_matches: int,
    violations_blocked: int,
    cross_org_blocks: int,
) -> list[dict[str, Any]]:
    """Produce the human-readable headline findings for the trial report."""
    findings: list[dict[str, Any]] = []
    if anomalies_by_type.get("POLICY_SCOPE_MODIFICATION"):
        findings.append({
            "severity": "critical",
            "title": "Agent self-modification detected",
            "count": anomalies_by_type["POLICY_SCOPE_MODIFICATION"],
            "summary": (
                "One or more agents in this environment modified policies that "
                "govern their own permission boundary — the CrowdStrike F50 "
                "self-elevation pattern.  Existing tools missed this."
            ),
        })
    if drift_critical:
        findings.append({
            "severity": "high",
            "title": "Critical permission drift",
            "count": drift_critical,
            "summary": (
                f"{drift_critical} agents grew their permission scope by 3x or more "
                "without an accompanying attestation event."
            ),
        })
    if mcp_chain_matches:
        findings.append({
            "severity": "high",
            "title": "MCP attack-chain matches",
            "count": mcp_chain_matches,
            "summary": (
                f"{mcp_chain_matches} MCP tool-call sequences matched known "
                "attack chain patterns (read→exfil, privilege ladder, etc.)."
            ),
        })
    if cross_org_blocks:
        findings.append({
            "severity": "critical",
            "title": "Cross-org actions without federation",
            "count": cross_org_blocks,
            "summary": (
                f"{cross_org_blocks} attempts to take action against external "
                "organization resources without an established federation trust."
            ),
        })
    if violations_blocked:
        findings.append({
            "severity": "high",
            "title": "Policy violations blocked",
            "count": violations_blocked,
            "summary": (
                f"{violations_blocked} policy modifications would have been blocked "
                "by TokenDNA enforcement.  In shadow mode, they were observed only."
            ),
        })
    if not findings:
        findings.append({
            "severity": "info",
            "title": "No high-severity findings in trial window",
            "count": 0,
            "summary": (
                "No critical or high-severity events were observed during this "
                "trial.  This is itself useful evidence — establishes a baseline "
                "for ongoing monitoring."
            ),
        })
    return findings

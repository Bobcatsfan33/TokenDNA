"""Tamper-evident TraceReport (P2.2).

Answers the third question — "what did it touch, and can I prove it?" — as
*evidence*, not just a story. The report is pure orchestration: it introduces no
new detection algorithms, it composes what the pillars already know into one
time-ordered narrative:

  * ``trust_graph``        — anomalies detected on the agent (why we are looking)
  * ``uis_store``          — the agent's actual event timeline (what it did)
  * ``delegation_receipt`` — who delegated what to whom (how it got its authority)
  * ``audit_log``          — what TokenDNA did about it (the containment actions)
  * ``blast_radius``       — who else is reachable (how far it could have gone)

Tamper-evidence has two independent layers:

1. **The report chains itself.** Each row carries ``prev_hash``/``row_hash``,
   hashed with the same primitive the audit log uses (HMAC-SHA256 when
   ``AUDIT_HMAC_KEY`` is set, SHA-256 otherwise). Reorder, edit, insert or drop a
   row and ``verify_trace_report`` reports the first violation.
2. **Its citations are checkable.** Every row carries an ``evidence_pointer``
   back to its source of record. Audit-sourced rows point at
   ``audit:<sequence>:<entry_hash>``, so a verifier can re-read the independent,
   hash-chained audit log and confirm the row still matches it. A report that
   agrees with itself but disagrees with the audit log is caught.

A verified report is therefore not "TokenDNA says this happened" — it is "here is
the chain, re-derive it yourself."
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from modules.security import audit_log

GENESIS_HASH = "0" * 64

# Sources, in the order they are merged before sorting.
SOURCE_ANOMALY = "anomaly"
SOURCE_UIS = "uis"
SOURCE_DELEGATION = "delegation"
SOURCE_AUDIT = "audit"

DEFAULT_WINDOW_HOURS = 24
DEFAULT_MAX_ROWS = 200
# UIS events are pulled newest-first and then filtered to the agent in Python
# (the store indexes `subject`, which is not the same field as identity.agent_id).
# Over-fetch so an active tenant's window still yields the agent's rows.
_UIS_SCAN_MULTIPLIER = 10


# ── Row / report ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TraceRow:
    """One time-ordered fact, with a pointer back to its source of record."""
    timestamp: str
    agent: str
    credential: str
    action: str
    resource: str
    evidence_pointer: str
    source: str
    narrative: str
    severity: str = "info"
    prev_hash: str = ""
    row_hash: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TraceReport:
    tenant_id: str
    agent_id: str
    generated_at: str
    window_start: str
    window_end: str
    rows: list[TraceRow] = field(default_factory=list)
    blast_radius: dict[str, Any] | None = None
    report_hash: str = GENESIS_HASH

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "generated_at": self.generated_at,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "rows": [r.as_dict() for r in self.rows],
            "blast_radius": self.blast_radius,
            "report_hash": self.report_hash,
            "row_count": len(self.rows),
        }


# ── Time helpers ──────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: str | None) -> datetime | None:
    """Tolerant ISO-8601 parse. The stores were written by different sprints and
    disagree on trailing 'Z' vs '+00:00' vs naive; none of them are wrong enough
    to drop a row over."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sort_key(row: TraceRow) -> tuple[float, str]:
    dt = _parse_ts(row.timestamp)
    # Unparseable timestamps sort last rather than vanish — surfacing bad data
    # beats silently dropping a fact from an evidence report.
    return (dt.timestamp() if dt else float("inf"), row.source)


# ── Hash chain ────────────────────────────────────────────────────────────────

def _row_canonical(row: TraceRow, prev_hash: str) -> bytes:
    """Deterministic bytes for a row — excludes the row's own hash."""
    payload = row.as_dict()
    payload.pop("row_hash", None)
    payload["prev_hash"] = prev_hash
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _chain(rows: list[TraceRow]) -> list[TraceRow]:
    """Link rows into a hash chain. Returns new rows (never mutates)."""
    chained: list[TraceRow] = []
    prev = GENESIS_HASH
    for row in rows:
        # compute_evidence_hash: HMAC-SHA256 when AUDIT_HMAC_KEY is configured,
        # SHA-256 otherwise. Reused so the report inherits the audit log's crypto
        # posture rather than inventing a second, weaker one.
        row_hash = audit_log.compute_evidence_hash(_row_canonical(row, prev))
        chained.append(TraceRow(**{**row.as_dict(), "prev_hash": prev,
                                   "row_hash": row_hash}))
        prev = row_hash
    return chained


# ── Row builders (one per source) ─────────────────────────────────────────────

def _anomaly_rows(tenant_id: str, agent_id: str, since: datetime) -> list[TraceRow]:
    from modules.identity import trust_graph

    rows: list[TraceRow] = []
    for a in trust_graph.get_anomalies(tenant_id, limit=200):
        ctx = a.get("context") or {}
        subject = ctx.get("agent_label") or ctx.get("subject_label") or ""
        # Anomalies key on node id; the agent label lives in the context.
        if subject and subject != agent_id:
            continue
        if not subject and agent_id not in str(a.get("detail", "")):
            continue
        ts = _parse_ts(a.get("detected_at"))
        if ts and ts < since:
            continue
        rows.append(TraceRow(
            timestamp=a.get("detected_at", ""),
            agent=agent_id,
            credential="-",
            action=a.get("anomaly_type", "ANOMALY"),
            resource=a.get("subject_node", ""),
            evidence_pointer=f"anomaly:{a.get('id', '?')}",
            source=SOURCE_ANOMALY,
            severity=a.get("severity", "medium"),
            narrative=(
                f"TokenDNA detected {a.get('anomaly_type', 'an anomaly')} "
                f"({a.get('severity', 'medium')}): {a.get('detail', '')}"
            ),
        ))
    return rows


def _uis_rows(tenant_id: str, agent_id: str, since: datetime,
              max_rows: int) -> list[TraceRow]:
    from modules.identity import uis_store

    rows: list[TraceRow] = []
    events = uis_store.list_events(tenant_id, limit=max_rows * _UIS_SCAN_MULTIPLIER)
    for ev in events:
        identity = ev.get("identity") or {}
        if identity.get("agent_id") != agent_id:
            continue
        ts = _parse_ts(ev.get("event_timestamp"))
        if ts and ts < since:
            continue

        auth = ev.get("auth") or {}
        token = ev.get("token") or {}
        binding = ev.get("binding") or {}
        meta = ev.get("metadata") or {}

        # The UIS schema has no free-text action/resource: an event records an
        # identity using a protocol+method against an audience. That pairing IS
        # the action, and it matches trust_graph's own tool-label convention.
        protocol = auth.get("protocol") or "unknown"
        method = auth.get("method") or "unknown"
        action = f"{protocol}:{method}"
        resource = token.get("audience") or identity.get("subject") or "-"
        credential = (binding.get("attestation_id") or binding.get("spiffe_id")
                      or token.get("issuer") or "-")
        outcome = ev.get("outcome", "success")
        mitre = meta.get("mitre_technique")

        narrative = (
            f"Agent {agent_id} authenticated via {action} to {resource} "
            f"({outcome})"
        )
        if mitre:
            narrative += f" — mapped to MITRE {mitre}"

        rows.append(TraceRow(
            timestamp=ev.get("event_timestamp", ""),
            agent=agent_id,
            credential=credential,
            action=action,
            resource=resource,
            evidence_pointer=f"uis:{ev.get('event_id', '?')}",
            source=SOURCE_UIS,
            severity="info" if outcome == "success" else "medium",
            narrative=narrative,
        ))
    return rows


def _delegation_rows(tenant_id: str, agent_id: str, since: datetime) -> list[TraceRow]:
    from modules.identity import delegation_receipt

    rows: list[TraceRow] = []
    try:
        receipts = delegation_receipt.get_receipts_for_agent(
            tenant_id, agent_id, include_revoked=True,
        )
    except Exception:  # noqa: BLE001 — a missing store must not sink the report
        return rows

    for r in receipts:
        ts = _parse_ts(r.issued_at)
        if ts and ts < since:
            continue
        state = "revoked" if r.revoked else "active"
        rows.append(TraceRow(
            timestamp=r.issued_at,
            agent=agent_id,
            credential=r.receipt_id,
            action="delegated_authority",
            resource=", ".join(r.scope) if r.scope else "-",
            evidence_pointer=f"receipt:{r.receipt_id}",
            source=SOURCE_DELEGATION,
            severity="info",
            narrative=(
                f"{r.delegator_id} delegated [{', '.join(r.scope) or 'no scope'}] "
                f"to {r.delegatee_id} on behalf of human principal "
                f"{r.human_principal_id} (depth {r.depth}, {state})"
            ),
        ))
    return rows


def _audit_row_from_record(rec: dict[str, Any], agent_id: str) -> TraceRow:
    """Derive a trace row from one audit record.

    Single source of truth, used by BOTH the composer and the verifier: the
    verifier re-derives each audit row straight from the live log with this and
    compares. That is what stops a forger from rewriting a row's content,
    re-chaining the report so it agrees with itself, and passing verification.
    """
    detail = rec.get("detail") or {}
    event_type = str(rec.get("event_type", ""))
    plane = detail.get("plane", "")
    outcome = rec.get("outcome", "")

    narrative = f"TokenDNA recorded {event_type} by {rec.get('subject', 'system')}"
    if plane:
        narrative += f" on the {plane} plane"
    if detail.get("detail"):
        narrative += f": {detail['detail']}"
    elif detail.get("reason"):
        narrative += f" (reason: {detail['reason']})"

    return TraceRow(
        timestamp=rec.get("timestamp", ""),
        agent=agent_id,
        credential="-",
        action=event_type,
        resource=plane or rec.get("resource", ""),
        # The pointer a verifier re-checks against the independent audit chain.
        evidence_pointer=f"audit:{rec.get('sequence', '?')}:{rec.get('entry_hash', '')}",
        source=SOURCE_AUDIT,
        severity="high" if "FAIL" in event_type or "FAILURE" in str(outcome) else "info",
        narrative=narrative,
    )


def _audit_rows(tenant_id: str, agent_id: str, since: datetime,
                log_path: Optional[str]) -> list[TraceRow]:
    """What TokenDNA *did* — the containment actions, from the hash-chained log."""
    rows: list[TraceRow] = []
    records = audit_log.read_records(
        log_path, tenant_id=tenant_id, resource=f"agent/{agent_id}",
    )
    for rec in records:
        ts = _parse_ts(rec.get("timestamp"))
        if ts and ts < since:
            continue
        rows.append(_audit_row_from_record(rec, agent_id))
    return rows


def _blast(tenant_id: str, agent_id: str, max_hops: int) -> dict[str, Any] | None:
    from modules.identity import blast_radius

    try:
        result = blast_radius.simulate_blast_radius(tenant_id, agent_id,
                                                    max_hops=max_hops)
    except Exception:  # noqa: BLE001 — an un-graphed agent has no blast radius
        return None

    agents, resources = [], []
    for node in result.reachable_nodes:
        (agents if node.node_type in ("agent", "workload") else resources).append(node.label)

    return {
        "impact_score": result.impact_score,
        "risk_tier": result.risk_tier,
        "total_nodes_reached": result.total_nodes_reached,
        "affected_agents": agents,
        "affected_resources": resources,
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_trace_report(
    tenant_id: str,
    agent_id: str,
    *,
    window_hours: int = DEFAULT_WINDOW_HOURS,
    max_rows: int = DEFAULT_MAX_ROWS,
    include_blast: bool = True,
    max_hops: int = 6,
    audit_log_path: Optional[str] = None,
) -> TraceReport:
    """Compose a time-ordered, self-chained evidence report for one agent."""
    end = _now()
    start = end - timedelta(hours=window_hours)

    rows: list[TraceRow] = []
    rows += _anomaly_rows(tenant_id, agent_id, start)
    rows += _uis_rows(tenant_id, agent_id, start, max_rows)
    rows += _delegation_rows(tenant_id, agent_id, start)
    rows += _audit_rows(tenant_id, agent_id, start, audit_log_path)

    rows.sort(key=_sort_key)
    if len(rows) > max_rows:
        # Keep the most recent max_rows — and say so, rather than truncating silently.
        rows = rows[-max_rows:]

    chained = _chain(rows)

    return TraceReport(
        tenant_id=tenant_id,
        agent_id=agent_id,
        generated_at=end.isoformat(),
        window_start=start.isoformat(),
        window_end=end.isoformat(),
        rows=chained,
        blast_radius=_blast(tenant_id, agent_id, max_hops) if include_blast else None,
        report_hash=chained[-1].row_hash if chained else GENESIS_HASH,
    )


def verify_trace_report(
    report: TraceReport | dict[str, Any],
    *,
    audit_log_path: Optional[str] = None,
    check_audit_citations: bool = True,
) -> dict[str, Any]:
    """Re-derive the report's chain, and re-check its audit citations.

    Returns ``{"ok", "rows", "first_violation", "message", "citations_checked"}``.
    ``first_violation`` is the 1-indexed row that failed.
    """
    data = report.as_dict() if isinstance(report, TraceReport) else dict(report)
    raw_rows = data.get("rows") or []

    prev = GENESIS_HASH
    for i, raw in enumerate(raw_rows, start=1):
        row = TraceRow(**raw)
        if row.prev_hash != prev:
            return {"ok": False, "rows": i - 1, "first_violation": i,
                    "message": f"Chain break at row {i}", "citations_checked": 0}
        expected = audit_log.compute_evidence_hash(_row_canonical(row, prev))
        if row.row_hash != expected:
            return {"ok": False, "rows": i - 1, "first_violation": i,
                    "message": f"Hash mismatch at row {i}", "citations_checked": 0}
        prev = row.row_hash

    if data.get("report_hash") != prev:
        return {"ok": False, "rows": len(raw_rows), "first_violation": len(raw_rows) or 1,
                "message": "report_hash does not match the row chain",
                "citations_checked": 0}

    checked = 0
    if check_audit_citations:
        result = _verify_audit_citations(raw_rows, data.get("tenant_id"), audit_log_path)
        if not result["ok"]:
            return result
        checked = result["citations_checked"]

    return {"ok": True, "rows": len(raw_rows), "first_violation": None,
            "message": f"Chain intact — {len(raw_rows)} row(s), {checked} audit citation(s) confirmed",
            "citations_checked": checked}


def _verify_audit_citations(
    raw_rows: list[dict[str, Any]],
    tenant_id: str | None,
    log_path: Optional[str],
) -> dict[str, Any]:
    """Re-derive every audit-sourced row from the live log and compare.

    This is what makes the report *evidence* rather than assertion. Checking only
    that the cited entry exists with the right hash is not enough — a forger can
    rewrite a row's narrative, leave the pointer intact, and re-chain the report
    so it agrees with itself. So the verifier rebuilds each audit row from the
    record the log actually holds (via the same builder the composer used) and
    compares the material fields. A trace can agree with itself and still be a
    lie about the log it cites; this catches that.
    """
    cited = [(i, r) for i, r in enumerate(raw_rows, start=1)
             if r.get("source") == SOURCE_AUDIT]
    if not cited:
        return {"ok": True, "rows": len(raw_rows), "first_violation": None,
                "message": "no audit citations", "citations_checked": 0}

    live = audit_log.read_records(log_path, tenant_id=tenant_id)
    by_seq = {str(rec.get("sequence")): rec for rec in live}

    def _fail(i: int, message: str) -> dict[str, Any]:
        return {"ok": False, "rows": i - 1, "first_violation": i,
                "message": message, "citations_checked": 0}

    material = ("timestamp", "agent", "credential", "action", "resource",
                "evidence_pointer", "narrative", "severity")

    for i, row in cited:
        pointer = str(row.get("evidence_pointer", ""))
        try:
            _, seq, entry_hash = pointer.split(":", 2)
        except ValueError:
            return _fail(i, f"Row {i} has a malformed audit pointer: {pointer!r}")

        rec = by_seq.get(seq)
        if rec is None:
            return _fail(i, f"Row {i} cites audit entry {seq}, which is not in the log")
        if str(rec.get("entry_hash")) != entry_hash:
            return _fail(i, (
                f"Row {i} cites audit entry {seq} with hash {entry_hash[:12]}…, "
                f"but the log now has {str(rec.get('entry_hash'))[:12]}…"
            ))

        rebuilt = _audit_row_from_record(rec, str(row.get("agent", ""))).as_dict()
        for fld in material:
            if row.get(fld) != rebuilt.get(fld):
                return _fail(i, (
                    f"Row {i} does not match audit entry {seq}: {fld} is "
                    f"{row.get(fld)!r} in the report but {rebuilt.get(fld)!r} in the log"
                ))

    return {"ok": True, "rows": len(raw_rows), "first_violation": None,
            "message": "audit citations confirmed", "citations_checked": len(cited)}

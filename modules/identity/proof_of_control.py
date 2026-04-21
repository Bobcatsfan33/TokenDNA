"""
TokenDNA — ZTIX Continuous Proof-of-Control (Expansion #2)

Closes the credential-persistence attack vector: a verifier whose private key
has been lost, rotated, or stolen can still pass static certificate checks
indefinitely. Continuous Proof-of-Control requires every verifier to
cryptographically prove they still hold their key within a configurable
interval — or get automatically demoted from quorum participation.

Background (original roadmap note)
───────────────────────────────────
"Substantially covered by PR #18's federation lifecycle hardening.
 Remaining short-interval proof renewal is ~1 week. Slot as a side sprint
 in Phase 3 (between 3-2 and 3-3)."

The `verifier_reputation` module already provides challenge-response mechanics
(issue_challenge / resolve_challenge / expire_pending_challenges). This module
adds the *interval enforcement layer* on top:

  1. Proof Interval Registry
     Each verifier has a configurable proof interval (default 24 h, min 1 h).
     Operators can tighten to 4 h for high-security environments.

  2. Proof Recording
     When a verifier successfully resolves a challenge (CORRECT outcome via
     verifier_reputation), the API layer calls record_proof() here. This
     advances `next_proof_due` by the configured interval.

  3. Sweep + Auto-Demotion
     sweep_expired_proofs() finds verifiers past their proof due date and:
       - Updates their proof status to OVERDUE / EXPIRED
       - Demotes them in trust_federation_verifiers (status → 'unverified')
       - Returns a list of demoted verifier IDs for alerting

  4. Re-activation
     Once a demoted verifier proves control again (record_proof() called),
     sweep will promote them back to 'active' on the next successful proof.

Integration points (API layer wires these; no cross-module import needed):
  - After verifier_reputation.resolve_challenge() → CORRECT → call record_proof()
  - Periodic sweep: POST /api/federation/verifiers/proof-sweep
  - Status check: GET /api/federation/verifiers/{id}/proof-status

API
───
GET  /api/federation/verifiers/{verifier_id}/proof-status    — current status
POST /api/federation/verifiers/{verifier_id}/proof-interval  — configure interval
POST /api/federation/verifiers/proof-sweep                   — sweep + demote
POST /api/federation/verifiers/proof-renew-all               — batch challenge
GET  /api/federation/verifiers/proof-registry                — all intervals + status
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_INTERVAL_HOURS: int = int(os.getenv("POC_DEFAULT_INTERVAL_HOURS", "24"))
_MIN_INTERVAL_HOURS: int = 1
_MAX_INTERVAL_HOURS: int = 168  # 1 week

_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utc_now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _add_hours(hours: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------


class ProofStatus(str, Enum):
    CURRENT = "current"       # proved control within the interval
    OVERDUE = "overdue"       # past due date, grace period (< 2x interval)
    EXPIRED = "expired"       # > 2x interval since last proof — demoted
    NEVER_PROVED = "never_proved"  # registered but never completed a proof


@dataclass
class ProofRecord:
    verifier_id: str
    tenant_id: str
    interval_hours: int
    last_proof_at: str | None
    next_proof_due: str | None
    status: ProofStatus
    consecutive_misses: int
    created_at: str
    updated_at: str


@dataclass
class SweepResult:
    tenant_id: str
    swept_at: str
    total_checked: int
    newly_overdue: int
    newly_expired: int
    demoted_in_federation: int
    demoted_ids: list[str]
    promoted_ids: list[str]
    challenges_issued: int


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _cursor():
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS verifier_proof_intervals (
                verifier_id         TEXT NOT NULL,
                tenant_id           TEXT NOT NULL,
                interval_hours      INTEGER NOT NULL DEFAULT 24,
                last_proof_at       TEXT,
                next_proof_due      TEXT,
                status              TEXT NOT NULL DEFAULT 'never_proved',
                consecutive_misses  INTEGER NOT NULL DEFAULT 0,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL,
                PRIMARY KEY (verifier_id, tenant_id)
            )
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_verifier_proof_due
            ON verifier_proof_intervals(tenant_id, next_proof_due, status)
        """)


def _row_to_record(row: sqlite3.Row) -> ProofRecord:
    return ProofRecord(
        verifier_id=row["verifier_id"],
        tenant_id=row["tenant_id"],
        interval_hours=row["interval_hours"],
        last_proof_at=row["last_proof_at"],
        next_proof_due=row["next_proof_due"],
        status=ProofStatus(row["status"]),
        consecutive_misses=row["consecutive_misses"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------


def register_verifier(
    verifier_id: str,
    tenant_id: str,
    interval_hours: int = _DEFAULT_INTERVAL_HOURS,
) -> ProofRecord:
    """
    Register a verifier in the proof-of-control registry with a given interval.
    Idempotent — calling again updates the interval without resetting proof state.
    """
    init_db()
    interval_hours = max(_MIN_INTERVAL_HOURS, min(_MAX_INTERVAL_HOURS, interval_hours))
    now = _utc_now()

    with _cursor() as cur:
        cur.execute("""
            INSERT INTO verifier_proof_intervals
                (verifier_id, tenant_id, interval_hours, status, consecutive_misses,
                 created_at, updated_at)
            VALUES (?, ?, ?, 'never_proved', 0, ?, ?)
            ON CONFLICT(verifier_id, tenant_id) DO UPDATE SET
                interval_hours = excluded.interval_hours,
                updated_at = excluded.updated_at
        """, (verifier_id, tenant_id, interval_hours, now, now))

    return get_proof_status(verifier_id, tenant_id)  # type: ignore[return-value]


def set_proof_interval(
    verifier_id: str,
    tenant_id: str,
    interval_hours: int,
) -> ProofRecord:
    """Update the proof interval for a registered verifier."""
    init_db()
    interval_hours = max(_MIN_INTERVAL_HOURS, min(_MAX_INTERVAL_HOURS, interval_hours))
    now = _utc_now()
    with _cursor() as cur:
        cur.execute("""
            INSERT INTO verifier_proof_intervals
                (verifier_id, tenant_id, interval_hours, status, consecutive_misses,
                 created_at, updated_at)
            VALUES (?, ?, ?, 'never_proved', 0, ?, ?)
            ON CONFLICT(verifier_id, tenant_id) DO UPDATE SET
                interval_hours = excluded.interval_hours,
                updated_at = excluded.updated_at
        """, (verifier_id, tenant_id, interval_hours, now, now))
    return get_proof_status(verifier_id, tenant_id)  # type: ignore[return-value]


def record_proof(verifier_id: str, tenant_id: str) -> ProofRecord:
    """
    Record a successful proof-of-control for a verifier.

    Call this from the API layer immediately after
    verifier_reputation.resolve_challenge() returns CORRECT outcome.

    Advances next_proof_due by the configured interval and resets
    consecutive_misses to 0. If verifier was OVERDUE or EXPIRED, promotes
    them back to CURRENT and re-activates in trust_federation.
    """
    init_db()
    now_dt = _utc_now_dt()
    now = now_dt.isoformat()

    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM verifier_proof_intervals WHERE verifier_id=? AND tenant_id=?",
            (verifier_id, tenant_id),
        )
        row = cur.fetchone()

    if row is None:
        # Auto-register with default interval on first proof
        register_verifier(verifier_id, tenant_id)
        with _cursor() as cur:
            cur.execute(
                "SELECT * FROM verifier_proof_intervals WHERE verifier_id=? AND tenant_id=?",
                (verifier_id, tenant_id),
            )
            row = cur.fetchone()

    prev_status = ProofStatus(row["status"])
    interval_hours = row["interval_hours"]
    next_due = (now_dt + timedelta(hours=interval_hours)).isoformat()

    with _cursor() as cur:
        cur.execute("""
            UPDATE verifier_proof_intervals
            SET last_proof_at=?, next_proof_due=?, status='current',
                consecutive_misses=0, updated_at=?
            WHERE verifier_id=? AND tenant_id=?
        """, (now, next_due, now, verifier_id, tenant_id))

    # If previously demoted, re-activate in trust_federation
    if prev_status in (ProofStatus.EXPIRED, ProofStatus.OVERDUE, ProofStatus.NEVER_PROVED):
        _promote_in_federation(verifier_id, tenant_id)

    result = get_proof_status(verifier_id, tenant_id)
    return result  # type: ignore[return-value]


def get_proof_status(verifier_id: str, tenant_id: str) -> ProofRecord | None:
    """Return the current proof-of-control status for a verifier."""
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM verifier_proof_intervals WHERE verifier_id=? AND tenant_id=?",
            (verifier_id, tenant_id),
        )
        row = cur.fetchone()
    if row is None:
        return None
    record = _row_to_record(row)
    # Dynamically compute live status in case last sweep was a while ago
    record.status = _compute_live_status(record)
    return record


def list_proof_registry(
    tenant_id: str,
    status: str | None = None,
    limit: int = 100,
) -> list[ProofRecord]:
    """List all registered verifiers and their proof status for a tenant."""
    init_db()
    if status:
        with _cursor() as cur:
            cur.execute(
                "SELECT * FROM verifier_proof_intervals WHERE tenant_id=? AND status=? "
                "ORDER BY next_proof_due ASC LIMIT ?",
                (tenant_id, status, min(limit, 500)),
            )
            rows = cur.fetchall()
    else:
        with _cursor() as cur:
            cur.execute(
                "SELECT * FROM verifier_proof_intervals WHERE tenant_id=? "
                "ORDER BY next_proof_due ASC LIMIT ?",
                (tenant_id, min(limit, 500)),
            )
            rows = cur.fetchall()
    records = [_row_to_record(r) for r in rows]
    # Apply live status computation
    for r in records:
        r.status = _compute_live_status(r)
    return records


def _compute_live_status(record: ProofRecord) -> ProofStatus:
    """Compute the live proof status without a DB write."""
    if record.next_proof_due is None:
        return ProofStatus.NEVER_PROVED

    now_dt = _utc_now_dt()
    try:
        due_dt = datetime.fromisoformat(record.next_proof_due)
        if due_dt.tzinfo is None:
            due_dt = due_dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return ProofStatus.NEVER_PROVED

    if now_dt <= due_dt:
        return ProofStatus.CURRENT

    overdue_secs = (now_dt - due_dt).total_seconds()
    grace_seconds = record.interval_hours * 3600  # 1x interval grace period
    if overdue_secs <= grace_seconds:
        return ProofStatus.OVERDUE
    return ProofStatus.EXPIRED


# ---------------------------------------------------------------------------
# Sweep + auto-demotion
# ---------------------------------------------------------------------------


def _list_proof_registry_raw(tenant_id: str, limit: int = 500) -> list[ProofRecord]:
    """Return records with DB status (no live override). Used internally by sweep."""
    init_db()
    with _cursor() as cur:
        cur.execute(
            "SELECT * FROM verifier_proof_intervals WHERE tenant_id=? "
            "ORDER BY next_proof_due ASC LIMIT ?",
            (tenant_id, limit),
        )
        rows = cur.fetchall()
    return [_row_to_record(r) for r in rows]


def sweep_expired_proofs(
    tenant_id: str,
    auto_issue_challenges: bool = True,
) -> SweepResult:
    """
    Sweep all registered verifiers for this tenant.

    For each verifier past their proof interval:
    - OVERDUE: consecutive_misses incremented, logged
    - EXPIRED (> 2x interval): demoted in trust_federation (status → 'unverified')

    Also promotes verifiers back to 'active' in trust_federation if they have
    recovered to CURRENT status since the last sweep.

    If auto_issue_challenges=True, issues a new challenge via verifier_reputation
    to each OVERDUE verifier (not EXPIRED — those must manually re-prove).

    Returns a SweepResult with counts and IDs for alerting.
    """
    init_db()
    now = _utc_now()
    # Use raw records (DB status) so sweep logic can detect transitions correctly
    records = _list_proof_registry_raw(tenant_id, limit=500)

    newly_overdue: list[str] = []
    newly_expired: list[str] = []
    promoted: list[str] = []
    challenges_issued = 0

    for r in records:
        live_status = _compute_live_status(r)

        if live_status == ProofStatus.CURRENT and r.status in (
            ProofStatus.OVERDUE, ProofStatus.EXPIRED
        ):
            # Was demoted, now current — promote
            _promote_in_federation(r.verifier_id, tenant_id)
            with _cursor() as cur:
                cur.execute("""
                    UPDATE verifier_proof_intervals
                    SET status='current', consecutive_misses=0, updated_at=?
                    WHERE verifier_id=? AND tenant_id=?
                """, (now, r.verifier_id, tenant_id))
            promoted.append(r.verifier_id)

        elif live_status == ProofStatus.OVERDUE:
            new_misses = r.consecutive_misses + 1
            with _cursor() as cur:
                cur.execute("""
                    UPDATE verifier_proof_intervals
                    SET status='overdue', consecutive_misses=?, updated_at=?
                    WHERE verifier_id=? AND tenant_id=? AND status != 'overdue'
                """, (new_misses, now, r.verifier_id, tenant_id))
            if r.status != ProofStatus.OVERDUE:
                newly_overdue.append(r.verifier_id)
            # Issue a challenge to nudge the verifier
            if auto_issue_challenges:
                try:
                    from modules.identity import verifier_reputation  # noqa: PLC0415
                    verifier_reputation.issue_challenge(
                        verifier_id=r.verifier_id,
                        tenant_id=tenant_id,
                    )
                    challenges_issued += 1
                except Exception as exc:
                    logger.warning(
                        "Could not issue proof challenge to %s: %s", r.verifier_id, exc
                    )

        elif live_status == ProofStatus.EXPIRED:
            with _cursor() as cur:
                cur.execute("""
                    UPDATE verifier_proof_intervals
                    SET status='expired', consecutive_misses=consecutive_misses+1,
                        updated_at=?
                    WHERE verifier_id=? AND tenant_id=?
                """, (now, r.verifier_id, tenant_id))
            if r.status != ProofStatus.EXPIRED:
                newly_expired.append(r.verifier_id)
                _demote_in_federation(r.verifier_id, tenant_id)

        elif live_status == ProofStatus.NEVER_PROVED and auto_issue_challenges:
            # New verifier — issue first challenge
            try:
                from modules.identity import verifier_reputation  # noqa: PLC0415
                verifier_reputation.issue_challenge(
                    verifier_id=r.verifier_id,
                    tenant_id=tenant_id,
                )
                challenges_issued += 1
            except Exception as exc:
                logger.warning(
                    "Could not issue initial challenge to %s: %s", r.verifier_id, exc
                )

    demoted_ids = newly_expired
    return SweepResult(
        tenant_id=tenant_id,
        swept_at=now,
        total_checked=len(records),
        newly_overdue=len(newly_overdue),
        newly_expired=len(newly_expired),
        demoted_in_federation=len(newly_expired),
        demoted_ids=demoted_ids,
        promoted_ids=promoted,
        challenges_issued=challenges_issued,
    )


def renew_all_overdue(tenant_id: str) -> dict[str, Any]:
    """
    Issue fresh challenges to all OVERDUE and NEVER_PROVED verifiers.
    Does not demote — that's sweep's job. This is the explicit "please prove
    now" batch operation.
    """
    init_db()
    records = _list_proof_registry_raw(tenant_id, limit=500)
    challenged: list[str] = []
    errors: list[str] = []

    for r in records:
        live_status = _compute_live_status(r)
        # NEVER_PROVED: no next_proof_due set yet → needs first challenge
        # OVERDUE: past interval but within grace → nudge with a challenge
        # EXPIRED verifiers must manually re-prove via the sweep + API flow
        if live_status in (ProofStatus.OVERDUE, ProofStatus.NEVER_PROVED):
            try:
                from modules.identity import verifier_reputation  # noqa: PLC0415
                verifier_reputation.issue_challenge(
                    verifier_id=r.verifier_id,
                    tenant_id=tenant_id,
                )
                challenged.append(r.verifier_id)
            except Exception as exc:
                logger.warning("renew_all_overdue error for %s: %s", r.verifier_id, exc)
                errors.append(r.verifier_id)

    return {
        "tenant_id": tenant_id,
        "challenged_count": len(challenged),
        "challenged_ids": challenged,
        "error_count": len(errors),
        "error_ids": errors,
    }


def proof_stats(tenant_id: str) -> dict[str, Any]:
    """Summary statistics for proof-of-control status across the tenant."""
    init_db()
    records = list_proof_registry(tenant_id, limit=1000)
    by_status: dict[str, int] = {s.value: 0 for s in ProofStatus}
    total_misses = 0
    for r in records:
        live = _compute_live_status(r)
        by_status[live.value] = by_status.get(live.value, 0) + 1
        total_misses += r.consecutive_misses
    return {
        "tenant_id": tenant_id,
        "total": len(records),
        "by_status": by_status,
        "total_consecutive_misses": total_misses,
        "overdue_count": by_status.get("overdue", 0),
        "expired_count": by_status.get("expired", 0),
    }


# ---------------------------------------------------------------------------
# trust_federation integration helpers
# ---------------------------------------------------------------------------


def _demote_in_federation(verifier_id: str, tenant_id: str) -> None:
    """
    Demote a verifier in trust_federation_verifiers to 'unverified' status.
    Only demotes active verifiers — does not touch already-revoked verifiers.
    """
    try:
        now = _utc_now()
        with _cursor() as cur:
            cur.execute("""
                UPDATE trust_federation_verifiers
                SET status='unverified', updated_at=?
                WHERE verifier_id=? AND tenant_id=? AND status='active'
            """, (now, verifier_id, tenant_id))
        logger.info(
            "proof_of_control: demoted verifier %s (tenant=%s) to unverified",
            verifier_id, tenant_id,
        )
    except Exception as exc:
        logger.warning("Could not demote verifier %s in federation: %s", verifier_id, exc)


def _promote_in_federation(verifier_id: str, tenant_id: str) -> None:
    """
    Promote a verifier back to 'active' in trust_federation_verifiers
    after successful proof-of-control.
    """
    try:
        now = _utc_now()
        with _cursor() as cur:
            cur.execute("""
                UPDATE trust_federation_verifiers
                SET status='active', updated_at=?
                WHERE verifier_id=? AND tenant_id=? AND status='unverified'
            """, (now, verifier_id, tenant_id))
        logger.info(
            "proof_of_control: promoted verifier %s (tenant=%s) back to active",
            verifier_id, tenant_id,
        )
    except Exception as exc:
        logger.warning("Could not promote verifier %s in federation: %s", verifier_id, exc)

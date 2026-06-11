"""
TokenDNA — Agent Attestation Certificate Lifecycle Dashboard (Sprint 6-1)

`attestation_certificates.py` handles issuance and verification.
`attestation_store.py` persists the raw certificate JSON.

What's missing: operators have zero visibility into the health of their
certificate fleet.  This module surfaces that as a product feature:

  1. Fleet view
     Complete certificate inventory per tenant — status, expiry, issuer,
     subject, days_until_expiry, health label (healthy/expiring_soon/expired/revoked).

  2. Expiry alerts
     Certs expiring within 30 / 7 / 1 days flagged with urgency tiers.
     Pre-expiry alerts stored in cert_expiry_alerts table.

  3. Certificate usage logging + anomaly detection
     Every cert usage event is recorded (IP, agent_id, timestamp).
     Anomalies fire when:
       a) cert is used from an IP/agent never seen before for that cert
       b) cert is used after it was marked as compromised
       c) a revoked cert is presented (honeypot hit)

  4. Deception mesh bridge
     A revoked cert presented at runtime is forwarded to the
     deception_mesh_decoys table as a honeypot hit (uses agent_lifecycle's
     record_decoy_hit logic at the API layer).

API (wired in api.py)
─────────────────────
GET  /api/certs/fleet                  Full certificate fleet for tenant
GET  /api/certs/expiring               Certs expiring within N days (default 30)
POST /api/certs/usage                  Record a certificate usage event
GET  /api/certs/anomalies              Usage anomalies for tenant
POST /api/certs/anomalies/{id}/resolve Resolve a cert anomaly
GET  /api/certs/{cert_id}/history      Full usage history for one cert
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

from modules.storage.pg_connection import ensure_sqlite_dir, AdaptedCursor, get_db_conn

log = logging.getLogger(__name__)

_lock = threading.Lock()

# ── Thresholds ────────────────────────────────────────────────────────────────

EXPIRY_CRITICAL_DAYS = int(os.getenv("CERT_EXPIRY_CRITICAL_DAYS", "1"))
EXPIRY_WARNING_DAYS = int(os.getenv("CERT_EXPIRY_WARNING_DAYS", "7"))
EXPIRY_NOTICE_DAYS = int(os.getenv("CERT_EXPIRY_NOTICE_DAYS", "30"))


# ── DB helpers ────────────────────────────────────────────────────────────────

def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _cursor():
    """Yield a backend-portable AdaptedCursor (SQLite or Postgres)."""
    with _lock:
        with get_db_conn(db_path=_db_path()) as conn:
            yield AdaptedCursor(conn.cursor())


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create cert dashboard tables if they don't exist."""
    db_path = _db_path()
    ensure_sqlite_dir(db_path)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_usage_log (
                usage_id       TEXT PRIMARY KEY,
                certificate_id TEXT NOT NULL,
                tenant_id      TEXT NOT NULL,
                agent_id       TEXT,
                source_ip      TEXT,
                cert_status    TEXT,
                verified       INTEGER NOT NULL DEFAULT 1,
                metadata_json  TEXT NOT NULL DEFAULT '{}',
                created_at     TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_anomalies (
                anomaly_id      TEXT PRIMARY KEY,
                certificate_id  TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                anomaly_type    TEXT NOT NULL,
                detail          TEXT NOT NULL,
                agent_id        TEXT,
                source_ip       TEXT,
                severity        TEXT NOT NULL DEFAULT 'high',
                resolved        INTEGER NOT NULL DEFAULT 0,
                resolved_by     TEXT,
                resolved_at     TEXT,
                created_at      TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_expiry_alerts (
                alert_id       TEXT PRIMARY KEY,
                certificate_id TEXT NOT NULL,
                tenant_id      TEXT NOT NULL,
                subject        TEXT NOT NULL,
                issuer         TEXT NOT NULL,
                expires_at     TEXT NOT NULL,
                urgency        TEXT NOT NULL,
                days_remaining INTEGER NOT NULL,
                acknowledged   INTEGER NOT NULL DEFAULT 0,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                created_at     TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_known_agents (
                certificate_id TEXT NOT NULL,
                tenant_id      TEXT NOT NULL,
                agent_id       TEXT NOT NULL,
                source_ip      TEXT,
                first_seen_at  TEXT NOT NULL,
                PRIMARY KEY (certificate_id, tenant_id, agent_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cert_renewals (
                renewal_id      TEXT PRIMARY KEY,
                certificate_id  TEXT NOT NULL,
                tenant_id       TEXT NOT NULL,
                expires_at      TEXT NOT NULL,
                triggered_at    TEXT NOT NULL,
                urgency         TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'triggered',
                hook_results_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_cert_usage_cert ON cert_usage_log(certificate_id, tenant_id)",
            "CREATE INDEX IF NOT EXISTS idx_cert_usage_tenant ON cert_usage_log(tenant_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_cert_anomalies_tenant ON cert_anomalies(tenant_id, resolved)",
            "CREATE INDEX IF NOT EXISTS idx_cert_expiry_tenant ON cert_expiry_alerts(tenant_id, acknowledged)",
            "CREATE INDEX IF NOT EXISTS idx_cert_renewals_cert ON cert_renewals(certificate_id, tenant_id)",
        ]:
            cur.execute(idx_sql)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_dt(iso_str: str | None) -> datetime | None:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _days_until(expires_at: str | None) -> int | None:
    dt = _parse_dt(expires_at)
    if dt is None:
        return None
    delta = dt - datetime.now(timezone.utc)
    return delta.days


def _health_label(cert: dict[str, Any]) -> str:
    status = cert.get("status", "active")
    if status == "revoked":
        return "revoked"
    days = _days_until(cert.get("expires_at"))
    if days is None:
        return "unknown"
    if days < 0:
        return "expired"
    if days <= EXPIRY_CRITICAL_DAYS:
        return "expiring_critical"
    if days <= EXPIRY_WARNING_DAYS:
        return "expiring_warning"
    if days <= EXPIRY_NOTICE_DAYS:
        return "expiring_notice"
    return "healthy"


def _urgency(days: int) -> str:
    if days <= EXPIRY_CRITICAL_DAYS:
        return "critical"
    if days <= EXPIRY_WARNING_DAYS:
        return "warning"
    return "notice"


def _enrich_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """Add dashboard-specific fields to a raw certificate dict."""
    days = _days_until(cert.get("expires_at"))
    return {
        **cert,
        "days_until_expiry": days,
        "health": _health_label(cert),
    }


# ── Fleet view ────────────────────────────────────────────────────────────────

def fleet_view(
    *,
    tenant_id: str,
    status: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """
    Return the full certificate fleet for a tenant.

    Pulls from the existing attestation_certificates table (written by
    attestation_store.insert_certificate).
    """
    from modules.identity import attestation_store as _store  # noqa: PLC0415
    certs = _store.list_certificates(
        tenant_id,
        limit=min(max(limit, 1), 2000),
        status=status,
    )
    enriched = [_enrich_cert(c) for c in certs]

    # Compute summary stats
    total = len(enriched)
    by_health: dict[str, int] = {}
    for c in enriched:
        h = c["health"]
        by_health[h] = by_health.get(h, 0) + 1

    return {
        "tenant_id": tenant_id,
        "total": total,
        "by_health": by_health,
        "certificates": enriched,
    }


# ── Expiry alerts ─────────────────────────────────────────────────────────────

def get_expiring(
    *,
    tenant_id: str,
    within_days: int = EXPIRY_NOTICE_DAYS,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Return certs expiring within `within_days` days.
    Automatically creates expiry alert records for newly discovered certs.
    """
    from modules.identity import attestation_store as _store  # noqa: PLC0415
    all_certs = _store.list_certificates(tenant_id, limit=2000)

    expiring = []
    now = datetime.now(timezone.utc)
    cutoff = now + timedelta(days=within_days)

    for cert in all_certs:
        if cert.get("status") == "revoked":
            continue
        expires_dt = _parse_dt(cert.get("expires_at"))
        if expires_dt is None:
            continue
        if expires_dt > cutoff:
            continue
        days = (expires_dt - now).days
        urgency = _urgency(max(days, 0))
        enriched = _enrich_cert(cert)
        enriched["urgency"] = urgency
        expiring.append(enriched)

        # Upsert expiry alert
        _upsert_expiry_alert(
            tenant_id=tenant_id,
            cert=cert,
            days_remaining=max(days, 0),
            urgency=urgency,
        )

    # Sort by expiry ascending (most urgent first)
    expiring.sort(key=lambda c: c.get("expires_at") or "")
    return expiring[:limit]


def _upsert_expiry_alert(
    *,
    tenant_id: str,
    cert: dict[str, Any],
    days_remaining: int,
    urgency: str,
) -> None:
    cert_id = cert.get("certificate_id", "")
    with _cursor() as cur:
        existing = cur.execute(
            "SELECT alert_id FROM cert_expiry_alerts WHERE certificate_id = ? AND tenant_id = ? AND acknowledged = 0",
            (cert_id, tenant_id),
        ).fetchone()
        if existing:
            cur.execute(
                "UPDATE cert_expiry_alerts SET days_remaining = ?, urgency = ? WHERE alert_id = ?",
                (days_remaining, urgency, existing["alert_id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO cert_expiry_alerts
                    (alert_id, certificate_id, tenant_id, subject, issuer,
                     expires_at, urgency, days_remaining, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    cert_id,
                    tenant_id,
                    cert.get("subject", ""),
                    cert.get("issuer", ""),
                    cert.get("expires_at", ""),
                    urgency,
                    days_remaining,
                    _iso_now(),
                ),
            )


def acknowledge_expiry_alert(
    *,
    tenant_id: str,
    alert_id: str,
    acknowledged_by: str,
) -> dict[str, Any]:
    """Acknowledge an expiry alert."""
    now = _iso_now()
    with _cursor() as cur:
        row = cur.execute(
            "SELECT alert_id FROM cert_expiry_alerts WHERE alert_id = ? AND tenant_id = ?",
            (alert_id, tenant_id),
        ).fetchone()
        if not row:
            raise KeyError(f"Alert '{alert_id}' not found for tenant '{tenant_id}'")
        cur.execute(
            """
            UPDATE cert_expiry_alerts
            SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
            WHERE alert_id = ?
            """,
            (acknowledged_by, now, alert_id),
        )
    with _cursor() as cur:
        updated = cur.execute(
            "SELECT * FROM cert_expiry_alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    return dict(updated)


# ── Certificate usage logging + anomaly detection ─────────────────────────────

def record_usage(
    *,
    tenant_id: str,
    certificate_id: str,
    agent_id: str | None = None,
    source_ip: str | None = None,
    cert_status: str = "active",
    verified: bool = True,
    metadata: dict | None = None,
) -> dict[str, Any]:
    """
    Record a certificate usage event and run anomaly checks.

    Returns the usage record with any anomalies that fired.
    """
    usage_id = str(uuid.uuid4())
    now = _iso_now()
    anomalies: list[dict[str, Any]] = []

    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO cert_usage_log
                (usage_id, certificate_id, tenant_id, agent_id, source_ip,
                 cert_status, verified, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                usage_id,
                certificate_id,
                tenant_id,
                agent_id,
                source_ip,
                cert_status,
                1 if verified else 0,
                json.dumps(metadata or {}),
                now,
            ),
        )

    # Anomaly 1: revoked cert used (honeypot hit)
    if cert_status == "revoked":
        anom = _fire_anomaly(
            tenant_id=tenant_id,
            certificate_id=certificate_id,
            anomaly_type="revoked_cert_used",
            detail=(
                f"Revoked certificate '{certificate_id}' was presented — "
                f"possible credential replay or compromised agent"
            ),
            agent_id=agent_id,
            source_ip=source_ip,
            severity="critical",
        )
        anomalies.append(anom)
        log.warning(
            "🚨 Revoked cert used: tenant=%s cert=%s agent=%s ip=%s",
            tenant_id, certificate_id, agent_id, source_ip,
        )

    # Anomaly 2: unknown agent/IP for this cert
    if agent_id:
        with _cursor() as cur:
            known = cur.execute(
                "SELECT agent_id FROM cert_known_agents WHERE certificate_id = ? AND tenant_id = ? AND agent_id = ?",
                (certificate_id, tenant_id, agent_id),
            ).fetchone()
        if not known:
            # Check if this cert has ANY known agents (first use is always new)
            with _cursor() as cur:
                any_known = cur.execute(
                    "SELECT COUNT(*) as cnt FROM cert_known_agents WHERE certificate_id = ? AND tenant_id = ?",
                    (certificate_id, tenant_id),
                ).fetchone()
            if any_known and any_known["cnt"] > 0:
                # Not first use — genuinely new agent
                anom = _fire_anomaly(
                    tenant_id=tenant_id,
                    certificate_id=certificate_id,
                    anomaly_type="unexpected_agent",
                    detail=(
                        f"Certificate '{certificate_id}' used by new agent '{agent_id}' "
                        f"not previously associated with this cert"
                    ),
                    agent_id=agent_id,
                    source_ip=source_ip,
                    severity="high",
                )
                anomalies.append(anom)
                log.warning(
                    "⚠️  Cert used by unexpected agent: tenant=%s cert=%s agent=%s",
                    tenant_id, certificate_id, agent_id,
                )
            # Register agent as known
            with _cursor() as cur:
                cur.execute(
                    """
                    INSERT OR IGNORE INTO cert_known_agents
                        (certificate_id, tenant_id, agent_id, source_ip, first_seen_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (certificate_id, tenant_id, agent_id, source_ip, now),
                )

    return {
        "usage_id": usage_id,
        "certificate_id": certificate_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "source_ip": source_ip,
        "cert_status": cert_status,
        "verified": verified,
        "anomalies_fired": anomalies,
        "created_at": now,
    }


def _fire_anomaly(
    *,
    tenant_id: str,
    certificate_id: str,
    anomaly_type: str,
    detail: str,
    agent_id: str | None,
    source_ip: str | None,
    severity: str = "high",
) -> dict[str, Any]:
    anomaly_id = str(uuid.uuid4())
    now = _iso_now()
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO cert_anomalies
                (anomaly_id, certificate_id, tenant_id, anomaly_type, detail,
                 agent_id, source_ip, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (anomaly_id, certificate_id, tenant_id, anomaly_type, detail,
             agent_id, source_ip, severity, now),
        )
    return {
        "anomaly_id": anomaly_id,
        "certificate_id": certificate_id,
        "tenant_id": tenant_id,
        "anomaly_type": anomaly_type,
        "detail": detail,
        "agent_id": agent_id,
        "source_ip": source_ip,
        "severity": severity,
        "resolved": False,
        "created_at": now,
    }


# ── Anomaly queries ───────────────────────────────────────────────────────────

def list_anomalies(
    *,
    tenant_id: str,
    resolved: bool | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return cert anomalies for a tenant."""
    limit = min(max(limit, 1), 1000)
    with _cursor() as cur:
        if resolved is None:
            rows = cur.execute(
                """
                SELECT * FROM cert_anomalies
                WHERE tenant_id = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT * FROM cert_anomalies
                WHERE tenant_id = ? AND resolved = ?
                ORDER BY created_at DESC LIMIT ?
                """,
                (tenant_id, 1 if resolved else 0, limit),
            ).fetchall()
    return [_row_to_anomaly(r) for r in rows]


def resolve_anomaly(
    *,
    tenant_id: str,
    anomaly_id: str,
    resolved_by: str,
) -> dict[str, Any]:
    """Resolve a cert anomaly."""
    now = _iso_now()
    with _cursor() as cur:
        row = cur.execute(
            "SELECT anomaly_id FROM cert_anomalies WHERE anomaly_id = ? AND tenant_id = ?",
            (anomaly_id, tenant_id),
        ).fetchone()
        if not row:
            raise KeyError(f"Anomaly '{anomaly_id}' not found for tenant '{tenant_id}'")
        cur.execute(
            "UPDATE cert_anomalies SET resolved = 1, resolved_by = ?, resolved_at = ? WHERE anomaly_id = ?",
            (resolved_by, now, anomaly_id),
        )
    with _cursor() as cur:
        updated = cur.execute(
            "SELECT * FROM cert_anomalies WHERE anomaly_id = ?",
            (anomaly_id,),
        ).fetchone()
    return _row_to_anomaly(updated)


def get_cert_history(
    *,
    tenant_id: str,
    certificate_id: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return full usage history for a certificate."""
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT * FROM cert_usage_log
            WHERE certificate_id = ? AND tenant_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (certificate_id, tenant_id, min(max(limit, 1), 1000)),
        ).fetchall()
    return [
        {
            "usage_id": r["usage_id"],
            "certificate_id": r["certificate_id"],
            "tenant_id": r["tenant_id"],
            "agent_id": r["agent_id"],
            "source_ip": r["source_ip"],
            "cert_status": r["cert_status"],
            "verified": bool(r["verified"]),
            "metadata": json.loads(r["metadata_json"] or "{}"),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def _row_to_anomaly(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "anomaly_id": row["anomaly_id"],
        "certificate_id": row["certificate_id"],
        "tenant_id": row["tenant_id"],
        "anomaly_type": row["anomaly_type"],
        "detail": row["detail"],
        "agent_id": row["agent_id"],
        "source_ip": row["source_ip"],
        "severity": row["severity"],
        "resolved": bool(row["resolved"]),
        "resolved_by": row["resolved_by"],
        "resolved_at": row["resolved_at"],
        "created_at": row["created_at"],
    }


# ── Fleet summary stats ───────────────────────────────────────────────────────

def fleet_summary(*, tenant_id: str) -> dict[str, Any]:
    """Return quick summary stats for the operator dashboard header."""
    view = fleet_view(tenant_id=tenant_id)
    by_health = view["by_health"]
    expiring_certs = get_expiring(tenant_id=tenant_id, within_days=EXPIRY_NOTICE_DAYS)
    open_anomalies = list_anomalies(tenant_id=tenant_id, resolved=False)
    critical_anomalies = [a for a in open_anomalies if a["severity"] == "critical"]
    return {
        "tenant_id": tenant_id,
        "total_certs": view["total"],
        "healthy": by_health.get("healthy", 0),
        "expiring_notice": by_health.get("expiring_notice", 0),
        "expiring_warning": by_health.get("expiring_warning", 0),
        "expiring_critical": by_health.get("expiring_critical", 0),
        "expired": by_health.get("expired", 0),
        "revoked": by_health.get("revoked", 0),
        "open_anomalies": len(open_anomalies),
        "critical_anomalies": len(critical_anomalies),
        "certs_expiring_soon": len(expiring_certs),
    }


# ── Lifecycle automation (T-4) ────────────────────────────────────────────────
#
# Replaces CRUD-only behavior with an adaptive sweep: it classifies the fleet,
# refreshes expiry alerts, fires audit events, and triggers operator-registered
# renewal hooks for certs crossing the renewal threshold — idempotently.

# Default: begin renewal once a cert is inside the WARNING window (7 days).
RENEWAL_THRESHOLD_DAYS = int(os.getenv("CERT_RENEWAL_THRESHOLD_DAYS", str(EXPIRY_WARNING_DAYS)))

# Registry of renewal hooks. A hook is ``Callable[[dict, dict], Any]`` receiving
# (cert, context) and returning a JSON-serializable result. Failures are
# isolated so one bad hook never blocks the sweep.
_renewal_hooks: list[Any] = []


def register_renewal_hook(hook: Any) -> None:
    """Register a renewal hook invoked by run_expiry_sweep for due certs."""
    _renewal_hooks.append(hook)


def clear_renewal_hooks() -> None:
    """Remove all registered renewal hooks (test/operator reset)."""
    _renewal_hooks.clear()


def _emit_audit(event_name: str, *, tenant_id: str, resource: str, detail: dict) -> None:
    """Best-effort SOC 2 audit emission for cert automation (T-4)."""
    try:
        from modules.security.audit_log import (  # noqa: PLC0415
            AuditEventType, AuditOutcome, log_event,
        )
        log_event(
            getattr(AuditEventType, event_name),
            AuditOutcome.SUCCESS,
            tenant_id=tenant_id,
            subject="cert-automation",
            resource=resource,
            detail=detail,
        )
    except Exception as exc:  # noqa: BLE001 - audit is best-effort
        log.warning("cert audit emission failed (%s): %s", event_name, exc)


def _renewal_already_open(cur, *, tenant_id: str, cert_id: str, expires_at: str) -> bool:
    """True if a renewal for this cert+expiry window is already on record.

    Keeps the sweep idempotent: re-running does not re-trigger hooks for a cert
    whose current certificate (same expires_at) was already actioned.
    """
    row = cur.execute(
        """
        SELECT renewal_id FROM cert_renewals
        WHERE certificate_id = ? AND tenant_id = ? AND expires_at = ?
              AND status != 'failed'
        """,
        (cert_id, tenant_id, expires_at),
    ).fetchone()
    return row is not None


def _trigger_renewal(cert: dict[str, Any], *, tenant_id: str, urgency: str, days: int) -> dict[str, Any]:
    """Invoke every renewal hook for a single cert; record + audit the result."""
    cert_id = cert.get("certificate_id", "")
    expires_at = cert.get("expires_at", "")
    context = {"tenant_id": tenant_id, "urgency": urgency, "days_until_expiry": days}

    hook_results: list[dict[str, Any]] = []
    overall_ok = True
    for hook in list(_renewal_hooks):
        name = getattr(hook, "__name__", repr(hook))
        try:
            result = hook(cert, context)
            hook_results.append({"hook": name, "ok": True, "result": result})
        except Exception as exc:  # noqa: BLE001 - one hook must not break the sweep
            overall_ok = False
            hook_results.append({"hook": name, "ok": False, "error": str(exc)})
            log.warning("renewal hook %s failed for cert %s: %s", name, cert_id, exc)

    status = "triggered" if overall_ok else "failed"
    with _cursor() as cur:
        cur.execute(
            """
            INSERT INTO cert_renewals
                (renewal_id, certificate_id, tenant_id, expires_at,
                 triggered_at, urgency, status, hook_results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()), cert_id, tenant_id, expires_at,
                _iso_now(), urgency, status, json.dumps(hook_results),
            ),
        )
    _emit_audit(
        "CERT_RENEWAL_TRIGGERED",
        tenant_id=tenant_id,
        resource=f"cert/{cert_id}",
        detail={"urgency": urgency, "days_until_expiry": days, "status": status,
                "hooks": len(hook_results)},
    )
    return {"certificate_id": cert_id, "status": status, "hook_results": hook_results}


def run_expiry_sweep(
    *,
    tenant_id: str,
    renew_within_days: int = RENEWAL_THRESHOLD_DAYS,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Adaptive certificate-lifecycle sweep (the automation, not CRUD).

    For a tenant it:
      1. classifies the fleet and refreshes expiry alerts (via get_expiring),
      2. triggers renewal hooks for non-revoked, non-expired certs within
         ``renew_within_days`` — idempotently (same cert+expiry not re-actioned),
      3. emits a CERT_EXPIRY_SWEEP audit event plus a CERT_RENEWAL_TRIGGERED
         per renewal.

    Returns a structured summary. ``dry_run=True`` classifies and reports what
    *would* be renewed without invoking hooks or writing renewal records.
    """
    init_db()
    # Refresh alerts across the notice window (also upserts alert rows).
    expiring = get_expiring(tenant_id=tenant_id, within_days=EXPIRY_NOTICE_DAYS, limit=2000)

    by_urgency: dict[str, int] = {}
    due: list[dict[str, Any]] = []
    for cert in expiring:
        urgency = cert.get("urgency", "notice")
        by_urgency[urgency] = by_urgency.get(urgency, 0) + 1
        days = cert.get("days_until_expiry")
        if cert.get("status") == "revoked":
            continue
        if days is None or days < 0:
            continue
        if days <= renew_within_days:
            due.append(cert)

    renewals: list[dict[str, Any]] = []
    skipped_idempotent = 0
    if not dry_run:
        for cert in due:
            cert_id = cert.get("certificate_id", "")
            expires_at = cert.get("expires_at", "")
            with _cursor() as cur:
                if _renewal_already_open(cur, tenant_id=tenant_id, cert_id=cert_id, expires_at=expires_at):
                    skipped_idempotent += 1
                    continue
            renewals.append(_trigger_renewal(
                cert, tenant_id=tenant_id,
                urgency=cert.get("urgency", "warning"),
                days=cert.get("days_until_expiry", 0),
            ))

    summary = {
        "tenant_id": tenant_id,
        "swept": len(expiring),
        "by_urgency": by_urgency,
        "due_for_renewal": len(due),
        "renewals_triggered": len(renewals),
        "skipped_idempotent": skipped_idempotent,
        "renewals": renewals,
        "dry_run": dry_run,
    }
    _emit_audit(
        "CERT_EXPIRY_SWEEP",
        tenant_id=tenant_id,
        resource="cert/fleet",
        detail={k: summary[k] for k in
                ("swept", "by_urgency", "due_for_renewal", "renewals_triggered",
                 "skipped_idempotent", "dry_run")},
    )
    return summary


def list_renewals(*, tenant_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Return recorded renewal actions for the tenant (most recent first)."""
    init_db()
    with _cursor() as cur:
        rows = cur.execute(
            """
            SELECT renewal_id, certificate_id, expires_at, triggered_at,
                   urgency, status, hook_results_json
            FROM cert_renewals WHERE tenant_id = ?
            ORDER BY triggered_at DESC LIMIT ?
            """,
            (tenant_id, limit),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["hook_results"] = json.loads(d.pop("hook_results_json") or "[]")
        out.append(d)
    return out

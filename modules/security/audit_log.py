"""
Aegis Security Platform — Immutable Audit Log
==============================================
FedRAMP High / IL6 compliance: NIST 800-53 Rev5 AU-2, AU-3, AU-9, AU-12

Every security-relevant event is written to an append-only, hash-chained log.
Each entry contains the SHA-256 hash of the previous entry, creating a
tamper-evident chain. Any modification to a past entry invalidates all
subsequent hashes — detectable during integrity verification.

AU-3 Required fields (all present):
  timestamp, event_type, subject (user/system), outcome,
  source_ip, resource, tenant_id, correlation_id

Storage backends (configure via AUDIT_BACKEND env var):
  - file     : append-only local file (dev / single-node)
  - redis    : Redis RPUSH to a write-only list (fast, in-memory)
  - siem     : forward to SIEM webhook (production recommended)
  - all      : write to all three simultaneously (maximum assurance)

IL6 note: For classified environments, pair with a WORM storage backend
(AWS S3 Object Lock, Azure Immutable Blob, or DISA ESS) and enable
CloudTrail / Azure Monitor forwarding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger("aegis.audit")

# ── Configuration ─────────────────────────────────────────────────────────────
AUDIT_BACKEND: str  = os.getenv("AUDIT_BACKEND", "file")
AUDIT_FILE:    str  = os.getenv("AUDIT_LOG_PATH", "/var/log/aegis/audit.jsonl")
AUDIT_HMAC_KEY: str = os.getenv("AUDIT_HMAC_KEY", "")  # REQUIRED in production
AUDIT_WEBHOOK:  str = os.getenv("SIEM_WEBHOOK_URL", "")

_lock = threading.Lock()
_chain_head: str = "0" * 64  # genesis hash


# ── Event types (AU-2 event taxonomy) ─────────────────────────────────────────
class AuditEventType(str, Enum):
    # Authentication & session
    AUTH_SUCCESS        = "auth.success"
    AUTH_FAILURE        = "auth.failure"
    AUTH_TOKEN_REVOKED  = "auth.token.revoked"
    AUTH_TOKEN_ISSUED   = "auth.token.issued"
    SESSION_CREATED     = "session.created"
    SESSION_TERMINATED  = "session.terminated"
    SESSION_TIMEOUT     = "session.timeout"

    # Access control
    ACCESS_GRANTED      = "access.granted"
    ACCESS_DENIED       = "access.denied"
    PRIVILEGE_ESCALATION= "access.privilege_escalation"

    # Threat detection (TokenDNA)
    THREAT_IMPOSSIBLE_TRAVEL = "threat.impossible_travel"
    THREAT_TOR_EXIT          = "threat.tor_exit"
    THREAT_SESSION_BRANCH    = "threat.session_branch"
    THREAT_DATACENTER_ASN    = "threat.datacenter_asn"
    THREAT_ABUSE_SCORE       = "threat.abuse_score_high"
    THREAT_STEP_UP           = "threat.step_up_required"
    THREAT_BLOCK             = "threat.block"
    THREAT_REVOKE            = "threat.revoke"

    # Cloud posture (Aegis)
    SCAN_STARTED        = "scan.started"
    SCAN_COMPLETED      = "scan.completed"
    FINDING_DETECTED    = "finding.detected"
    REMEDIATION_APPLIED = "remediation.applied"
    REMEDIATION_FAILED  = "remediation.failed"

    # Tenant management
    TENANT_CREATED      = "tenant.created"
    TENANT_DELETED      = "tenant.deleted"
    API_KEY_CREATED     = "apikey.created"
    API_KEY_REVOKED     = "apikey.revoked"

    # System
    CONFIG_CHANGED      = "system.config_changed"
    STARTUP             = "system.startup"
    SHUTDOWN            = "system.shutdown"
    INTEGRITY_VERIFIED  = "system.integrity_verified"
    INTEGRITY_VIOLATION = "system.integrity_violation"


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# ── Audit record ──────────────────────────────────────────────────────────────
@dataclass
class AuditRecord:
    """AU-3 compliant audit record."""
    event_type:     str
    outcome:        str
    tenant_id:      str         = "_global_"
    subject:        str         = "system"          # user_id, service name, or "system"
    source_ip:      str         = "0.0.0.0"
    resource:       str         = ""                # ARN, URL, or identifier
    detail:         dict        = field(default_factory=dict)
    correlation_id: str         = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:      str         = field(default_factory=lambda: _iso_now())
    sequence:       int         = 0                 # monotonic counter (set by logger)
    prev_hash:      str         = ""                # hash of previous entry — tamper-evident chain
    entry_hash:     str         = ""                # HMAC-SHA256 of this entry's canonical form


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(time.time() * 1000) % 1000:03d}Z"


def _canonical(record: AuditRecord) -> bytes:
    """Deterministic JSON bytes for hashing (excludes entry_hash itself)."""
    d = asdict(record)
    d.pop("entry_hash", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _compute_hash(canonical_bytes: bytes) -> str:
    """HMAC-SHA256 if key configured, plain SHA-256 otherwise."""
    if AUDIT_HMAC_KEY:
        return hmac.new(
            AUDIT_HMAC_KEY.encode(),
            canonical_bytes,
            hashlib.sha256,
        ).hexdigest()
    return hashlib.sha256(canonical_bytes).hexdigest()


# ── Core logger ───────────────────────────────────────────────────────────────
_sequence_counter = 0


def log_event(
    event_type:     AuditEventType | str,
    outcome:        AuditOutcome | str = AuditOutcome.SUCCESS,
    *,
    tenant_id:      str = "_global_",
    subject:        str = "system",
    source_ip:      str = "0.0.0.0",
    resource:       str = "",
    detail:         Optional[dict] = None,
    correlation_id: Optional[str] = None,
) -> AuditRecord:
    """
    Write a tamper-evident audit entry.  Thread-safe.

    Usage:
        from modules.security.audit_log import log_event, AuditEventType, AuditOutcome

        log_event(
            AuditEventType.AUTH_FAILURE,
            AuditOutcome.FAILURE,
            tenant_id=tid,
            subject=user_id,
            source_ip=request.client.host,
            resource="/secure",
            detail={"reason": "impossible_travel"},
        )
    """
    global _sequence_counter, _chain_head

    with _lock:
        _sequence_counter += 1

        record = AuditRecord(
            event_type=str(event_type),
            outcome=str(outcome),
            tenant_id=tenant_id,
            subject=subject,
            source_ip=source_ip,
            resource=resource,
            detail=detail or {},
            correlation_id=correlation_id or str(uuid.uuid4()),
            sequence=_sequence_counter,
            prev_hash=_chain_head,
        )

        canonical = _canonical(record)
        record.entry_hash = _compute_hash(canonical)
        _chain_head = record.entry_hash  # advance chain

    _dispatch(record)
    return record


def _dispatch(record: AuditRecord) -> None:
    """Write to configured backend(s). Never raises — audit failures are logged, not fatal."""
    backend = AUDIT_BACKEND.lower()
    try:
        if backend in ("file", "all"):
            _write_file(record)
        if backend in ("redis", "all"):
            _write_redis(record)
        if backend in ("siem", "all") and AUDIT_WEBHOOK:
            _write_siem(record)
    except Exception as e:  # noqa: BLE001
        logger.error("AUDIT DISPATCH FAILED — event may be lost: %s | %s", record.event_type, e)


def _write_file(record: AuditRecord) -> None:
    path = Path(AUDIT_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(record)) + "\n")
        f.flush()
        os.fsync(f.fileno())  # force kernel buffer flush — critical for integrity


def _write_redis(record: AuditRecord) -> None:
    """Append to a Redis list — use with ACL rules to make write-only from app."""
    try:
        from modules.identity.cache_redis import get_redis
        r = get_redis()
        key = f"audit:{record.tenant_id}:{time.strftime('%Y%m%d')}"
        r.rpush(key, json.dumps(asdict(record)))
        r.expire(key, 90 * 86400)  # 90-day retention per FedRAMP AU-11
    except Exception as e:  # noqa: BLE001
        logger.warning("Audit Redis write failed: %s", e)


def _write_siem(record: AuditRecord) -> None:
    """Forward to SIEM webhook with HMAC signature."""
    payload = json.dumps(asdict(record)).encode()
    sig = hmac.new(
        (AUDIT_HMAC_KEY or "unsigned").encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    try:
        requests.post(
            AUDIT_WEBHOOK,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Aegis-Signature": f"sha256={sig}",
                "X-Aegis-Event":     record.event_type,
            },
            timeout=3,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("Audit SIEM forward failed: %s", e)


# ── Integrity verification ────────────────────────────────────────────────────
def verify_log_integrity(log_path: Optional[str] = None) -> dict:
    """
    Walk the audit log and verify the hash chain.
    Returns {"ok": bool, "entries": int, "first_violation": int | None}

    Run this periodically (e.g. nightly cron) and alert on violations.
    """
    path = Path(log_path or AUDIT_FILE)
    if not path.exists():
        return {"ok": True, "entries": 0, "first_violation": None, "message": "No log file yet"}

    prev = "0" * 64
    count = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            record = AuditRecord(**data)
            if record.prev_hash != prev:
                return {"ok": False, "entries": count, "first_violation": count + 1,
                        "message": f"Chain break at entry {count + 1}"}
            canonical = _canonical(record)
            expected = _compute_hash(canonical)
            if record.entry_hash != expected:
                return {"ok": False, "entries": count, "first_violation": count + 1,
                        "message": f"Hash mismatch at entry {count + 1}"}
            prev = record.entry_hash
            count += 1
        except Exception as e:
            return {"ok": False, "entries": count, "first_violation": count + 1,
                    "message": f"Parse error at entry {count + 1}: {e}"}

    return {"ok": True, "entries": count, "first_violation": None,
            "message": f"Chain intact — {count} entries verified"}


# ── Startup event ─────────────────────────────────────────────────────────────
if not AUDIT_HMAC_KEY and os.getenv("ENVIRONMENT", "dev") not in ("dev", "test"):
    logger.warning(
        "AUDIT_HMAC_KEY not set — audit entries are SHA-256 only, not HMAC-signed. "
        "Set AUDIT_HMAC_KEY for FedRAMP-compliant tamper detection."
    )

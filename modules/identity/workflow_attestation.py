"""
TokenDNA — Workflow Attestation

Single-agent attestation answers "is this agent legit?". Workflow attestation
answers the harder question: **was the entire causal chain that led to this
action authorized end-to-end?**

A *workflow* is a directed acyclic chain of hops. Each hop binds:

    actor       — the agent_id taking the action
    action      — the operation (tool name, RPC, etc.)
    target      — the resource being acted on
    receipt_id  — optional delegation_receipt that authorized the hop

The workflow is canonicalized, hashed (Merkle-style), and HMAC-signed. The
``merkle_root`` becomes the workflow's stable identity — any deviation in
hops, ordering, or referenced delegation receipts produces a different root.

What this enables
-----------------
1. **Replay.** Given a workflow_id, ``replay_workflow`` reconstructs every
   hop and re-verifies the signature plus the delegation receipts referenced
   at each hop. Output: a hop-by-hop verification report with a single
   ``overall_valid`` boolean.

2. **Drift detection.** A *registered* workflow is the canonical shape.
   Subsequent runs are recorded via ``record_observation``; if the observed
   chain hashes differently from the canonical, the observation is flagged
   as drifted. The dashboard alerts on adversarial agents inserting
   themselves into known workflows.

Tables
------
``workflows``               canonical signed workflow definitions
``workflow_observations``   each observed run + drift score against canonical

Trust model
-----------
- The HMAC secret is shared server-side (env var, defaults to a dev value).
- Cross-tenant lookups are blocked.
- Replay re-verifies linked delegation receipts via
  ``delegation_receipt.verify_receipt`` — a revoked or expired receipt
  flips ``overall_valid`` to false even if the workflow signature itself
  is intact.
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modules.storage import db_backend

logger = logging.getLogger(__name__)
_lock = threading.Lock()


# ── Constants ─────────────────────────────────────────────────────────────────

VALID_HOP_FIELDS: frozenset[str] = frozenset({
    "actor", "action", "target", "receipt_id", "metadata",
})


def _secret() -> bytes:
    return os.getenv(
        "TOKENDNA_WORKFLOW_SECRET",
        "dev-workflow-secret-do-not-use-in-prod",
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
CREATE TABLE IF NOT EXISTS workflows (
    workflow_id     TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    hops_json       TEXT NOT NULL,
    merkle_root     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    created_by      TEXT,
    status          TEXT NOT NULL DEFAULT 'active',  -- active | retired
    UNIQUE(tenant_id, merkle_root)
);

CREATE INDEX IF NOT EXISTS idx_workflows_tenant
    ON workflows(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS workflow_observations (
    observation_id      TEXT PRIMARY KEY,
    workflow_id         TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    observed_at         TEXT NOT NULL,
    observed_root       TEXT NOT NULL,
    canonical_root      TEXT NOT NULL,
    drift               INTEGER NOT NULL DEFAULT 0,
    drift_details       TEXT NOT NULL DEFAULT '{}',
    observed_hops_json  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workflow_obs_drift
    ON workflow_observations(tenant_id, drift, observed_at DESC);
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
class Workflow:
    workflow_id: str
    tenant_id: str
    name: str
    description: str
    hops: list[dict[str, Any]]
    merkle_root: str
    signature: str
    created_at: str
    created_by: str | None
    status: str = "active"

    def as_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "hops": [dict(h) for h in self.hops],
            "merkle_root": self.merkle_root,
            "signature": self.signature,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "status": self.status,
        }


@dataclass(frozen=True)
class ReplayResult:
    workflow_id: str
    overall_valid: bool
    overall_reason: str
    signature_valid: bool
    hops: list[dict[str, Any]] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: _iso(_now()))

    def as_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "overall_valid": self.overall_valid,
            "overall_reason": self.overall_reason,
            "signature_valid": self.signature_valid,
            "hops": list(self.hops),
            "checked_at": self.checked_at,
        }


class WorkflowError(ValueError):
    """Raised when a workflow cannot be registered or replayed."""


# ── Canonicalization & signing ────────────────────────────────────────────────

def _canonical_hop(hop: dict[str, Any]) -> dict[str, Any]:
    """Project to allowed fields + sort keys for deterministic hashing."""
    canonical: dict[str, Any] = {}
    for k in sorted(hop.keys()):
        if k not in VALID_HOP_FIELDS:
            continue
        v = hop[k]
        if v is None:
            continue
        if isinstance(v, dict):
            canonical[k] = {kk: v[kk] for kk in sorted(v.keys())}
        else:
            canonical[k] = v
    if "actor" not in canonical or "action" not in canonical:
        raise WorkflowError("hop_missing_required_fields")
    return canonical


def _hop_hash(hop: dict[str, Any]) -> str:
    payload = json.dumps(hop, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def merkle_root(hops: list[dict[str, Any]]) -> str:
    """
    Pairwise SHA-256 fold of canonicalized hop hashes. For an odd-length
    leaf set the last leaf is duplicated (standard Bitcoin-style padding).
    Empty input returns the digest of the empty string.
    """
    if not hops:
        return hashlib.sha256(b"").hexdigest()
    layer = [_hop_hash(_canonical_hop(h)) for h in hops]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        nxt: list[str] = []
        for i in range(0, len(layer), 2):
            joined = (layer[i] + layer[i + 1]).encode("utf-8")
            nxt.append(hashlib.sha256(joined).hexdigest())
        layer = nxt
    return layer[0]


def _sign_workflow(
    *,
    tenant_id: str,
    name: str,
    root: str,
    created_at: str,
) -> str:
    payload = "|".join((tenant_id, name, root, created_at)).encode("utf-8")
    return hmac.new(_secret(), payload, hashlib.sha256).hexdigest()


# ── Register ──────────────────────────────────────────────────────────────────

def register_workflow(
    tenant_id: str,
    name: str,
    hops: list[dict[str, Any]],
    description: str = "",
    created_by: str | None = None,
) -> Workflow:
    """
    Canonicalize the hops, compute a Merkle root, sign, and store. Returns
    the persisted workflow. Idempotent on (tenant_id, merkle_root) — a
    second call with the same canonicalized chain returns the existing row.
    """
    if _use_pg():
        raise NotImplementedError("workflow_attestation PG path not implemented")
    if not isinstance(hops, list) or not hops:
        raise WorkflowError("hops_must_be_non_empty_list")
    name = (name or "").strip()
    if not name:
        raise WorkflowError("name_required")

    canonical = [_canonical_hop(h) for h in hops]
    root = merkle_root(canonical)

    with _lock:
        conn = _get_conn()
        try:
            existing = conn.execute(
                "SELECT * FROM workflows WHERE tenant_id=? AND merkle_root=?",
                (tenant_id, root),
            ).fetchone()
            if existing:
                return _row_to_workflow(existing)

            now = _iso(_now())
            wid = f"wf:{uuid.uuid4().hex[:24]}"
            sig = _sign_workflow(
                tenant_id=tenant_id, name=name, root=root, created_at=now,
            )
            conn.execute(
                """
                INSERT INTO workflows
                    (workflow_id, tenant_id, name, description, hops_json,
                     merkle_root, signature, created_at, created_by, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    wid, tenant_id, name, description,
                    json.dumps(canonical, sort_keys=True),
                    root, sig, now, created_by,
                ),
            )
            conn.commit()
            return Workflow(
                workflow_id=wid,
                tenant_id=tenant_id,
                name=name,
                description=description,
                hops=canonical,
                merkle_root=root,
                signature=sig,
                created_at=now,
                created_by=created_by,
            )
        finally:
            conn.close()


def _row_to_workflow(row: sqlite3.Row) -> Workflow:
    return Workflow(
        workflow_id=row["workflow_id"],
        tenant_id=row["tenant_id"],
        name=row["name"],
        description=row["description"],
        hops=json.loads(row["hops_json"]),
        merkle_root=row["merkle_root"],
        signature=row["signature"],
        created_at=row["created_at"],
        created_by=row["created_by"],
        status=row["status"],
    )


def get_workflow(workflow_id: str, tenant_id: str | None = None) -> Workflow | None:
    if _use_pg():
        return None
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM workflows WHERE workflow_id=?",
                (workflow_id,),
            ).fetchone()
            if not row:
                return None
            if tenant_id is not None and row["tenant_id"] != tenant_id:
                return None
            return _row_to_workflow(row)
        finally:
            conn.close()


def list_workflows(
    tenant_id: str,
    status: str | None = "active",
    limit: int = 100,
) -> list[Workflow]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM workflows WHERE tenant_id=?"
            params: list[Any] = [tenant_id]
            if status:
                sql += " AND status=?"
                params.append(status)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(min(int(limit), 500))
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [_row_to_workflow(r) for r in rows]
        finally:
            conn.close()


def retire_workflow(workflow_id: str, tenant_id: str | None = None) -> bool:
    if _use_pg():
        return False
    with _lock:
        conn = _get_conn()
        try:
            sql = "UPDATE workflows SET status='retired' WHERE workflow_id=? AND status='active'"
            params: list[Any] = [workflow_id]
            if tenant_id is not None:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


# ── Replay ────────────────────────────────────────────────────────────────────

def replay_workflow(
    workflow_id: str,
    tenant_id: str | None = None,
) -> ReplayResult:
    """
    Reconstruct the canonical chain, re-derive the signature, and re-verify
    every linked delegation receipt. Returns per-hop status plus rolled-up
    overall_valid / overall_reason.
    """
    wf = get_workflow(workflow_id, tenant_id=tenant_id)
    if not wf:
        return ReplayResult(
            workflow_id=workflow_id,
            overall_valid=False,
            overall_reason="not_found_or_cross_tenant",
            signature_valid=False,
        )

    # Re-derive signature from current row.
    expected_root = merkle_root(wf.hops)
    expected_sig = _sign_workflow(
        tenant_id=wf.tenant_id, name=wf.name,
        root=expected_root, created_at=wf.created_at,
    )
    sig_ok = (
        hmac.compare_digest(expected_root, wf.merkle_root)
        and hmac.compare_digest(expected_sig, wf.signature)
    )

    # Re-verify referenced delegation receipts (lazy import — soft dependency).
    hop_reports: list[dict[str, Any]] = []
    overall_valid = sig_ok
    overall_reason = "ok" if sig_ok else "signature_invalid"
    try:
        from modules.identity import delegation_receipt as _dr  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        _dr = None

    for idx, hop in enumerate(wf.hops):
        receipt_id = hop.get("receipt_id")
        receipt_status: dict[str, Any] | None = None
        if receipt_id and _dr is not None:
            try:
                v = _dr.verify_receipt(receipt_id, tenant_id=wf.tenant_id)
                receipt_status = v.as_dict()
                if not v.valid and overall_valid:
                    overall_valid = False
                    overall_reason = f"hop_{idx}:receipt_{v.reason}"
            except Exception as exc:  # noqa: BLE001
                receipt_status = {"valid": False, "reason": f"verify_error:{exc}"}
                if overall_valid:
                    overall_valid = False
                    overall_reason = f"hop_{idx}:receipt_verify_error"
        if wf.status == "retired" and overall_valid:
            overall_valid = False
            overall_reason = "workflow_retired"
        hop_reports.append({
            "index": idx,
            "actor": hop.get("actor"),
            "action": hop.get("action"),
            "target": hop.get("target"),
            "receipt_id": receipt_id,
            "receipt_status": receipt_status,
        })

    return ReplayResult(
        workflow_id=workflow_id,
        overall_valid=overall_valid,
        overall_reason=overall_reason,
        signature_valid=sig_ok,
        hops=hop_reports,
    )


# ── Observations & drift ──────────────────────────────────────────────────────

def record_observation(
    workflow_id: str,
    observed_hops: list[dict[str, Any]],
    tenant_id: str | None = None,
) -> dict[str, Any]:
    """
    Record a runtime observation against a registered workflow. Compares the
    canonicalized observed hops to the workflow's canonical chain and stores
    a drift bool plus structured drift_details.
    """
    wf = get_workflow(workflow_id, tenant_id=tenant_id)
    if not wf:
        raise WorkflowError("not_found_or_cross_tenant")
    canonical_observed = [_canonical_hop(h) for h in observed_hops]
    observed_root = merkle_root(canonical_observed)
    drift = observed_root != wf.merkle_root
    details = _diff_chains(wf.hops, canonical_observed) if drift else {}
    now = _iso(_now())
    obs_id = f"wfobs:{uuid.uuid4().hex[:24]}"
    if _use_pg():
        return {
            "observation_id": obs_id, "workflow_id": workflow_id,
            "drift": drift, "drift_details": details,
        }
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO workflow_observations
                    (observation_id, workflow_id, tenant_id, observed_at,
                     observed_root, canonical_root, drift, drift_details,
                     observed_hops_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    obs_id, workflow_id, wf.tenant_id, now,
                    observed_root, wf.merkle_root,
                    1 if drift else 0,
                    json.dumps(details, sort_keys=True),
                    json.dumps(canonical_observed, sort_keys=True),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    return {
        "observation_id": obs_id,
        "workflow_id": workflow_id,
        "tenant_id": wf.tenant_id,
        "observed_at": now,
        "observed_root": observed_root,
        "canonical_root": wf.merkle_root,
        "drift": drift,
        "drift_details": details,
    }


def _diff_chains(
    canonical: list[dict[str, Any]],
    observed: list[dict[str, Any]],
) -> dict[str, Any]:
    """Lightweight structural diff for drift telemetry. Reports hop-count
    delta + per-index field diffs for the overlapping prefix."""
    details: dict[str, Any] = {
        "canonical_hops": len(canonical),
        "observed_hops": len(observed),
        "extra_hops": max(0, len(observed) - len(canonical)),
        "missing_hops": max(0, len(canonical) - len(observed)),
    }
    diffs: list[dict[str, Any]] = []
    for i in range(min(len(canonical), len(observed))):
        c = canonical[i]
        o = observed[i]
        keys = sorted(set(c.keys()) | set(o.keys()))
        per_field: dict[str, Any] = {}
        for k in keys:
            cv = c.get(k)
            ov = o.get(k)
            if cv != ov:
                per_field[k] = {"canonical": cv, "observed": ov}
        if per_field:
            diffs.append({"index": i, "fields": per_field})
    if diffs:
        details["hop_diffs"] = diffs
    return details


def get_observations(
    workflow_id: str,
    drift_only: bool = False,
    limit: int = 50,
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    if _use_pg():
        return []
    with _lock:
        conn = _get_conn()
        try:
            sql = "SELECT * FROM workflow_observations WHERE workflow_id=?"
            params: list[Any] = [workflow_id]
            if tenant_id is not None:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            if drift_only:
                sql += " AND drift=1"
            sql += " ORDER BY observed_at DESC LIMIT ?"
            params.append(min(int(limit), 500))
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [
                {
                    "observation_id": r["observation_id"],
                    "workflow_id": r["workflow_id"],
                    "tenant_id": r["tenant_id"],
                    "observed_at": r["observed_at"],
                    "observed_root": r["observed_root"],
                    "canonical_root": r["canonical_root"],
                    "drift": bool(r["drift"]),
                    "drift_details": json.loads(r["drift_details"] or "{}"),
                    "observed_hops": json.loads(r["observed_hops_json"]),
                }
                for r in rows
            ]
        finally:
            conn.close()

"""
TokenDNA -- Compliance control mapping and evidence package generation.

Provides automation primitives for DISA STIG/eMASS/FedRAMP-aligned evidence
outputs derived from TokenDNA identity and attestation controls.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any


_lock = threading.Lock()


def _db_path() -> str:
    return os.getenv("DATA_DB_PATH", "/data/tokendna.db")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


CONTROL_MAPS = {
    "disa_stig": {
        "IA-2": ["MFA assertion checks in UIS auth.mfa_asserted", "HVIP privileged MFA enforcement"],
        "IA-5": ["Token binding checks (DPoP/mTLS)", "certificate lifecycle management"],
        "AC-3": ["ABAC decision enforcement with auditable trace"],
        "AU-2": ["Startup/security event audit logging", "drift/certificate lifecycle events"],
        "AU-9": ["Tamper-evident certificate transparency log chain"],
    },
    "fedramp": {
        "IA-2": ["Privileged identity verification and step-up requirements"],
        "IA-5": ["Cryptographic token/certificate binding and revocation"],
        "AC-6": ["Least privilege via attestation scope constraints"],
        "SI-4": ["Continuous drift monitoring and threat intelligence scoring"],
        "AU-12": ["Comprehensive event generation and evidence export"],
    },
    "emass": {
        "CM-3": ["Configuration/attestation baseline drift detection"],
        "IA-3": ["Machine/agent identity attestation records"],
        "AC-2": ["Lifecycle governance for agent credentials/certificates"],
        "AU-6": ["Cross-source event correlation via UIS and drift logs"],
    },
}


def init_db() -> None:
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_evidence_packages (
                package_id             TEXT PRIMARY KEY,
                tenant_id              TEXT NOT NULL,
                framework              TEXT NOT NULL,
                generated_at           TEXT NOT NULL,
                controls_json          TEXT NOT NULL,
                summary_json           TEXT NOT NULL,
                evidence_json          TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_compliance_pkg_tenant_framework_time ON compliance_evidence_packages(tenant_id, framework, generated_at DESC)"
        )


def build_control_map(framework: str) -> dict[str, Any]:
    key = (framework or "").lower()
    controls = CONTROL_MAPS.get(key)
    if controls is None:
        controls = {}
    return {"framework": key, "controls": controls}


def generate_evidence_package(
    *,
    tenant_id: str,
    framework: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    control_map = build_control_map(framework)
    generated_at = _iso_now()
    package_id = uuid.uuid4().hex

    evidence = {
        "uis_event_count": int(inputs.get("uis_event_count", 0)),
        "attestation_count": int(inputs.get("attestation_count", 0)),
        "certificate_count": int(inputs.get("certificate_count", 0)),
        "revoked_certificate_count": int(inputs.get("revoked_certificate_count", 0)),
        "drift_event_count": int(inputs.get("drift_event_count", 0)),
        "threat_signal_count": int(inputs.get("threat_signal_count", 0)),
    }
    score = 0
    if evidence["attestation_count"] > 0:
        score += 20
    if evidence["certificate_count"] > 0:
        score += 20
    if evidence["uis_event_count"] > 0:
        score += 20
    if evidence["drift_event_count"] > 0:
        score += 20
    if evidence["threat_signal_count"] > 0:
        score += 20

    summary = {
        "coverage_score": score,
        "maturity_tier": "advanced" if score >= 80 else ("intermediate" if score >= 50 else "baseline"),
        "generated_at": generated_at,
    }

    package = {
        "package_id": package_id,
        "tenant_id": tenant_id,
        "framework": control_map["framework"],
        "generated_at": generated_at,
        "controls": control_map["controls"],
        "summary": summary,
        "evidence": evidence,
    }
    return package


def store_evidence_package(package: dict[str, Any]) -> None:
    with _cursor() as cur:
        cur.execute(
            """
            INSERT OR REPLACE INTO compliance_evidence_packages (
                package_id, tenant_id, framework, generated_at,
                controls_json, summary_json, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                package["package_id"],
                package["tenant_id"],
                package["framework"],
                package["generated_at"],
                json.dumps(package.get("controls", {}), sort_keys=True),
                json.dumps(package.get("summary", {}), sort_keys=True),
                json.dumps(package.get("evidence", {}), sort_keys=True),
            ),
        )


def list_evidence_packages(tenant_id: str, framework: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    with _cursor() as cur:
        if framework:
            rows = cur.execute(
                """
                SELECT package_id, tenant_id, framework, generated_at, controls_json, summary_json, evidence_json
                FROM compliance_evidence_packages
                WHERE tenant_id = ? AND framework = ?
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (tenant_id, framework.lower(), limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT package_id, tenant_id, framework, generated_at, controls_json, summary_json, evidence_json
                FROM compliance_evidence_packages
                WHERE tenant_id = ?
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()

    return [
        {
            "package_id": row["package_id"],
            "tenant_id": row["tenant_id"],
            "framework": row["framework"],
            "generated_at": row["generated_at"],
            "controls": json.loads(row["controls_json"]),
            "summary": json.loads(row["summary_json"]),
            "evidence": json.loads(row["evidence_json"]),
        }
        for row in rows
    ]


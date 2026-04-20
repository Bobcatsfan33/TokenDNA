"""
Tests for modules/identity/cert_dashboard.py — Certificate Lifecycle Dashboard.

Sprint 6-1: fleet view, expiry alerts, usage logging, anomaly detection
(revoked cert used, unexpected agent), deception mesh bridge, resolve flows.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest


# ── Fixture ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_cert_dash.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))

    # Also init attestation_store so list_certificates works
    import modules.identity.attestation_store as astore
    importlib.reload(astore)
    astore.init_db()

    import modules.identity.cert_dashboard as cd
    importlib.reload(cd)
    cd.init_db()
    yield cd


TENANT = "tenant-cert-test"


def _cert_id() -> str:
    return f"cert-{uuid.uuid4().hex[:8]}"


def _make_cert(db_path, cert_id=None, subject="agent-1", issuer="ca.acme.io",
               status="active", expires_delta_days=60):
    """Insert a synthetic cert directly into attestation_certificates."""
    cid = cert_id or _cert_id()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=expires_delta_days)
    cert = {
        "certificate_id": cid,
        "tenant_id": TENANT,
        "attestation_id": str(uuid.uuid4()),
        "issuer": issuer,
        "subject": subject,
        "issued_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "claims": {},
        "signature_alg": "HS256",
        "ca_key_id": "tokendna-ca-default",
        "status": status,
        "revoked_at": None if status != "revoked" else now.isoformat(),
        "revocation_reason": "test" if status == "revoked" else None,
        "signature": "fakesig",
    }
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT OR IGNORE INTO attestation_certificates
            (certificate_id, tenant_id, attestation_id, issued_at, expires_at,
             issuer, subject, signature_alg, ca_key_id, status, revoked_at,
             revocation_reason, signature, certificate_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cert["certificate_id"],
            cert["tenant_id"],
            cert["attestation_id"],
            cert["issued_at"],
            cert["expires_at"],
            cert["issuer"],
            cert["subject"],
            cert["signature_alg"],
            cert["ca_key_id"],
            cert["status"],
            cert["revoked_at"],
            cert["revocation_reason"],
            cert["signature"],
            json.dumps(cert),
        ),
    )
    conn.commit()
    conn.close()
    return cert


# ── Fleet view ────────────────────────────────────────────────────────────────

def test_fleet_view_empty(isolated_db):
    cd = isolated_db
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["total"] == 0
    assert result["certificates"] == []


def test_fleet_view_returns_certs(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, subject="agent-A")
    _make_cert(db_path, subject="agent-B")
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["total"] == 2


def test_fleet_view_health_labels_healthy(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=90)
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["certificates"][0]["health"] == "healthy"


def test_fleet_view_health_expiring_notice(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=20)
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["certificates"][0]["health"] == "expiring_notice"


def test_fleet_view_health_expiring_warning(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=5)
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["certificates"][0]["health"] == "expiring_warning"


def test_fleet_view_health_expiring_critical(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=0)
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["certificates"][0]["health"] in ("expiring_critical", "expired")


def test_fleet_view_health_revoked(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, status="revoked", expires_delta_days=60)
    result = cd.fleet_view(tenant_id=TENANT)
    assert result["certificates"][0]["health"] == "revoked"


def test_fleet_view_includes_days_until_expiry(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=45)
    result = cd.fleet_view(tenant_id=TENANT)
    days = result["certificates"][0]["days_until_expiry"]
    assert 44 <= days <= 46


def test_fleet_view_by_health_summary(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=90)
    _make_cert(db_path, expires_delta_days=5)
    _make_cert(db_path, status="revoked", expires_delta_days=60)
    result = cd.fleet_view(tenant_id=TENANT)
    assert "healthy" in result["by_health"]
    assert "revoked" in result["by_health"]


def test_fleet_tenant_isolation(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, subject="agent-A")
    result = cd.fleet_view(tenant_id="other-tenant")
    assert result["total"] == 0


# ── Expiry alerts ─────────────────────────────────────────────────────────────

def test_get_expiring_within_30_days(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=15)
    _make_cert(db_path, expires_delta_days=90)
    expiring = cd.get_expiring(tenant_id=TENANT, within_days=30)
    assert len(expiring) == 1
    assert expiring[0]["days_until_expiry"] <= 30


def test_get_expiring_urgency_critical(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=0)
    expiring = cd.get_expiring(tenant_id=TENANT, within_days=30)
    assert len(expiring) == 1
    assert expiring[0]["urgency"] == "critical"


def test_get_expiring_creates_alert_record(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=5)
    cd.get_expiring(tenant_id=TENANT, within_days=30)
    # Check alert was created
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT COUNT(*) as cnt FROM cert_expiry_alerts WHERE tenant_id = ?",
                       (TENANT,)).fetchone()
    conn.close()
    assert row[0] >= 1


def test_get_expiring_excludes_revoked(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, status="revoked", expires_delta_days=5)
    expiring = cd.get_expiring(tenant_id=TENANT, within_days=30)
    assert len(expiring) == 0


def test_acknowledge_expiry_alert(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=3)
    cd.get_expiring(tenant_id=TENANT, within_days=30)
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT alert_id FROM cert_expiry_alerts WHERE tenant_id = ?",
                       (TENANT,)).fetchone()
    conn.close()
    alert_id = row[0]
    result = cd.acknowledge_expiry_alert(
        tenant_id=TENANT, alert_id=alert_id, acknowledged_by="ops@acme.io"
    )
    assert result["acknowledged"] == 1
    assert result["acknowledged_by"] == "ops@acme.io"


def test_acknowledge_nonexistent_alert_raises(isolated_db):
    cd = isolated_db
    with pytest.raises(KeyError):
        cd.acknowledge_expiry_alert(
            tenant_id=TENANT, alert_id="fake-alert", acknowledged_by="ops@acme.io"
        )


# ── Usage logging ─────────────────────────────────────────────────────────────

def test_record_usage_clean(isolated_db):
    cd = isolated_db
    result = cd.record_usage(
        tenant_id=TENANT,
        certificate_id=_cert_id(),
        agent_id="agent-001",
        source_ip="10.0.0.1",
        cert_status="active",
    )
    assert result["cert_status"] == "active"
    assert result["anomalies_fired"] == []


def test_record_usage_revoked_fires_anomaly(isolated_db):
    cd = isolated_db
    result = cd.record_usage(
        tenant_id=TENANT,
        certificate_id=_cert_id(),
        agent_id="agent-001",
        source_ip="10.0.0.1",
        cert_status="revoked",
    )
    types = [a["anomaly_type"] for a in result["anomalies_fired"]]
    assert "revoked_cert_used" in types


def test_record_usage_unexpected_agent_fires_anomaly(isolated_db):
    cd = isolated_db
    cid = _cert_id()
    # First use — registers agent as known
    cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-A", cert_status="active")
    # Second use from a different, unknown agent
    result = cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-UNKNOWN", cert_status="active")
    types = [a["anomaly_type"] for a in result["anomalies_fired"]]
    assert "unexpected_agent" in types


def test_record_usage_known_agent_no_anomaly(isolated_db):
    cd = isolated_db
    cid = _cert_id()
    cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-A", cert_status="active")
    # Same agent again — no anomaly
    result = cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-A", cert_status="active")
    assert result["anomalies_fired"] == []


def test_get_cert_history(isolated_db):
    cd = isolated_db
    cid = _cert_id()
    cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-A")
    cd.record_usage(tenant_id=TENANT, certificate_id=cid, agent_id="agent-A")
    history = cd.get_cert_history(tenant_id=TENANT, certificate_id=cid)
    assert len(history) == 2


def test_cert_history_tenant_isolation(isolated_db):
    cd = isolated_db
    cid = _cert_id()
    cd.record_usage(tenant_id=TENANT, certificate_id=cid)
    history = cd.get_cert_history(tenant_id="other-tenant", certificate_id=cid)
    assert len(history) == 0


# ── Anomaly management ────────────────────────────────────────────────────────

def test_list_anomalies_empty(isolated_db):
    cd = isolated_db
    anomalies = cd.list_anomalies(tenant_id=TENANT)
    assert anomalies == []


def test_list_anomalies_returns_after_revoked_use(isolated_db):
    cd = isolated_db
    cd.record_usage(tenant_id=TENANT, certificate_id=_cert_id(), cert_status="revoked")
    anomalies = cd.list_anomalies(tenant_id=TENANT)
    assert len(anomalies) >= 1


def test_list_anomalies_filter_unresolved(isolated_db):
    cd = isolated_db
    cd.record_usage(tenant_id=TENANT, certificate_id=_cert_id(), cert_status="revoked")
    unresolved = cd.list_anomalies(tenant_id=TENANT, resolved=False)
    assert all(not a["resolved"] for a in unresolved)


def test_resolve_anomaly(isolated_db):
    cd = isolated_db
    cd.record_usage(tenant_id=TENANT, certificate_id=_cert_id(), cert_status="revoked")
    anomalies = cd.list_anomalies(tenant_id=TENANT, resolved=False)
    assert len(anomalies) >= 1
    aid = anomalies[0]["anomaly_id"]
    resolved = cd.resolve_anomaly(
        tenant_id=TENANT, anomaly_id=aid, resolved_by="security@acme.io"
    )
    assert resolved["resolved"] is True
    assert resolved["resolved_by"] == "security@acme.io"


def test_resolve_nonexistent_anomaly_raises(isolated_db):
    cd = isolated_db
    with pytest.raises(KeyError):
        cd.resolve_anomaly(tenant_id=TENANT, anomaly_id="fake-id", resolved_by="x")


# ── Fleet summary ─────────────────────────────────────────────────────────────

def test_fleet_summary_counts(isolated_db, tmp_path):
    cd = isolated_db
    db_path = os.environ["DATA_DB_PATH"]
    _make_cert(db_path, expires_delta_days=90)
    _make_cert(db_path, expires_delta_days=5)
    _make_cert(db_path, status="revoked", expires_delta_days=60)
    summary = cd.fleet_summary(tenant_id=TENANT)
    assert summary["total_certs"] == 3
    assert summary["revoked"] == 1
    assert "open_anomalies" in summary
    assert "certs_expiring_soon" in summary

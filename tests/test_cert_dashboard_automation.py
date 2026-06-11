"""T-4: cert_dashboard lifecycle automation (sweep + renewal hooks + audit).

Proves the deferred module reaches real lifecycle automation (not CRUD-only):
an adaptive sweep classifies the fleet, fires renewal hooks for due certs,
is idempotent, supports dry-run, isolates hook failures, and emits audit events.
"""
from __future__ import annotations

import importlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest

TENANT = "tenant-cert-auto"


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_cert_auto.db"
    monkeypatch.setenv("DATA_DB_PATH", str(db_file))
    import modules.identity.attestation_store as astore
    importlib.reload(astore)
    astore.init_db()
    import modules.identity.cert_dashboard as cd
    importlib.reload(cd)
    cd.init_db()
    cd.clear_renewal_hooks()
    yield cd
    cd.clear_renewal_hooks()


def _db_path() -> str:
    return os.environ["DATA_DB_PATH"]


def _make_cert(cert_id=None, subject="agent-1", issuer="ca.acme.io",
               status="active", expires_delta_days=60):
    cid = cert_id or f"cert-{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=expires_delta_days)
    cert = {
        "certificate_id": cid, "tenant_id": TENANT,
        "attestation_id": str(uuid.uuid4()), "issuer": issuer, "subject": subject,
        "issued_at": now.isoformat(), "expires_at": expires.isoformat(),
        "signature_alg": "HS256", "ca_key_id": "tokendna-ca-default",
        "status": status,
        "revoked_at": None if status != "revoked" else now.isoformat(),
        "revocation_reason": None if status != "revoked" else "test",
        "signature": "fakesig",
    }
    conn = sqlite3.connect(_db_path())
    conn.execute(
        """
        INSERT OR IGNORE INTO attestation_certificates
            (certificate_id, tenant_id, attestation_id, issued_at, expires_at,
             issuer, subject, signature_alg, ca_key_id, status, revoked_at,
             revocation_reason, signature, certificate_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (cert["certificate_id"], cert["tenant_id"], cert["attestation_id"],
         cert["issued_at"], cert["expires_at"], cert["issuer"], cert["subject"],
         cert["signature_alg"], cert["ca_key_id"], cert["status"], cert["revoked_at"],
         cert["revocation_reason"], cert["signature"], json.dumps(cert)),
    )
    conn.commit()
    conn.close()
    return cert


@pytest.fixture
def captured_audit(monkeypatch):
    events = []
    import modules.security.audit_log as audit
    monkeypatch.setattr(
        audit, "log_event",
        lambda et, *a, **k: events.append((getattr(et, "value", str(et)), k.get("detail", {}))),
    )
    return events


# ── sweep classification ──────────────────────────────────────────────────────

def test_sweep_empty_fleet(isolated_db):
    cd = isolated_db
    out = cd.run_expiry_sweep(tenant_id=TENANT)
    assert out["swept"] == 0
    assert out["due_for_renewal"] == 0
    assert out["renewals_triggered"] == 0


def test_sweep_classifies_by_urgency(isolated_db):
    cd = isolated_db
    _make_cert(expires_delta_days=1)    # critical
    _make_cert(expires_delta_days=5)    # warning
    _make_cert(expires_delta_days=20)   # notice
    _make_cert(expires_delta_days=200)  # healthy (not expiring)
    out = cd.run_expiry_sweep(tenant_id=TENANT)
    assert out["swept"] == 3            # the 200-day cert is outside the notice window
    assert out["by_urgency"].get("critical", 0) == 1
    assert out["by_urgency"].get("warning", 0) == 1
    assert out["by_urgency"].get("notice", 0) == 1


# ── renewal hooks ─────────────────────────────────────────────────────────────

def test_sweep_triggers_renewal_hook_for_due_certs(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=3)   # within 7-day threshold
    _make_cert(cert_id="cert-far", expires_delta_days=25)  # outside threshold
    called = []
    cd.register_renewal_hook(lambda cert, ctx: called.append(cert["certificate_id"]) or "ok")
    out = cd.run_expiry_sweep(tenant_id=TENANT)
    assert out["due_for_renewal"] == 1
    assert out["renewals_triggered"] == 1
    assert called == ["cert-due"]


def test_renewal_records_persisted(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=2)
    cd.register_renewal_hook(lambda cert, ctx: {"renewed": cert["certificate_id"]})
    cd.run_expiry_sweep(tenant_id=TENANT)
    renewals = cd.list_renewals(tenant_id=TENANT)
    assert len(renewals) == 1
    assert renewals[0]["certificate_id"] == "cert-due"
    assert renewals[0]["status"] == "triggered"
    assert renewals[0]["hook_results"][0]["ok"] is True


def test_sweep_is_idempotent(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=2)
    cd.register_renewal_hook(lambda cert, ctx: "ok")
    first = cd.run_expiry_sweep(tenant_id=TENANT)
    second = cd.run_expiry_sweep(tenant_id=TENANT)
    assert first["renewals_triggered"] == 1
    assert second["renewals_triggered"] == 0
    assert second["skipped_idempotent"] == 1
    assert len(cd.list_renewals(tenant_id=TENANT)) == 1


def test_dry_run_does_not_trigger(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=2)
    called = []
    cd.register_renewal_hook(lambda cert, ctx: called.append(1))
    out = cd.run_expiry_sweep(tenant_id=TENANT, dry_run=True)
    assert out["dry_run"] is True
    assert out["due_for_renewal"] == 1
    assert out["renewals_triggered"] == 0
    assert called == []
    assert cd.list_renewals(tenant_id=TENANT) == []


def test_hook_failure_isolated(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=2)

    def bad_hook(cert, ctx):
        raise RuntimeError("renewal backend down")

    cd.register_renewal_hook(bad_hook)
    out = cd.run_expiry_sweep(tenant_id=TENANT)
    assert out["renewals_triggered"] == 1  # attempt recorded
    renewals = cd.list_renewals(tenant_id=TENANT)
    assert renewals[0]["status"] == "failed"
    assert renewals[0]["hook_results"][0]["ok"] is False


def test_revoked_and_expired_not_renewed(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-revoked", expires_delta_days=2, status="revoked")
    _make_cert(cert_id="cert-expired", expires_delta_days=-2)
    called = []
    cd.register_renewal_hook(lambda cert, ctx: called.append(cert["certificate_id"]))
    out = cd.run_expiry_sweep(tenant_id=TENANT)
    assert out["renewals_triggered"] == 0
    assert called == []


def test_renew_within_days_override(isolated_db):
    cd = isolated_db
    _make_cert(cert_id="cert-20", expires_delta_days=20)
    cd.register_renewal_hook(lambda cert, ctx: "ok")
    out = cd.run_expiry_sweep(tenant_id=TENANT, renew_within_days=25)
    assert out["due_for_renewal"] == 1
    assert out["renewals_triggered"] == 1


# ── audit emission ────────────────────────────────────────────────────────────

def test_sweep_emits_audit_events(isolated_db, captured_audit):
    cd = isolated_db
    _make_cert(cert_id="cert-due", expires_delta_days=2)
    cd.register_renewal_hook(lambda cert, ctx: "ok")
    cd.run_expiry_sweep(tenant_id=TENANT)
    names = [e[0] for e in captured_audit]
    assert "cert.expiry_sweep" in names
    assert "cert.renewal_triggered" in names

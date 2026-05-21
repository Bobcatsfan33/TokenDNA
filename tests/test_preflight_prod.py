from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.preflight_prod import run_preflight


def _clear(monkeypatch):
    for key in (
        "ENVIRONMENT",
        "TOKENDNA_ENV",
        "DEV_MODE",
        "OIDC_ISSUER",
        "OIDC_AUDIENCE",
        "DNA_HMAC_KEY",
        "AUDIT_HMAC_KEY",
        "TOKENDNA_DB_BACKEND",
        "TOKENDNA_PG_DSN",
        "DATA_BACKEND",
        "DATABASE_URL",
        "TOKENDNA_DELEGATION_SECRET",
        "TOKENDNA_WORKFLOW_SECRET",
        "TOKENDNA_HONEYPOT_SECRET",
        "TOKENDNA_POSTURE_SECRET",
        "ATTESTATION_CA_KEY_ID",
        "ATTESTATION_CA_SECRET",
    ):
        monkeypatch.delenv(key, raising=False)


def test_preflight_accepts_database_aliases(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DATA_BACKEND", "postgres")
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/tokendna")

    report = run_preflight("dev")

    assert report["storage"]["backend"] == "postgres"
    assert report["storage"]["postgres_dsn_present"] is True
    assert report["passed"] is True


def test_preflight_detects_dsn_alias_mismatch(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("TOKENDNA_DB_BACKEND", "postgres")
    monkeypatch.setenv("TOKENDNA_PG_DSN", "postgresql://localhost/a")
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/b")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["storage_dsn_aliases_consistent"]["ok"] is False


def test_preflight_rejects_placeholder_production_secret(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("DNA_HMAC_KEY", "change-me-64-hex-dna-hmac-key")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["dna_hmac_key_strong"]["ok"] is False
    assert "placeholder" in checks["dna_hmac_key_strong"]["detail"]


def test_preflight_reports_no_direct_sqlite_modules(monkeypatch):
    _clear(monkeypatch)
    report = run_preflight("dev")

    assert report["storage"]["direct_sqlite_module_count"] == 0
    assert report["storage"]["direct_sqlite_modules"] == []

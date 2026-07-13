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
        "TOKENDNA_OIDC_TENANT_CLAIM",
        "TOKENDNA_OIDC_ALLOW_SUB_TENANT_FALLBACK",
        "TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON",
        "TOKENDNA_SCIM_GROUP_ROLE_MAP_JSON",
        "AUDIT_BACKEND",
        "AUDIT_BACKENDS",
        "AUDIT_LOG_PATH",
        "AUDIT_LOG_FILE",
        "SIEM_WEBHOOK_URL",
        "TOKENDNA_COMPLIANCE_PROFILE",
        "SECRETS_BACKEND",
        "USE_FIPS",
        "FIPS_MODE",
        "ATTESTATION_KEY_BACKEND",
        "ATTESTATION_KMS_KEY_ID",
        "AWS_REGION",
        "TLS_CA_CERT_PATH",
        "TLS_API_CERT_PATH",
        "TLS_API_KEY_PATH",
        "TLS_POSTGRES_CERT_PATH",
        "TLS_POSTGRES_KEY_PATH",
        "REDIS_TLS",
        "CLICKHOUSE_SECURE",
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


def test_preflight_requires_explicit_oidc_tenant_claim_in_production(monkeypatch):
    _clear(monkeypatch)

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["oidc_tenant_claim_set"]["ok"] is False


def test_preflight_rejects_oidc_sub_tenant_fallback_in_production(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("TOKENDNA_OIDC_TENANT_CLAIM", "org_id")
    monkeypatch.setenv("TOKENDNA_OIDC_ALLOW_SUB_TENANT_FALLBACK", "true")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["oidc_sub_tenant_fallback_disabled"]["ok"] is False


def test_preflight_rejects_invalid_role_map_json(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("TOKENDNA_OIDC_GROUP_ROLE_MAP_JSON", "not-json")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["tokendna_oidc_group_role_map_json_valid"]["ok"] is False


def test_preflight_accepts_legacy_audit_env_aliases(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AUDIT_BACKENDS", "file")
    monkeypatch.setenv("AUDIT_LOG_FILE", "/var/log/aegis/audit.jsonl")

    report = run_preflight("dev")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["audit_backend_set"]["ok"] is True
    assert checks["audit_log_path_set"]["ok"] is True


def test_preflight_requires_siem_webhook_when_audit_backend_includes_siem(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("AUDIT_BACKEND", "file,siem")
    monkeypatch.setenv("AUDIT_LOG_PATH", "/tmp/audit.jsonl")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["audit_siem_webhook_set"]["ok"] is False


def test_preflight_rejects_unknown_compliance_profile(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("TOKENDNA_COMPLIANCE_PROFILE", "made_up")

    report = run_preflight("production")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["compliance_profile_known"]["ok"] is False


def test_preflight_dod_il5_requires_hardened_controls(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("TOKENDNA_COMPLIANCE_PROFILE", "dod_il5")
    monkeypatch.setenv("AUDIT_BACKEND", "file")
    monkeypatch.setenv("ATTESTATION_KEY_BACKEND", "software")

    report = run_preflight("il5")

    checks = {c["name"]: c for c in report["checks"]}
    assert checks["managed_secrets_backend"]["ok"] is False
    assert checks["audit_siem_enabled"]["ok"] is False
    assert checks["fips_enabled"]["ok"] is False
    assert checks["attestation_managed_key_backend"]["ok"] is False
    assert checks["mtls_api_material_set"]["ok"] is False
    assert checks["redis_tls_enabled"]["ok"] is False
    assert checks["clickhouse_tls_enabled"]["ok"] is False
    assert checks["postgres_mtls_material_set"]["ok"] is False


def test_preflight_dod_il5_accepts_hardened_controls(monkeypatch):
    _clear(monkeypatch)
    env = {
        "DEV_MODE": "false",
        "TOKENDNA_ENV": "production",
        "TOKENDNA_COMPLIANCE_PROFILE": "dod_il5",
        "OIDC_ISSUER": "https://idp.example.com",
        "OIDC_AUDIENCE": "tokendna",
        "TOKENDNA_OIDC_TENANT_CLAIM": "org_id",
        "TOKENDNA_DB_BACKEND": "postgres",
        "TOKENDNA_PG_DSN": "postgresql://localhost/tokendna",
        "DATABASE_URL": "postgresql://localhost/tokendna",
        "DNA_HMAC_KEY": "a" * 32,
        "AUDIT_HMAC_KEY": "b" * 32,
        "AUDIT_BACKEND": "file,siem",
        "AUDIT_LOG_PATH": "/tmp/audit.jsonl",
        "SIEM_WEBHOOK_URL": "https://siem.example.com/hook",
        "SECRETS_BACKEND": "vault",
        "USE_FIPS": "true",
        "ATTESTATION_KEY_BACKEND": "aws_kms",
        "ATTESTATION_CA_KEY_ID": "ca-1",
        "ATTESTATION_KMS_KEY_ID": "arn:aws:kms:us-east-1:123:key/abc",
        "AWS_REGION": "us-east-1",
        "TOKENDNA_DELEGATION_SECRET": "c" * 32,
        "TOKENDNA_WORKFLOW_SECRET": "d" * 32,
        "TOKENDNA_HONEYPOT_SECRET": "e" * 32,
        "TOKENDNA_POSTURE_SECRET": "f" * 32,
        "TLS_CA_CERT_PATH": "/pki/ca.crt",
        "TLS_API_CERT_PATH": "/pki/api.crt",
        "TLS_API_KEY_PATH": "/pki/api.key",
        "TLS_POSTGRES_CERT_PATH": "/pki/postgres.crt",
        "TLS_POSTGRES_KEY_PATH": "/pki/postgres.key",
        "REDIS_TLS": "true",
        "CLICKHOUSE_SECURE": "true",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    report = run_preflight("il5")

    assert report["passed"] is True
    assert report["compliance_profile"] == "dod_il5"
